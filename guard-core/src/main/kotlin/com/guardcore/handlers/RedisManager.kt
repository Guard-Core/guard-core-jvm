package com.guardcore.handlers

import com.guardcore.config.EventTypes
import com.guardcore.config.SecurityConfig
import com.guardcore.errors.GuardRedisError
import com.guardcore.protocols.AgentHandlerProtocol
import com.guardcore.protocols.GuardRedisConnection
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.util.py.PyJson
import com.guardcore.util.py.PyUrllib
import io.lettuce.core.ClientOptions
import io.lettuce.core.RedisClient
import io.lettuce.core.RedisException
import io.lettuce.core.RedisFuture
import io.lettuce.core.RedisURI
import io.lettuce.core.ScanArgs
import io.lettuce.core.ScanCursor
import io.lettuce.core.ScriptOutputType
import io.lettuce.core.SocketOptions
import io.lettuce.core.TimeoutOptions
import io.lettuce.core.api.StatefulRedisConnection
import io.lettuce.core.api.async.RedisAsyncCommands
import java.time.Duration
import java.util.UUID
import java.util.concurrent.CompletionException
import java.util.logging.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * The raw async Redis command surface the handlers use. The Lettuce implementation backs
 * [RedisManager]; tests substitute fakes exactly like the Python tests swap `Redis.from_url`.
 */
public interface RedisOperations : AutoCloseable {
  public suspend fun get(key: String): String?

  public suspend fun set(key: String, value: String): Boolean

  public suspend fun setEx(key: String, value: String, ttlSeconds: Long): Boolean

  public suspend fun pSetEx(key: String, value: String, ttlMillis: Long): Boolean

  public suspend fun del(vararg keys: String): Long

  public suspend fun exists(key: String): Long

  public suspend fun keys(pattern: String): List<String>

  public suspend fun incr(key: String): Long

  public suspend fun expire(key: String, seconds: Long): Boolean

  public suspend fun pTtl(key: String): Long

  public suspend fun zadd(key: String, score: Double, member: String): Long

  public suspend fun zremRangeByScore(key: String, min: String, max: String): Long

  public suspend fun zcard(key: String): Long

  /** ZRANGE key 0 -1 WITHSCORES as (member, score-text) pairs. */
  public suspend fun zrangeWithScores(key: String): List<Pair<String, String>>

  public suspend fun evalSha(sha: String, keys: List<String>, argv: List<String>): Long

  public suspend fun scriptLoad(script: String): String?

  public suspend fun ping(): Boolean

  /**
   * redis-py `pipeline()` (transaction=True): MULTI, queue the operations, EXEC. Returns the EXEC
   * results in order.
   */
  public suspend fun transaction(ops: suspend (QueuedRedisOperations) -> Unit): List<Any?>

  /** redis-py `scan_iter(match=...)`: full iteration collecting the matched keys. */
  public suspend fun scan(match: String): List<String>
}

/**
 * The write-only view used inside [RedisOperations.transaction]: commands queue inside MULTI and
 * their results arrive from the EXEC batch, mirroring redis-py pipeline callables. Each call
 * registers the command future so [RedisOperations.transaction] can await the batch results in
 * order after EXEC.
 */
public interface QueuedRedisOperations : AutoCloseable {
  public suspend fun incr(key: String)

  public suspend fun expire(key: String, seconds: Long)

  public suspend fun zadd(key: String, score: Double, member: String)

  public suspend fun zremRangeByScore(key: String, min: String, max: String)

  public suspend fun zcard(key: String)

  public suspend fun get(key: String)

  public suspend fun pTtl(key: String)

  public suspend fun setEx(key: String, value: String, ttlSeconds: Long)

  public suspend fun del(vararg keys: String)
}

/** Lettuce-backed [RedisOperations]. */
public class LettuceRedisOperations
internal constructor(
    private val client: RedisClient,
    private val connection: StatefulRedisConnection<String, String>,
) : RedisOperations {
  override suspend fun get(key: String): String? = await { it.get(key) }

  override suspend fun set(key: String, value: String): Boolean =
      await { it.set(key, value) } == "OK"

  override suspend fun setEx(key: String, value: String, ttlSeconds: Long): Boolean =
      await { it.setex(key, ttlSeconds, value) } == "OK"

  override suspend fun pSetEx(key: String, value: String, ttlMillis: Long): Boolean =
      await { it.psetex(key, ttlMillis, value) } == "OK"

  override suspend fun del(vararg keys: String): Long = await { it.del(*keys) }

  override suspend fun exists(key: String): Long = await { it.exists(key) }

  override suspend fun keys(pattern: String): List<String> = await { it.keys(pattern) }

  override suspend fun incr(key: String): Long = await { it.incr(key) }

  override suspend fun expire(key: String, seconds: Long): Boolean = await {
    it.expire(key, seconds)
  }

  override suspend fun pTtl(key: String): Long = await { it.pttl(key) }

  override suspend fun zadd(key: String, score: Double, member: String): Long = await {
    it.zadd(key, score, member)
  }

  override suspend fun zremRangeByScore(key: String, min: String, max: String): Long = await {
    it.zremrangebyscore(key, min, max)
  }

  override suspend fun zcard(key: String): Long = await { it.zcard(key) }

  override suspend fun zrangeWithScores(key: String): List<Pair<String, String>> = await {
    it.zrangeWithScores(key, 0, -1)
  }
      .map { sv -> sv.value to com.guardcore.util.py.PyJson.floatRepr(sv.score) }

  override suspend fun evalSha(sha: String, keys: List<String>, argv: List<String>): Long = await {
    it.evalsha(sha, ScriptOutputType.INTEGER, keys.toTypedArray(), *argv.toTypedArray())
  }

  override suspend fun scriptLoad(script: String): String? = await { it.scriptLoad(script) }

  override suspend fun ping(): Boolean = await { it.ping() } == "PONG"

  override suspend fun transaction(ops: suspend (QueuedRedisOperations) -> Unit): List<Any?> =
      withContext(Dispatchers.IO) {
        val async = connection.async()
        async.multi()
        val futures = mutableListOf<java.util.concurrent.Future<*>>()
        ops(LettuceQueuedOperations(async, futures))
        try {
          async.exec().get()
        } catch (e: CompletionException) {
          throw (e.cause ?: e)
        }
        // Queued futures complete with their real outputs once EXEC lands
        // (redis-py pipeline.execute() result order).
        futures.map { future ->
          try {
            future.get()
          } catch (e: CompletionException) {
            throw (e.cause ?: e)
          } catch (e: java.util.concurrent.ExecutionException) {
            throw (e.cause ?: e)
          }
        }
      }

  override suspend fun scan(match: String): List<String> {
    val args = ScanArgs.Builder.matches(match).limit(1000)
    val result = mutableListOf<String>()
    var cursor = ScanCursor.of("0")
    while (true) {
      val batch = await { it.scan(cursor, args) }
      result.addAll(batch.keys)
      // ScanCursor.of() leaves the finished flag false even for cursor "0"; the
      // termination signal is the server cursor string itself.
      if (batch.cursor == "0") break
      cursor = ScanCursor.of(batch.cursor)
    }
    return result
  }

  override fun close() {
    connection.close()
    client.shutdown()
  }

  private class LettuceQueuedOperations(
      private val ops: RedisAsyncCommands<String, String>,
      private val futures: MutableList<java.util.concurrent.Future<*>>,
  ) : QueuedRedisOperations {
    override suspend fun incr(key: String) {
      futures.add(ops.incr(key))
    }

    override suspend fun expire(key: String, seconds: Long) {
      futures.add(ops.expire(key, seconds))
    }

    override suspend fun zadd(key: String, score: Double, member: String) {
      futures.add(ops.zadd(key, score, member))
    }

    override suspend fun zremRangeByScore(key: String, min: String, max: String) {
      futures.add(ops.zremrangebyscore(key, min, max))
    }

    override suspend fun zcard(key: String) {
      futures.add(ops.zcard(key))
    }

    override suspend fun get(key: String) {
      futures.add(ops.get(key))
    }

    override suspend fun pTtl(key: String) {
      futures.add(ops.pttl(key))
    }

    override suspend fun setEx(key: String, value: String, ttlSeconds: Long) {
      futures.add(ops.setex(key, ttlSeconds, value))
    }

    override suspend fun del(vararg keys: String) {
      futures.add(ops.del(*keys))
    }

    override fun close() {}
  }

  private suspend fun <T> await(
      block: (RedisAsyncCommands<String, String>) -> RedisFuture<T>,
  ): T =
      withContext(Dispatchers.IO) {
        try {
          block(connection.async()).get()
        } catch (e: CompletionException) {
          throw (e.cause ?: e)
        }
      }
}

/**
 * The agent event sink the W3 handlers emit through. [AgentHandlerProtocol] is the production sink
 * (guard-agent-jvm in W7); handler tests register suspend-lambda fakes, mirroring the Python tests'
 * fake `guard_agent.SecurityEvent` module.
 */
public interface HandlerAgentSink {
  public suspend fun sendEvent(event: Map<String, Any?>)

  public companion object {
    /** Wrap the production protocol sink. */
    public fun of(handler: AgentHandlerProtocol): HandlerAgentSink =
        object : HandlerAgentSink {
          override suspend fun sendEvent(event: Map<String, Any?>) {
            handler.sendEvent(event)
          }
        }
  }
}

/**
 * Port of `guard_core/handlers/redis_handler.py` (RedisManager): the singleton Redis connection
 * manager every Redis-backed handler resolves through.
 *
 * Connection tuning mirrors `_connection_kwargs` (redis_handler.py:97); the key schema is
 * `{redis_prefix}{namespace}:{key}` (redis_handler.py:255). The redis-py client-level retry
 * (Retry(ExponentialBackoff(), retries), redis_handler.py:116) maps to the Lettuce
 * reconnect/timeout options: transient failures surface as GuardRedisError 503 after the timeout
 * budget either way (idiom mapping, docs/w3-handlers-parity.md).
 */
public open class RedisManager(
    config: SecurityConfig,
    private val clientFactory:
        (
            url: String,
            connectTimeout: Double?,
            socketTimeout: Double?,
        ) -> RedisOperations,
) : RedisHandlerProtocol {
  public var config: SecurityConfig = config

  public val logger: Logger = Logger.getLogger("guard_core.handlers.redis")

  @Volatile public var agentHandler: HandlerAgentSink? = null

  @Volatile private var operations: RedisOperations? = null

  @Volatile private var closed: Boolean = false

  private val connectionLock = Mutex()

  public constructor(config: SecurityConfig) : this(config, Companion::defaultClientFactory)

  /** Port of `initialize_agent` (redis_handler.py:70). */
  public suspend fun initializeAgent(agentHandler: HandlerAgentSink?) {
    this.agentHandler = agentHandler
  }

  public companion object {
    private const val REDIS_HANDLER_NAME = "redis"

    @Volatile private var instance: RedisManager? = null

    /** Python `RedisManager(config)` singleton dispatch (redis_handler.py:61). */
    public fun getInstance(config: SecurityConfig): RedisManager {
      val existing = instance
      if (existing != null) {
        existing.config = config
        existing.closed = false
        return existing
      }
      synchronized(this) {
        val again = instance
        if (again != null) {
          again.config = config
          again.closed = false
          return again
        }
        val created = RedisManager(config)
        instance = created
        return created
      }
    }

    /** Test seam mirroring `RedisManager._instance = None`. */
    public fun resetInstance() {
      synchronized(this) { instance = null }
    }

    private fun defaultClientFactory(
        url: String,
        connectTimeout: Double?,
        socketTimeout: Double?,
    ): RedisOperations {
      val uri = RedisURI.create(url)
      val socket =
          SocketOptions.builder()
              .connectTimeout(Duration.ofNanos(((connectTimeout ?: 2.0) * 1e9).toLong()))
              .build()
      val client =
          RedisClient.create(uri).apply {
            setOptions(
                ClientOptions.builder()
                    .socketOptions(socket)
                    .timeoutOptions(
                        TimeoutOptions.builder()
                            .timeoutCommands(true)
                            .fixedTimeout(
                                Duration.ofNanos(((socketTimeout ?: 2.0) * 1e9).toLong()),
                            )
                            .build(),
                    )
                    .build(),
            )
          }
      val connection = client.connect()
      return LettuceRedisOperations(client, connection)
    }
  }

  /** Port of `_send_redis_event` (redis_handler.py:73): the W7 telemetry seam. */
  public suspend fun sendRedisEvent(
      eventType: String,
      actionTaken: String,
      reason: String,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    val handler = agentHandler ?: return
    try {
      handler.sendEvent(
          linkedMapOf<String, Any?>(
              "event_type" to eventType,
              "ip_address" to "system",
              "action_taken" to actionTaken,
              "reason" to reason,
              "handler_name" to REDIS_HANDLER_NAME,
              "metadata" to metadata,
          ),
      )
    } catch (e: Exception) {
      logger.severe("Failed to send Redis event to agent: $e")
    }
  }

  /** Port of `_connection_kwargs` (redis_handler.py:97): connection tuning floors. */
  public fun connectionKwargs(cfg: SecurityConfig? = null): Map<String, Any?> {
    val use = cfg ?: config
    val kwargs = LinkedHashMap<String, Any?>()
    kwargs["socket_connect_timeout"] = use.redisSocketConnectTimeout
    kwargs["socket_timeout"] = use.redisSocketTimeout
    kwargs["health_check_interval"] = use.redisHealthCheckInterval
    if (use.redisMaxConnections != null) {
      kwargs["max_connections"] = use.redisMaxConnections
    }
    if (use.redisRetries > 0) {
      kwargs["retry"] = true
      kwargs["retry_on_error"] = listOf("ConnectionError", "TimeoutError")
    }
    return kwargs
  }

  private suspend fun safeAClose(client: RedisOperations) {
    try {
      client.close()
    } catch (e: Exception) {
      logger.warning("Failed to close a Redis client: $e")
    }
  }

  private suspend fun discardClient() {
    operations?.let { old ->
      operations = null
      safeAClose(old)
    }
  }

  /** Port of `initialize` (redis_handler.py:131). Open for the test monkeypatch idiom. */
  override suspend fun initialize() {
    val cfg = config
    if (!cfg.enableRedis) {
      connectionLock.withLock { discardClient() }
      return
    }
    closed = false
    connectionLock.withLock {
      discardClient()
      var newRedis: RedisOperations? = null
      try {
        val url = cfg.redisUrl
        if (url != null) {
          newRedis = clientFactory(url, cfg.redisSocketConnectTimeout, cfg.redisSocketTimeout)
          if (newRedis.ping()) {
            operations = newRedis
            logger.info("Redis connection established")
            sendRedisEvent(
                eventType = EventTypes.EVENT_REDIS_CONNECTION,
                actionTaken = "connection_established",
                reason = "Redis connection successfully established",
                metadata = mapOf("redis_url" to redactRedisUrl(url)),
            )
          } else {
            throw RedisException("PING returned non-PONG")
          }
        } else {
          logger.warning("Redis URL is None, skipping connection")
        }
      } catch (e: Exception) {
        logger.severe("Redis connection failed: $e")
        sendRedisEvent(
            eventType = EventTypes.EVENT_REDIS_ERROR,
            actionTaken = "connection_failed",
            reason = "Redis connection failed: $e",
            metadata =
                mapOf(
                    "redis_url" to redactRedisUrl(config.redisUrl),
                    "error_type" to "connection_error",
                ),
        )
        newRedis?.let { safeAClose(it) }
        operations = null
        throw GuardRedisError(503, "Redis connection failed").initCause(e)
      }
    }
  }

  /** Port of `close` (redis_handler.py:181). */
  public suspend fun close() {
    if (operations != null) {
      discardClient()
      logger.info("Redis connection closed")
      sendRedisEvent(
          eventType = EventTypes.EVENT_REDIS_CONNECTION,
          actionTaken = "connection_closed",
          reason = "Redis connection closed gracefully",
      )
    }
    closed = true
  }

  /**
   * Port of `get_connection` (redis_handler.py:193): runs [block] with the live client, mapping
   * connection failures to GuardRedisError(503, "Redis connection failed").
   */
  public suspend fun <T> withConnection(block: suspend (RedisOperations) -> T): T {
    try {
      if (closed) {
        sendRedisEvent(
            eventType = EventTypes.EVENT_REDIS_ERROR,
            actionTaken = "operation_failed",
            reason = "Attempted to use closed Redis connection",
            metadata = mapOf("error_type" to "connection_closed"),
        )
        throw GuardRedisError(503, "Redis connection closed")
      }
      if (operations == null) {
        initialize()
      }
      val ops =
          operations
              ?: run {
                sendRedisEvent(
                    eventType = EventTypes.EVENT_REDIS_ERROR,
                    actionTaken = "operation_failed",
                    reason = "Redis connection is None after initialization",
                    metadata = mapOf("error_type" to "initialization_failed"),
                )
                throw GuardRedisError(503, "Redis connection failed")
              }
      return block(ops)
    } catch (e: RedisException) {
      logger.severe("Redis operation failed: $e")
      sendRedisEvent(
          eventType = EventTypes.EVENT_REDIS_ERROR,
          actionTaken = "operation_failed",
          reason = "Redis operation failed: $e",
          metadata = mapOf("error_type" to "operation_error"),
      )
      throw GuardRedisError(503, "Redis connection failed").initCause(e)
    } catch (e: GuardRedisError) {
      throw e
    }
  }

  /** Protocol parity for `RedisHandlerProtocol.getConnection` (redis_protocol.py:45). */
  override fun getConnection(): GuardRedisConnection =
      object : GuardRedisConnection {
        override val client: Any? = operations

        override fun close() {
          // The Python context manager yields the shared client and closes nothing.
        }
      }

  /** Port of `safe_operation` (redis_handler.py:230). */
  public suspend fun safeOperation(func: suspend (RedisOperations) -> Any?): Any? {
    if (!config.enableRedis) {
      return null
    }
    return try {
      withConnection { conn -> func(conn) }
    } catch (e: Exception) {
      logger.severe("Redis operation failed: $e")
      sendRedisEvent(
          eventType = EventTypes.EVENT_REDIS_ERROR,
          actionTaken = "safe_operation_failed",
          reason = "Redis safe operation failed: $e",
          metadata =
              mapOf(
                  "error_type" to "safe_operation_error",
                  "function_name" to "unknown",
              ),
      )
      throw GuardRedisError(503, "Redis operation failed").initCause(e)
    }
  }

  private fun fullKey(namespace: String, key: String): String =
      "${config.redisPrefix}$namespace:$key"

  /** Port of `get_key` (redis_handler.py:250). */
  override suspend fun getKey(namespace: String, key: String): Any? {
    if (!config.enableRedis) return null
    return safeOperation { conn -> conn.get(fullKey(namespace, key)) }
  }

  /** Port of `set_key` (redis_handler.py:260). */
  override suspend fun setKey(
      namespace: String,
      key: String,
      value: Any?,
      ttl: Int?,
  ): Boolean? {
    if (!config.enableRedis) return null
    val result = safeOperation { conn ->
      val fullKey = fullKey(namespace, key)
      val text = valueString(value)
      if (ttl != null && ttl != 0) {
        conn.setEx(fullKey, text, ttl.toLong())
      } else {
        conn.set(fullKey, text)
      }
    }
    return if (result == null) false else result != false
  }

  /** Port of `incr` (redis_handler.py:275). */
  public suspend fun incr(namespace: String, key: String, ttl: Int? = null): Long? {
    if (!config.enableRedis) return null
    val result = safeOperation { conn ->
      val fullKey = fullKey(namespace, key)
      conn.transaction { tx ->
        tx.incr(fullKey)
        if (ttl != null && ttl != 0) {
          tx.expire(fullKey, ttl.toLong())
        }
      }
    }
    @Suppress("UNCHECKED_CAST") val results = result as? List<Any?> ?: return 0L
    return (results.firstOrNull() as? Number)?.toLong() ?: 0L
  }

  /** Port of `record_sliding_window_hit` (redis_handler.py:298). */
  public suspend fun recordSlidingWindowHit(
      namespace: String,
      key: String,
      timestamp: Double,
      windowStart: Double,
      ttl: Int,
  ): Long {
    if (!config.enableRedis) return 0L
    val result = safeOperation { conn ->
      val fullKey = fullKey(namespace, key)
      conn.transaction { tx ->
        tx.zadd(fullKey, timestamp, UUID.randomUUID().toString().replace("-", ""))
        tx.zremRangeByScore(fullKey, "-inf", "(${PyJson.floatRepr(windowStart)}")
        tx.zcard(fullKey)
        tx.expire(fullKey, ttl.toLong())
      }
    }
    @Suppress("UNCHECKED_CAST") val results = result as? List<Any?> ?: return 0L
    if (results.size <= 2) return 0L
    return (results[2] as? Number)?.toLong() ?: 0L
  }

  /** Port of `exists` (redis_handler.py:317). Not part of RedisHandlerProtocol. */
  public suspend fun exists(namespace: String, key: String): Boolean? {
    if (!config.enableRedis) return null
    val result =
        (safeOperation { conn -> conn.exists(fullKey(namespace, key)) } as? Number) ?: return false
    return result.toLong() > 0L
  }

  /** Port of `delete` (redis_handler.py:328). */
  override suspend fun delete(namespace: String, key: String): Int? {
    if (!config.enableRedis) return null
    val result = safeOperation { conn -> conn.del(fullKey(namespace, key)) } ?: return 0
    return (result as? Number)?.toInt() ?: 0
  }

  /** Port of `keys` (redis_handler.py:340). */
  override suspend fun keys(pattern: String): List<String>? {
    if (!config.enableRedis) return null
    val result = safeOperation { conn -> conn.keys("${config.redisPrefix}$pattern") }
    @Suppress("UNCHECKED_CAST")
    return (result as? List<String>) ?: emptyList()
  }

  /** Port of `delete_pattern` (redis_handler.py:352). */
  public suspend fun deletePattern(pattern: String): Int? {
    if (!config.enableRedis) return null
    val result = safeOperation { conn ->
      val fullPattern = "${config.redisPrefix}$pattern"
      val found = conn.keys(fullPattern)
      if (found.isEmpty()) 0L else conn.del(*found.toTypedArray())
    }
    return (result as? Number)?.toInt() ?: 0
  }

  /** Live operations handle for callers that need raw command access (tests, migration). */
  public suspend fun operations(): RedisOperations? {
    if (operations == null) initialize()
    return operations
  }

  /** Test/ops seam mirroring `handler._redis`. */
  public fun redisOrNull(): RedisOperations? = operations

  /** Test seam mirroring `handler._redis = ...`. */
  public fun setRedisForTests(ops: RedisOperations?) {
    operations = ops
  }

  /** Test seam mirroring `handler._closed = ...`. */
  public fun setClosedForTests(value: Boolean) {
    closed = value
  }

  public fun isClosed(): Boolean = closed
}

/** Python `str(value)` for Redis storage: bytes stay latin-1 decodable, strings pass through. */
public fun valueString(value: Any?): String =
    when (value) {
      null -> "None"
      is String -> value
      is ByteArray -> String(value, Charsets.ISO_8859_1)
      else -> value.toString()
    }

private fun unparseableRedisUrl(url: String, scheme: String = ""): String {
  val s = scheme.ifEmpty { url.substringBefore("://", "") }
  return if (s.isNotEmpty() && url.contains("://")) "$s://<unparseable>" else "<unparseable>"
}

/**
 * Port of `_redact_redis_url` (redis_handler.py:29): keep scheme/path/query/fragment, drop
 * credentials from the netloc, keep host and port.
 */
public fun redactRedisUrl(url: String?): String? {
  if (url == null) return null
  val parts =
      try {
        PyUrllib.urlsplit(url)
      } catch (e: Exception) {
        return unparseableRedisUrl(url)
      }
  if (parts.netloc.isEmpty()) return url
  val host: String
  val port: Int?
  try {
    val (h, p) = splitHostPort(parts.netloc)
    host = h
    port = p
  } catch (e: Exception) {
    return unparseableRedisUrl(url, parts.scheme)
  }
  val netloc = if (host.contains(":")) "[$host]" else host
  val withPort = if (port != null) "$netloc:$port" else netloc
  return PyUrllib.urlunsplit(parts.scheme, withPort, parts.path, parts.query, parts.fragment)
}

/** CPython `SplitResult.hostname` / `.port` extraction over a raw netloc. */
private fun splitHostPort(netloc: String): Pair<String, Int?> {
  var rest = netloc
  val at = rest.lastIndexOf('@')
  if (at >= 0) rest = rest.substring(at + 1)
  return if (rest.startsWith("[")) {
    val close = rest.indexOf(']')
    if (close < 0) throw IllegalArgumentException("Invalid IPv6 URL")
    val host = rest.substring(1, close).lowercase()
    val remainder = rest.substring(close + 1)
    if (remainder.startsWith(":")) {
      val portText = remainder.substring(1)
      val port = portText.toIntOrNull() ?: throw IllegalArgumentException("Port could not be cast")
      host to port
    } else {
      if (remainder.isNotEmpty()) throw IllegalArgumentException("Invalid IPv6 URL")
      host to null
    }
  } else {
    val colon = rest.indexOf(':')
    if (colon < 0) {
      rest.lowercase() to null
    } else {
      val host = rest.substring(0, colon).lowercase()
      val portText = rest.substring(colon + 1)
      if (portText.isEmpty()) {
        host to null
      } else {
        val port =
            portText.toIntOrNull()
                ?: throw IllegalArgumentException("Port could not be cast to integer")
        host to port
      }
    }
  }
}
