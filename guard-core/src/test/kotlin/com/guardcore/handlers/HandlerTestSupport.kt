package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.protocols.GuardRedisConnection
import com.guardcore.protocols.RedisHandlerProtocol
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import java.util.logging.Handler
import java.util.logging.Level
import java.util.logging.LogRecord
import java.util.logging.Logger
import kotlinx.coroutines.runBlocking

/** conftest REDIS_URL (tests/conftest.py:54). */
public val TEST_REDIS_URL: String = System.getenv("REDIS_URL") ?: "redis://localhost:6379"

private val TEST_REDIS_PREFIX_BASE: String = System.getenv("REDIS_PREFIX") ?: "test:guard_core:"

/** W3 seam registration for the tests (mirrors the facade entry init). */
private val seamsRegistered: Any = com.guardcore.handlers.HandlerSeams.register()

/** conftest REDIS_PREFIX: pid + random suffix so runs never collide. */
public fun uniqueRedisPrefix(): String =
    "$TEST_REDIS_PREFIX_BASE${ProcessHandle.current().pid()}:${UUID.randomUUID().toString().replace("-", "").take(8)}:"

/** Recording agent sink: the AsyncMock agent of the python handler tests. */
public class RecordingAgent : HandlerAgentSink {
  public val events: MutableList<Map<String, Any?>> = mutableListOf()
  public var failWith: Exception? = null

  override suspend fun sendEvent(event: Map<String, Any?>) {
    failWith?.let { throw it }
    events.add(event)
  }
}

/**
 * Recording RedisHandlerProtocol fake: the AsyncMock redis handler of the python handler tests. Get
 * returns are scripted per (namespace, key); every call is recorded.
 */
public class RecordingRedis(
    public val redisPrefix: String = "guard:",
) : RedisHandlerProtocol {
  public val getKeyCalls: MutableList<Pair<String, String>> = mutableListOf()
  public val setKeyCalls: MutableList<Triple<String, String, Any?>> = mutableListOf()
  public val setKeyTtls: MutableList<Int?> = mutableListOf()
  public val deleteCalls: MutableList<Pair<String, String>> = mutableListOf()
  public val keysCalls: MutableList<String> = mutableListOf()

  public val getKeyReturns: MutableMap<Pair<String, String>, Any?> = linkedMapOf()
  public val setKeyFailWith: Exception? = null
  public var keysReturn: List<String> = emptyList()
  public var getKeyDefault: Any? = null

  override suspend fun getKey(namespace: String, key: String): Any? {
    getKeyCalls.add(namespace to key)
    return getKeyReturns[namespace to key] ?: getKeyDefault
  }

  override suspend fun setKey(
      namespace: String,
      key: String,
      value: Any?,
      ttl: Int?,
  ): Boolean? {
    setKeyCalls.add(Triple(namespace, key, value))
    setKeyTtls.add(ttl)
    setKeyFailWith?.let { throw it }
    return true
  }

  override suspend fun delete(namespace: String, key: String): Int? {
    deleteCalls.add(namespace to key)
    return 1
  }

  override suspend fun keys(pattern: String): List<String>? {
    keysCalls.add(pattern)
    return keysReturn
  }

  override suspend fun initialize() {}

  override fun getConnection(): GuardRedisConnection =
      object : GuardRedisConnection {
        override val client: Any? = null

        override fun close() {}
      }
}

/** A redis handler whose set_key always fails (python `_FailingRedisHandler`). */
public class FailingSetKeyRedis : RedisHandlerProtocol {
  override suspend fun getKey(namespace: String, key: String): Any? = null

  override suspend fun setKey(
      namespace: String,
      key: String,
      value: Any?,
      ttl: Int?,
  ): Boolean? = throw RuntimeException("down")

  override suspend fun delete(namespace: String, key: String): Int? = 0

  override suspend fun keys(pattern: String): List<String>? = emptyList()

  override suspend fun initialize() {}

  override fun getConnection(): GuardRedisConnection =
      object : GuardRedisConnection {
        override val client: Any? = null

        override fun close() {}
      }
}

/**
 * conftest `security_config_redis` fixture (tests/conftest.py:409): a live-Redis config with the
 * fixed test lists and thresholds.
 */
public fun securityConfigRedis(): SecurityConfig =
    SecurityConfigBuilder()
        .apply {
          redisUrl = TEST_REDIS_URL
          redisPrefix = uniqueRedisPrefix()
          whitelist = listOf("127.0.0.1")
          blacklist = listOf("192.168.1.1")
          blockedUserAgents = listOf("badbot")
          autoBanThreshold = 3
          autoBanDuration = 300
          customErrorResponses =
              mapOf(
                  403 to "Custom Forbidden",
                  429 to "Custom Too Many Requests",
              )
        }
        .build()

/** conftest `security_config` fixture (tests/conftest.py:380): redis disabled. */
public fun securityConfigNoRedis(): SecurityConfig =
    SecurityConfigBuilder()
        .apply {
          enableRedis = false
          redisUrl = null
          whitelist = listOf("127.0.0.1")
          blacklist = listOf("192.168.1.1")
          blockedUserAgents = listOf("badbot")
          autoBanThreshold = 3
          autoBanDuration = 300
          customErrorResponses =
              mapOf(
                  403 to "Custom Forbidden",
                  429 to "Custom Too Many Requests",
              )
        }
        .build()

/** caplog equivalent: captures records for one logger while `block` runs. */
public class LogCapture(
    private val logger: Logger,
    private val level: Level = Level.INFO,
) : Handler() {
  public val records: MutableList<LogRecord> = mutableListOf()

  init {
    logger.addHandler(this)
    logger.level = level
  }

  public fun release() {
    logger.removeHandler(this)
  }

  public fun messages(levelNo: Level): List<String> =
      records.filter { it.level == levelNo }.map { it.message }

  override fun publish(record: LogRecord) {
    records.add(record)
  }

  override fun flush() {}

  override fun close() {}
}

public suspend fun captureLogs(
    loggerName: String,
    level: Level = Level.INFO,
    block: suspend (LogCapture) -> Unit,
) {
  val logger = Logger.getLogger(loggerName)
  val capture = LogCapture(logger, level)
  try {
    block(capture)
  } finally {
    capture.release()
  }
}

/** Run a suspend test body under runBlocking. */
public fun runTest(block: suspend () -> Unit) {
  runBlocking { block() }
}

public fun redisOpCounter(): AtomicInteger = AtomicInteger(0)
