package com.guardcore.handlers

import com.guardcore.config.EventTypes
import com.guardcore.config.SecurityConfig
import com.guardcore.errors.GuardRedisError
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.util.AgentEvents
import com.guardcore.util.IdentityHash
import com.guardcore.util.LruStore
import com.guardcore.util.RequestLogging
import io.lettuce.core.RedisException
import io.lettuce.core.RedisNoScriptException
import java.util.ArrayDeque
import java.util.logging.Logger

/** Per-process module state of `guard_core/handlers/ratelimit_handler.py`. */
public object RateLimitState {
  /** Python `_by_ip_request_timestamps` (ratelimit_handler.py:23). */
  public val byIpRequestTimestamps: LinkedHashMap<String, ArrayDeque<Double>> = linkedMapOf()

  /** Python `_by_ip_autoban_counts` (ratelimit_handler.py:24). */
  public val byIpAutobanCounts: LinkedHashMap<String, Int> = linkedMapOf()

  /** Python `_MAX_TRACKED_RATE_LIMIT_KEYS` (ratelimit_handler.py:25). */
  public const val MAX_TRACKED_RATE_LIMIT_KEYS: Int = 10_000

  /** Python `_redis_fail_open_warned` (ratelimit_handler.py:26). */
  @Volatile public var redisFailOpenWarned: Boolean = false

  public val logger: Logger = Logger.getLogger("guard_core.handlers.ratelimit")

  public fun reset() {
    byIpRequestTimestamps.clear()
    byIpAutobanCounts.clear()
    redisFailOpenWarned = false
  }
}

/** Python `_RATE_LIMIT_HANDLER_NAME` (ratelimit_handler.py:22). */
public const val RATE_LIMIT_HANDLER_NAME: String = "rate_limit"

/** Port of `_warn_redis_fail_open_in_memory_fallback` (ratelimit_handler.py:29). */
public fun warnRedisFailOpenInMemoryFallback() {
  if (RateLimitState.redisFailOpenWarned) {
    return
  }
  RateLimitState.redisFailOpenWarned = true
  RateLimitState.logger.warning(
      "Redis unavailable for rate limiting; using the in-memory window " +
          "(redis_fail_open=True); with several workers the effective limit " +
          "is workers x rate_limit",
  )
}

/** Port of `_resolve_redis_rate_limit_failure` (ratelimit_handler.py:41). */
public fun resolveRedisRateLimitFailure(
    error: Exception,
    redisFailOpen: Boolean,
    logger: Logger,
    context: String,
) {
  if (redisFailOpen) {
    warnRedisFailOpenInMemoryFallback()
    return
  }
  logger.severe("$context: $error")
  throw GuardRedisError(503, "Redis rate limiting unavailable").initCause(error)
}

/**
 * Port of `_redis_request_count` (ratelimit_handler.py:54). Returns (count, scriptSha); count is
 * null when Redis yielded no answer (or fail-open swallowed the failure).
 */
public suspend fun redisRequestCount(
    redisHandler: com.guardcore.protocols.RedisHandlerProtocol?,
    logger: Logger,
    clientIp: String,
    currentTime: Double,
    windowStart: Double,
    rateLimitWindow: Int,
    rateLimit: Int,
    rateLimitScriptSha: String?,
    onScriptReloaded: (suspend () -> Unit)? = null,
    endpointPath: String = "",
    redisFailOpen: Boolean = false,
): Pair<Long?, String?> {
  var scriptSha = rateLimitScriptSha
  if (redisHandler == null) {
    return null to scriptSha
  }

  val rateKey =
      if (endpointPath.isNotEmpty()) {
        "rate:$clientIp:${IdentityHash.hashIdentitySegment(endpointPath)}"
      } else {
        "rate:$clientIp"
      }
  val keyName = "${redisPrefixOf(redisHandler)}rate_limit:$rateKey"

  try {
    if (scriptSha != null) {
      val count =
          withRedisConnection(redisHandler) { conn ->
            try {
              conn.evalSha(
                  scriptSha!!,
                  listOf(keyName),
                  listOf(
                      PyFloatStr.of(currentTime),
                      rateLimitWindow.toString(),
                      rateLimit.toString(),
                  ),
              )
            } catch (e: RedisNoScriptException) {
              scriptSha = conn.scriptLoad(RATE_LIMIT_SCRIPT)
              logger.info("Rate limit Lua script reloaded after NOSCRIPT")
              onScriptReloaded?.invoke()
              conn.evalSha(
                  scriptSha!!,
                  listOf(keyName),
                  listOf(
                      PyFloatStr.of(currentTime),
                      rateLimitWindow.toString(),
                      rateLimit.toString(),
                  ),
              )
            }
          }
      return count to scriptSha
    } else {
      val count =
          withRedisConnection(redisHandler) { conn ->
            val results = conn.transaction { tx ->
              tx.zadd(keyName, currentTime, PyFloatStr.of(currentTime))
              tx.zremRangeByScore(keyName, "0", PyFloatStr.of(windowStart))
              tx.zcard(keyName)
              tx.expire(keyName, (rateLimitWindow * 2).toLong())
            }
            (results.getOrNull(2) as? Number)?.toLong() ?: 0L
          }
      return count to scriptSha
    }
  } catch (e: RedisNoScriptException) {
    resolveRedisRateLimitFailure(e, redisFailOpen, logger, "Redis rate limiting error")
  } catch (e: RedisException) {
    resolveRedisRateLimitFailure(e, redisFailOpen, logger, "Redis rate limiting error")
  } catch (e: GuardRedisError) {
    resolveRedisRateLimitFailure(e, redisFailOpen, logger, "Redis rate limiting error")
  } catch (e: Exception) {
    resolveRedisRateLimitFailure(e, redisFailOpen, logger, "Unexpected error in rate limiting")
  }

  return null to scriptSha
}

/** Python float `str()` over the CPython float.__repr__ port. */
public object PyFloatStr {
  public fun of(value: Double): String = com.guardcore.util.py.PyJson.floatRepr(value)
}

/**
 * `async with redis_handler.get_connection() as conn` (ratelimit_handler.py:79): real managers
 * auto-initialize and map connection failures; protocol fakes yield their raw scripted client.
 */
public suspend fun <T> withRedisConnection(
    redisHandler: com.guardcore.protocols.RedisHandlerProtocol?,
    block: suspend (RedisOperations) -> T,
): T? =
    when (redisHandler) {
      is RedisManager -> redisHandler.withConnection { conn -> block(conn) }
      null -> null
      else -> (redisHandler.getConnection().client as? RedisOperations)?.let { block(it) }
    }

/** Port of `_in_memory_request_count` (ratelimit_handler.py:125). */
public fun inMemoryRequestCount(
    requestTimestamps: LinkedHashMap<String, ArrayDeque<Double>>,
    clientIp: String,
    windowStart: Double,
    currentTime: Double,
    endpointPath: String = "",
): Long {
  val key =
      if (endpointPath.isNotEmpty()) {
        "$clientIp:${IdentityHash.hashIdentitySegment(endpointPath)}"
      } else {
        clientIp
      }

  val timestamps =
      LruStore.lruPopOrCreate(requestTimestamps, key, RateLimitState.MAX_TRACKED_RATE_LIMIT_KEYS) {
        ArrayDeque()
      }

  while (!timestamps.isEmpty() && timestamps.first() <= windowStart) {
    timestamps.removeFirst()
  }

  val requestCount = timestamps.size.toLong()
  timestamps.addLast(currentTime)
  requestTimestamps[key] = timestamps

  return requestCount
}

/**
 * Port of `_feed_rate_limit_autoban` (ratelimit_handler.py:152): feeds a rate-limited call into the
 * shared auto-ban engine through the dedicated per-process violation counter.
 */
public suspend fun feedRateLimitAutoban(ip: String, config: SecurityConfig) {
  if (!(config.enableRateLimitAutoBan && config.enableIpBanning)) {
    return
  }
  if (config.passiveMode) {
    return
  }

  val ipBanManager = IpBanManager.getInstance()
  if (ipBanManager.isIpBanned(ip)) {
    return
  }

  val count =
      LruStore.lruPopOrCreate(
          RateLimitState.byIpAutobanCounts,
          ip,
          RateLimitState.MAX_TRACKED_RATE_LIMIT_KEYS,
      ) {
        0
      } + 1
  RateLimitState.byIpAutobanCounts[ip] = count
  val ipCounts = mapOf("rate_limit" to count)
  val result =
      com.guardcore.core.checks.ChecksHelpers.resolveAndApplyThresholdBan(
          ipCounts,
          config,
          ipBanManager,
          ip,
          listOf("rate_limit"),
          "rate_limit_exceeded",
      )
  if (result != null) {
    RateLimitState.logger.warning(
        "check_rate_limit_by_ip: auto-banned $ip (rate_limit_exceeded)",
    )
  }
}

/**
 * Port of `check_rate_limit_by_ip` (ratelimit_handler.py:199): records a sliding-window hit for a
 * raw IP outside the HTTP pipeline. Returns true when allowed, false when rate-limited.
 */
public suspend fun checkRateLimitByIp(
    ip: String,
    config: SecurityConfig,
    redisHandler: com.guardcore.protocols.RedisHandlerProtocol? = null,
    endpointPath: String = "",
): Boolean {
  try {
    com.guardcore.util.py.parseAddress(ip)
  } catch (e: Exception) {
    throw IllegalArgumentException("check_rate_limit_by_ip: invalid ip '$ip'").initCause(e)
  }
  if (endpointPath.contains(':')) {
    val safeEndpointPath =
        RequestLogging.redactEndpointForDisplay(
            endpointPath,
            config.logSensitiveParams,
            config.logSensitiveBodyFields,
            config.logSensitiveHeaders,
        )
    throw IllegalArgumentException(
        "check_rate_limit_by_ip: endpoint_path must not contain ':' " + "(got '$safeEndpointPath')",
    )
  }

  if (!config.enableRateLimiting) {
    return true
  }

  val currentTime = nowSeconds()
  val windowStart = currentTime - config.rateLimitWindow

  var allowed: Boolean? = null
  if (config.enableRedis && redisHandler != null) {
    val (count, _) =
        redisRequestCount(
            redisHandler,
            RateLimitState.logger,
            ip,
            currentTime,
            windowStart,
            config.rateLimitWindow,
            config.rateLimit,
            null,
            null,
            endpointPath,
            config.redisFailOpen,
        )
    if (count != null) {
      allowed = count <= config.rateLimit
    }
  }

  if (allowed == null) {
    val requestCount =
        inMemoryRequestCount(
            RateLimitState.byIpRequestTimestamps,
            ip,
            windowStart,
            currentTime,
            endpointPath = endpointPath,
        )
    allowed = requestCount < config.rateLimit
  }

  if (!allowed) {
    feedRateLimitAutoban(ip, config)
  }

  return allowed
}

/**
 * Port of `guard_core/handlers/ratelimit_handler.py` (RateLimitManager): the sliding-window rate
 * limiter over Redis (Lua script) with an in-memory fallback.
 */
public class RateLimitManager
private constructor(
    config: SecurityConfig,
) {
  public companion object {
    @Volatile private var instance: RateLimitManager? = null

    /** Python `RateLimitManager(config)` singleton dispatch (ratelimit_handler.py:314). */
    public fun getInstance(config: SecurityConfig): RateLimitManager {
      val existing = instance
      if (existing != null) {
        existing.config = config
        return existing
      }
      synchronized(this) {
        val again = instance
        if (again != null) {
          again.config = config
          return again
        }
        val created = RateLimitManager(config)
        instance = created
        return created
      }
    }

    /** Test seam mirroring `RateLimitManager._instance = None`. */
    public fun resetInstance() {
      synchronized(this) { instance = null }
    }
  }

  public var config: SecurityConfig = config

  public val requestTimestamps: LinkedHashMap<String, ArrayDeque<Double>> = linkedMapOf()

  public val logger: Logger = Logger.getLogger("guard_core.handlers.ratelimit")

  @Volatile public var redisHandler: com.guardcore.protocols.RedisHandlerProtocol? = null

  @Volatile public var agentHandler: HandlerAgentSink? = null

  @Volatile public var rateLimitScriptSha: String? = null

  /** Port of `initialize_redis` (ratelimit_handler.py:329). */
  public suspend fun initializeRedis(redisHandler: com.guardcore.protocols.RedisHandlerProtocol?) {
    this.redisHandler = redisHandler

    if (redisHandler != null && config.enableRedis) {
      try {
        withRedisConnection(redisHandler) { conn ->
          rateLimitScriptSha = conn.scriptLoad(RATE_LIMIT_SCRIPT)
          logger.info("Rate limiting Lua script loaded successfully")
          rateLimitScriptSha
        }
      } catch (e: Exception) {
        logger.severe("Failed to load rate limiting Lua script: $e")
      }
    }
  }

  /** Port of `initialize_agent` (ratelimit_handler.py:342). */
  public suspend fun initializeAgent(agentHandler: HandlerAgentSink?) {
    this.agentHandler = agentHandler
  }

  /** Port of `_emit_script_reloaded_event` (ratelimit_handler.py:345). */
  public suspend fun emitScriptReloadedEvent() {
    val handler = agentHandler ?: return
    try {
      handler.sendEvent(
          com.guardcore.core.events.securityEventEnvelope(
              eventType = EventTypes.EVENT_RATE_LIMIT_SCRIPT_RELOADED,
              ipAddress = "system",
              actionTaken = "script_reloaded",
              reason = "NOSCRIPT recovery: Lua script re-cached on Redis",
              handlerName = RATE_LIMIT_HANDLER_NAME,
              metadata = emptyMap<String, Any?>(),
          ),
      )
    } catch (e: Exception) {
      logger.severe("Failed to send script-reload event: $e")
    }
  }

  /** Port of `_get_redis_request_count` (ratelimit_handler.py:368). */
  public suspend fun getRedisRequestCount(
      clientIp: String,
      currentTime: Double,
      windowStart: Double,
      endpointPath: String = "",
      rateLimitWindow: Int? = null,
      rateLimit: Int? = null,
      redisFailOpen: Boolean? = null,
  ): Long? {
    val (count, sha) =
        redisRequestCount(
            redisHandler,
            logger,
            clientIp,
            currentTime,
            windowStart,
            rateLimitWindow ?: config.rateLimitWindow,
            rateLimit ?: config.rateLimit,
            rateLimitScriptSha,
            { emitScriptReloadedEvent() },
            endpointPath,
            redisFailOpen ?: config.redisFailOpen,
        )
    rateLimitScriptSha = sha
    return count
  }

  /** Port of `_handle_rate_limit_exceeded` (ratelimit_handler.py:395). */
  public suspend fun handleRateLimitExceeded(
      request: GuardRequest,
      clientIp: String,
      count: Long,
      createErrorResponse: suspend (Int, String) -> GuardResponse,
      rateLimitWindow: Int? = null,
      config: SecurityConfig? = null,
  ): GuardResponse {
    val displayConfig = config ?: this.config
    val window = rateLimitWindow ?: displayConfig.rateLimitWindow
    val message = "Rate limit exceeded for IP:"
    val detail = "requests in ${window}s window)"
    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "$message $clientIp ($count $detail",
        level = displayConfig.logSuspiciousLevel?.pythonName,
        passiveMode = displayConfig.passiveMode,
        checkName = "rate_limit",
        mutedCheckLogs = displayConfig.mutedCheckLogs,
        onBlock = displayConfig.onBlock,
        sensitiveHeaders = displayConfig.logSensitiveHeaders,
        sensitiveParams = displayConfig.logSensitiveParams,
        sensitiveBodyFields = displayConfig.logSensitiveBodyFields,
    )

    if (agentHandler != null) {
      sendRateLimitEvent(request, clientIp, count, config = displayConfig)
    }

    val response = createErrorResponse(429, "Too many requests")
    response.headers["Retry-After"] = window.toString()
    return response
  }

  /** Port of `_get_in_memory_request_count` (ratelimit_handler.py:435). */
  public fun getInMemoryRequestCount(
      clientIp: String,
      windowStart: Double,
      currentTime: Double,
      endpointPath: String = "",
  ): Long =
      inMemoryRequestCount(
          requestTimestamps,
          clientIp,
          windowStart,
          currentTime,
          endpointPath = endpointPath,
      )

  /** Port of `check_rate_limit` (ratelimit_handler.py:450). */
  public suspend fun checkRateLimit(
      request: GuardRequest,
      clientIp: String,
      createErrorResponse: suspend (Int, String) -> GuardResponse,
      endpointPath: String = "",
      rateLimit: Int? = null,
      rateLimitWindow: Int? = null,
      config: SecurityConfig? = null,
  ): GuardResponse? {
    val displayConfig = config ?: this.config
    if (!displayConfig.enableRateLimiting) {
      return null
    }

    val effectiveLimit = rateLimit ?: displayConfig.rateLimit
    val effectiveWindow = rateLimitWindow ?: displayConfig.rateLimitWindow

    val currentTime = nowSeconds()
    val windowStart = currentTime - effectiveWindow

    if (displayConfig.enableRedis && redisHandler != null) {
      val count =
          getRedisRequestCount(
              clientIp,
              currentTime,
              windowStart,
              endpointPath = endpointPath,
              rateLimitWindow = effectiveWindow,
              rateLimit = effectiveLimit,
              redisFailOpen = displayConfig.redisFailOpen,
          )

      if (count != null) {
        if (count > effectiveLimit) {
          return handleRateLimitExceeded(
              request,
              clientIp,
              count,
              createErrorResponse,
              rateLimitWindow = effectiveWindow,
              config = displayConfig,
          )
        }
        return null
      }
    }

    val requestCount =
        getInMemoryRequestCount(clientIp, windowStart, currentTime, endpointPath = endpointPath)

    if (requestCount >= effectiveLimit) {
      return handleRateLimitExceeded(
          request,
          clientIp,
          requestCount + 1,
          createErrorResponse,
          rateLimitWindow = effectiveWindow,
          config = displayConfig,
      )
    }

    return null
  }

  /** Port of `_send_rate_limit_event` (ratelimit_handler.py:515). */
  public suspend fun sendRateLimitEvent(
      request: GuardRequest,
      clientIp: String,
      requestCount: Long,
      config: SecurityConfig? = null,
  ) {
    val displayConfig = config ?: this.config
    try {
      val message = "Rate limit exceeded"
      val details = "${requestCount} requests in ${displayConfig.rateLimitWindow}s window"

      agentHandler?.sendEvent(
          com.guardcore.core.events.securityEventEnvelope(
              eventType = EventTypes.EVENT_RATE_LIMITED,
              ipAddress = clientIp,
              actionTaken = "request_blocked",
              reason = "$message: $details",
              endpoint =
                  RequestLogging.redactEndpointForDisplay(
                      request.urlPath,
                      displayConfig.logSensitiveParams,
                      displayConfig.logSensitiveBodyFields,
                      displayConfig.logSensitiveHeaders,
                  ),
              method = request.method,
              responseTime = AgentEvents.getPipelineResponseTime(request),
              handlerName = RATE_LIMIT_HANDLER_NAME,
              metadata =
                  mapOf(
                      "request_count" to requestCount,
                      "rate_limit" to displayConfig.rateLimit,
                      "window" to displayConfig.rateLimitWindow,
                  ),
          ),
      )
    } catch (e: Exception) {
      logger.severe("Failed to send rate limit event to agent: $e")
    }
  }

  /** Port of `reset` (ratelimit_handler.py:561). */
  public suspend fun reset() {
    requestTimestamps.clear()

    val redis = redisHandler
    if (config.enableRedis && redis != null) {
      try {
        val keys = redis.keys("rate_limit:rate:*")
        if (!keys.isNullOrEmpty()) {
          if (redis is RedisManager) {
            redis.deletePattern("rate_limit:rate:*")
          } else {
            // delete_pattern("rate_limit:rate:*") re-prefixes internally; the keys call
            // already returned fully-qualified keys, so delete them as returned.
            (redis.getConnection().client as? RedisOperations)?.del(*keys.toTypedArray())
          }
        }
      } catch (e: Exception) {
        logger.severe("Failed to reset Redis rate limits: $e")
      }
    }

    redisHandler = null
    agentHandler = null
  }
}
