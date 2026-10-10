package com.guardcore.handlers

import com.guardcore.config.BehaviorRuleConfig
import com.guardcore.config.SecurityConfig
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.util.IdentityHash
import com.guardcore.util.LruStore
import java.util.logging.Logger
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Port of `guard_core/handlers/behavior_handler.py` (BehaviorRule, BehaviorTracker, config_to_rule)
 * with its mixin files:
 * - `_behavior_action_dispatch.py` -> BehaviorActionDispatch.kt extensions
 * - `_behavior_response_pattern.py` + `_behavior_json_pattern.py` -> BehaviorResponsePattern.kt
 *   extensions
 */

/** Python `BehaviorRule.__init__` defaults (behavior_handler.py:29). */
public class BehaviorRule(
    public val ruleType: String,
    public val threshold: Int,
    public val window: Int = 3600,
    public val pattern: String? = null,
    public val action: String = "log",
    public val customAction:
        (suspend (clientIp: String, endpointId: String, details: String) -> Unit)? =
        null,
    public val banDuration: Int? = null,
    public val correlateWithDetection: Boolean = false,
)

/** Port of `config_to_rule` (behavior_handler.py:182). */
public fun configToRule(cfg: BehaviorRuleConfig): BehaviorRule =
    BehaviorRule(
        ruleType = cfg.ruleType.pythonName,
        threshold = cfg.threshold,
        window = cfg.window,
        pattern = cfg.pattern,
        action = cfg.action.pythonName,
        banDuration = cfg.banDuration,
        correlateWithDetection = cfg.correlateWithDetection,
    )

/**
 * Python `_MAX_TRACKED_ENDPOINTS` / `_MAX_TRACKED_CLIENTS_PER_ENDPOINT` (behavior_handler.py:50).
 */
public const val MAX_TRACKED_ENDPOINTS: Int = 10_000
public const val MAX_TRACKED_CLIENTS_PER_ENDPOINT: Int = 10_000

/**
 * Port of `BehaviorTracker` (behavior_handler.py:54): per-endpoint usage and return-pattern tallies
 * over Redis (shared workers) or the local LRU store (single process).
 */
public class BehaviorTracker(
    public val config: SecurityConfig,
) {
  public val logger: Logger = Logger.getLogger("guard_core.handlers.behavior")

  /** Port of `usage_counts` (behavior_handler.py:58): endpoint -> client -> timestamps. */
  public val usageCounts: LinkedHashMap<String, LinkedHashMap<String, MutableList<Double>>> =
      linkedMapOf()

  /** Port of `return_patterns` (behavior_handler.py:61): pattern_key -> client -> timestamps. */
  public val returnPatterns: LinkedHashMap<String, LinkedHashMap<String, MutableList<Double>>> =
      linkedMapOf()

  @Volatile public var redisHandler: RedisHandlerProtocol? = null

  @Volatile public var agentHandler: HandlerAgentSink? = null

  /** Port of `_body_unavailable_log_cache` (behavior_handler.py:66). */
  public val bodyUnavailableLogCache: TtlCache<String, Boolean> =
      TtlCache(maxsize = 1000, ttlSeconds = 300.0)

  private val lock = Mutex()

  /** Port of `initialize_redis` (behavior_handler.py:71). */
  public suspend fun initializeBehaviorRedis(redisHandler: RedisHandlerProtocol?) {
    this.redisHandler = redisHandler
  }

  /** Port of `initialize_agent` (behavior_handler.py:74). */
  public suspend fun initializeAgent(agentHandler: HandlerAgentSink?) {
    this.agentHandler = agentHandler
  }

  /** Port of `get_recent_event_count` (behavior_handler.py:77). */
  public suspend fun getRecentEventCount(ip: String, windowSeconds: Int): Int {
    if (ip.isEmpty()) {
      return 0
    }
    val cutoff = nowSeconds() - windowSeconds
    var count = 0
    lock.withLock {
      for (endpointBucket in usageCounts.values) {
        for (ts in endpointBucket[ip] ?: emptyList()) {
          if (ts >= cutoff) {
            count += 1
          }
        }
      }
    }
    return count
  }

  /** Port of `track_endpoint_usage` (behavior_handler.py:89). */
  public suspend fun trackEndpointUsage(
      endpointId: String,
      clientIp: String,
      rule: BehaviorRule,
  ): Boolean {
    val currentTime = nowSeconds()
    val windowStart = currentTime - rule.window

    val redis = redisHandler
    if (redis != null) {
      val key =
          "behavior:usage:${IdentityHash.hashIdentitySegment(endpointId)}:" +
              IdentityHash.hashIdentitySegment(clientIp)

      val validCount =
          slidingWindowHit(redis, "behavior_usage", key, currentTime, windowStart, rule.window)

      return validCount > rule.threshold
    }

    lock.withLock {
      val bucket =
          LruStore.lruPopOrCreate(
              usageCounts,
              endpointId,
              MAX_TRACKED_ENDPOINTS,
          ) {
            linkedMapOf()
          }
      usageCounts[endpointId] = bucket
      val timestamps =
          LruStore.lruPopOrCreate(bucket, clientIp, MAX_TRACKED_CLIENTS_PER_ENDPOINT) {
            mutableListOf<Double>()
          }

      timestamps.removeAll { it < windowStart }

      timestamps.add(currentTime)
      bucket[clientIp] = timestamps

      return timestamps.size > rule.threshold
    }
  }

  /** Port of `track_return_pattern` (behavior_handler.py:126). */
  public suspend fun trackReturnPattern(
      endpointId: String,
      clientIp: String,
      response: GuardResponse,
      rule: BehaviorRule,
      effectiveThreshold: Int? = null,
  ): Boolean {
    val pattern = rule.pattern ?: return false

    val threshold = effectiveThreshold ?: rule.threshold
    val currentTime = nowSeconds()
    val windowStart = currentTime - rule.window

    val patternMatched = checkResponsePattern(response, pattern)

    if (patternMatched != true) {
      return false
    }

    val redis = redisHandler
    if (redis != null) {
      val key =
          "behavior:return:${IdentityHash.hashIdentitySegment(endpointId)}:" +
              IdentityHash.hashIdentitySegment(clientIp) +
              ":" +
              IdentityHash.hashIdentitySegment(pattern)

      val validCount =
          slidingWindowHit(redis, "behavior_returns", key, currentTime, windowStart, rule.window)

      return validCount > threshold
    }

    val patternKey = "$endpointId:$pattern"
    lock.withLock {
      val bucket =
          LruStore.lruPopOrCreate(returnPatterns, patternKey, MAX_TRACKED_ENDPOINTS) {
            linkedMapOf()
          }
      returnPatterns[patternKey] = bucket
      val timestamps =
          LruStore.lruPopOrCreate(bucket, clientIp, MAX_TRACKED_CLIENTS_PER_ENDPOINT) {
            mutableListOf<Double>()
          }

      timestamps.removeAll { it < windowStart }

      timestamps.add(currentTime)
      bucket[clientIp] = timestamps

      return timestamps.size > threshold
    }
  }

  /**
   * `redis_handler.record_sliding_window_hit` resolves through the protocol; with a [RedisManager]
   * it delegates to the real implementation (UUID members, zset shape).
   */
  private suspend fun slidingWindowHit(
      redis: RedisHandlerProtocol,
      namespace: String,
      key: String,
      timestamp: Double,
      windowStart: Double,
      window: Int,
  ): Long =
      when (redis) {
        is RedisManager ->
            redis.recordSlidingWindowHit(namespace, key, timestamp, windowStart, window)
        else -> {
          val ops = redis.getConnection().client as? RedisOperations
          if (ops != null) {
            val fullKey = "${redisPrefixOf(redis)}$namespace:$key"
            val results = ops.transaction { tx ->
              tx.zadd(fullKey, timestamp, java.util.UUID.randomUUID().toString().replace("-", ""))
              tx.zremRangeByScore(
                  fullKey,
                  "-inf",
                  "(${com.guardcore.util.py.PyJson.floatRepr(windowStart)}",
              )
              tx.zcard(fullKey)
              tx.expire(fullKey, window.toLong())
            }
            (results.getOrNull(2) as? Number)?.toLong() ?: 0L
          } else {
            0L
          }
        }
      }
}
