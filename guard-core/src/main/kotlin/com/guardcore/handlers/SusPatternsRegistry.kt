package com.guardcore.handlers

import com.guardcore.config.EventTypes
import com.guardcore.engine.detection.PatternCompiler
import com.guardcore.engine.suspatterns.SusPatternsManager
import com.guardcore.protocols.RedisHandlerProtocol
import java.util.logging.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Port of the `guard_core/handlers/_suspatterns_registry.py` (custom-pattern registry) handler
 * surface that W3 owns: add/remove pattern with the Redis `patterns:custom` persistence, the
 * restore-on-initialize path, and the pattern_added/pattern_removed events.
 *
 * The compile/validate/detect surface underneath is the W2 engine
 * (`com.guardcore.engine.suspatterns.SusPatternsManager`); the reference's
 * `asyncio.to_thread(validate)` runs inline under the hard match deadline (Go posture, engine idiom
 * mapping). The `_suspatterns_views`/`_suspatterns_state` detect() path is engine-side from W2.
 */
public object SusPatternsRegistry {
  private val logger: Logger = Logger.getLogger("guard_core.handlers.suspatterns")

  /** Python `_SUS_PATTERNS_HANDLER_NAME` (_suspatterns_registry.py:17). */
  public const val SUS_PATTERNS_HANDLER_NAME: String = "sus_patterns"

  @Volatile public var redisHandler: RedisHandlerProtocol? = null

  @Volatile public var agentHandler: HandlerAgentSink? = null

  private val engine: SusPatternsManager
    get() = SusPatternsManager.shared()

  private val engineCompiler: PatternCompiler?
    get() = engine.detectionState.compiler

  /** Port of `_send_pattern_event` (_suspatterns_registry.py:32). */
  public suspend fun sendPatternEvent(
      eventType: String,
      ipAddress: String,
      actionTaken: String,
      reason: String,
      patternMatched: String? = null,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    val handler = agentHandler ?: return
    try {
      handler.sendEvent(
          linkedMapOf<String, Any?>(
              "event_type" to eventType,
              "ip_address" to ipAddress,
              "action_taken" to actionTaken,
              "reason" to reason,
              "pattern_matched" to patternMatched,
              "handler_name" to SUS_PATTERNS_HANDLER_NAME,
              "metadata" to metadata,
          ),
      )
    } catch (e: Exception) {
      logger.severe("Failed to send pattern event to agent: $e")
    }
  }

  /** Port of `initialize_redis` (_suspatterns_registry.py:63). */
  public suspend fun initializeRedis(redisHandler: RedisHandlerProtocol?) {
    this.redisHandler = redisHandler
    val redis = redisHandler ?: return
    try {
      val cachedPatterns = redis.getKey("patterns", "custom")?.toString()
      if (!cachedPatterns.isNullOrEmpty()) {
        val patterns = cachedPatterns.split(",")
        for (pattern in patterns) {
          if (pattern !in engine.customPatterns) {
            val restored = addPattern(pattern, custom = true)
            if (!restored) {
              logger.warning(
                  "Skipped restoring persisted pattern: " +
                      "${DetectionScanRedaction.redactPatternSource(pattern).take(50)}...",
              )
            }
          }
        }
      }
    } catch (e: Exception) {
      logger.warning("Custom pattern restore skipped: $e")
    }
  }

  /** Port of `add_pattern` (_suspatterns_registry.py:83). */
  public suspend fun addPattern(pattern: String, custom: Boolean = false): Boolean {
    val compiler = engineCompiler ?: PatternCompiler()
    val maxContentLength =
        engine.config?.detectionMaxBodyInspectBytes
            ?: com.guardcore.engine.suspatterns.DEFAULT_MAX_BODY_INSPECT_BYTES
    val (isSafe, reason) =
        withContext(Dispatchers.IO) {
          compiler.validatePatternSafety(pattern, maxContentLength = maxContentLength)
        }
    if (!isSafe) {
      logger.warning(
          "Rejected unsafe pattern ($reason): " +
              "${DetectionScanRedaction.redactPatternSource(pattern).take(50)}...",
      )
      return false
    }

    if (!engine.addPattern(pattern, custom)) {
      return false
    }

    if (custom) {
      val redis = redisHandler
      if (redis != null) {
        redis.setKey("patterns", "custom", engine.customPatterns.joinToString(","))
      }
    }

    if (agentHandler != null) {
      val details = (if (custom) "Custom" else "Default") + " pattern added"
      sendPatternEvent(
          eventType = EventTypes.EVENT_PATTERN_ADDED,
          ipAddress = "system",
          actionTaken = "pattern_added",
          reason = "$details to detection system",
          patternMatched = DetectionScanRedaction.redactPatternSource(pattern),
          metadata =
              mapOf(
                  "pattern_type" to if (custom) "custom" else "default",
                  "total_patterns" to
                      (if (custom) engine.customPatterns.size else engine.patterns.size),
              ),
      )
    }

    return true
  }

  /** Port of `_remove_custom_pattern` (_suspatterns_registry.py:138). */
  public suspend fun removeCustomPattern(pattern: String): Boolean {
    if (pattern !in engine.customPatterns) {
      return false
    }

    engine.customPatterns.remove(pattern)
    engine.compiledCustomPatterns.removeAll { it.compiled.source != pattern }

    val redis = redisHandler
    if (redis != null) {
      redis.setKey("patterns", "custom", engine.customPatterns.joinToString(","))
    }

    return true
  }

  /** Port of `_remove_default_pattern` (_suspatterns_registry.py:157). */
  public fun removeDefaultPattern(pattern: String): Boolean {
    val index = engine.patterns.indexOf(pattern)
    if (index == -1) {
      return false
    }
    engine.patterns.removeAt(index)
    if (index < engine.compiledPatterns.size) {
      engine.compiledPatterns.removeAt(index)
      return true
    }
    return false
  }

  /** Port of `_clear_pattern_caches` (_suspatterns_registry.py:170). */
  public suspend fun clearPatternCaches(pattern: String) {
    engine.detectionState.compiler?.clearCache()
    engine.detectionState.performanceMonitor?.removePatternStats(pattern)
  }

  /** Port of `_send_pattern_removal_event` (_suspatterns_registry.py:176). */
  public suspend fun sendPatternRemovalEvent(pattern: String, custom: Boolean, totalPatterns: Int) {
    val details = (if (custom) "Custom" else "Default") + " pattern removed"
    sendPatternEvent(
        eventType = EventTypes.EVENT_PATTERN_REMOVED,
        ipAddress = "system",
        actionTaken = "pattern_removed",
        reason = "$details from detection system",
        patternMatched = DetectionScanRedaction.redactPatternSource(pattern),
        metadata =
            mapOf(
                "pattern_type" to if (custom) "custom" else "default",
                "total_patterns" to totalPatterns,
            ),
    )
  }

  /** Port of `remove_pattern` (_suspatterns_registry.py:196). */
  public suspend fun removePattern(pattern: String, custom: Boolean = false): Boolean {
    val patternRemoved =
        if (custom) {
          removeCustomPattern(pattern)
        } else {
          removeDefaultPattern(pattern)
        }

    if (patternRemoved) {
      clearPatternCaches(pattern)
    }

    if (patternRemoved) {
      val totalPatterns = if (custom) engine.customPatterns.size else engine.patterns.size
      sendPatternRemovalEvent(pattern, custom, totalPatterns)
    }

    return patternRemoved
  }

  /** Port of `get_default_patterns` (_suspatterns_registry.py:216). */
  public suspend fun getDefaultPatterns(): List<String> = engine.patterns.toList()

  /** Port of `get_custom_patterns` (_suspatterns_registry.py:221). */
  public suspend fun getCustomPatterns(): List<String> = engine.customPatterns.toList()

  /** Port of `get_all_patterns` (_suspatterns_registry.py:226). */
  public suspend fun getAllPatterns(): List<String> =
      engine.patterns + engine.customPatterns.toList()

  /** Port of `reset` (_suspatterns_registry.py:252). */
  public suspend fun reset() {
    engine.customPatterns.clear()
    engine.compiledCustomPatterns.clear()
    redisHandler = null
    agentHandler = null
    engine.detectionState.compiler?.clearCache()
    engine.detectionState.performanceMonitor?.clearStats()
  }
}
