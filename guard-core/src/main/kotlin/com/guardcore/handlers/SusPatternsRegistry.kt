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
          com.guardcore.core.events.securityEventEnvelope(
              eventType = eventType,
              ipAddress = ipAddress,
              actionTaken = actionTaken,
              reason = reason,
              patternMatched = patternMatched,
              handlerName = SUS_PATTERNS_HANDLER_NAME,
              metadata = metadata,
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
      // Python passes pattern= as a **kwarg, so it lands in metadata (pattern_matched stays null).
      sendPatternEvent(
          eventType = EventTypes.EVENT_PATTERN_ADDED,
          ipAddress = "system",
          actionTaken = "pattern_added",
          reason = "$details to detection system",
          metadata =
              mapOf(
                  "pattern" to DetectionScanRedaction.redactPatternSource(pattern),
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
    // Python passes pattern= as a **kwarg, so it lands in metadata (pattern_matched stays null).
    sendPatternEvent(
        eventType = EventTypes.EVENT_PATTERN_REMOVED,
        ipAddress = "system",
        actionTaken = "pattern_removed",
        reason = "$details from detection system",
        metadata =
            mapOf(
                "pattern" to DetectionScanRedaction.redactPatternSource(pattern),
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

  /**
   * Port of `suspatterns_handler.detect` (suspatterns_handler.py:855): the full engine verdict plus
   * the `overall_detection` performance record (suspatterns_handler.py:966-976) and the
   * pattern_detected threat event on match (suspatterns_handler.py:1020-1050).
   */
  public suspend fun detect(
      content: String,
      ipAddress: String,
      context: String = "unknown",
      correlationId: String? = null,
      enabledCategories: Set<String>? = null,
      contentPreview: String? = null,
  ): Map<String, Any?> {
    val executionStart = System.nanoTime()
    val result = engine.detect(content, ipAddress, context, correlationId, enabledCategories)
    val totalExecutionTime = (System.nanoTime() - executionStart) / 1e9

    engine.detectionState.performanceMonitor?.recordMetric(
        "overall_detection",
        totalExecutionTime,
        content.length,
        matched = result.isThreat,
        timeout = false,
        agentHandler =
            agentHandler?.let { sink ->
              // The engine monitor seam is synchronous; the sink handoff blocks on the dispatch.
              com.guardcore.engine.detection.AnomalyEventSink { event ->
                kotlinx.coroutines.runBlocking { sink.sendEvent(event) }
              }
            },
        correlationId = correlationId,
    )

    if (result.isThreat) {
      sendThreatEvent(
          result,
          ipAddress,
          context,
          content,
          correlationId,
          contentPreview,
      )
    }

    return linkedMapOf(
        "is_threat" to result.isThreat,
        "threat_score" to result.threatScore,
        "threats" to result.threats.map { it.toMap() },
        "context" to result.context,
        "original_length" to result.originalLength,
        "processed_length" to result.processedLength,
        "execution_time" to totalExecutionTime,
        "detection_method" to result.detectionMethod,
        "timeouts" to result.timeouts,
        "correlation_id" to result.correlationId,
    )
  }

  /**
   * Port of `_send_threat_event` (suspatterns_handler.py:990): pattern info from the first matched
   * pattern (semantic threats render `semantic:<attack_type>`), redacted pattern source, and the
   * count metadata payload.
   */
  private suspend fun sendThreatEvent(
      result: com.guardcore.engine.suspatterns.DetectResult,
      ipAddress: String,
      context: String,
      content: String,
      correlationId: String?,
      contentPreview: String?,
  ) {
    val threats = result.threats
    val regexThreats = threats.filter { it.type != "semantic" }
    val semanticThreats = threats.filter { it.type == "semantic" }

    val patternInfo =
        when {
          regexThreats.isNotEmpty() -> regexThreats.first().pattern
          semanticThreats.isNotEmpty() ->
              "semantic:${semanticThreats.first().attackType ?: "suspicious"}"
          else -> "unknown"
        }

    val previewSource = contentPreview ?: content
    val cappedPreview = if (previewSource.length > 100) previewSource.take(100) else previewSource

    val threatCategories = com.guardcore.engine.suspatterns.collectThreatCategories(threats)

    val patternMatched =
        com.guardcore.handlers.DetectionScanRedaction.redactPatternSource(patternInfo)

    sendPatternEvent(
        eventType = EventTypes.EVENT_PATTERN_DETECTED,
        ipAddress = ipAddress,
        actionTaken = "threat_detected",
        reason = "Threat detected in $context",
        patternMatched = patternMatched,
        metadata =
            linkedMapOf(
                "pattern" to patternMatched,
                "context" to context,
                "content_preview" to
                    com.guardcore.engine.suspatterns.sanitizeForReporting(cappedPreview),
                "threat_score" to result.threatScore,
                "threats" to threats.size,
                "regex_threats" to regexThreats.size,
                "semantic_threats" to semanticThreats.size,
                "timeouts" to result.timeouts.size,
                "detection_method" to result.detectionMethod,
                "execution_time_ms" to (result.executionTime * 1000).toInt(),
                "correlation_id" to correlationId,
                "threat_categories" to threatCategories,
                "category" to threatCategories.firstOrNull(),
            ),
    )
  }

  /** Port of `reset` (_suspatterns_registry.py:252). */
  public suspend fun reset() {
    engine.customPatterns.clear()
    engine.compiledCustomPatterns.clear()
    redisHandler = null
    agentHandler = null
    engine.detectionState.compiler?.clearCache()
    engine.detectionState.performanceMonitor?.clearStats()
  }

  /**
   * Corpus helper mirroring the events harness's direct registry clears (events_harness.py:397-398,
   * 410-411); production never calls it.
   */
  public fun clearCustomPatternsForCorpus() {
    engine.customPatterns.clear()
    engine.compiledCustomPatterns.clear()
  }

  /**
   * Corpus helper seeding the registry directly so a case pins the removal event alone
   * (events_harness.py:412-415); production never calls it.
   */
  public fun seedCustomPatternForCorpus(pattern: String) {
    engine.customPatterns.clear()
    engine.compiledCustomPatterns.clear()
    engine.customPatterns.add(pattern)
    val compiled =
        PatternCompiler().compilePattern(pattern, com.guardcore.engine.py.PyReFlags.IGNORECASE)
    engine.compiledCustomPatterns.add(
        com.guardcore.engine.suspatterns.CompiledPatternRow(compiled, setOf(), "custom"),
    )
  }
}
