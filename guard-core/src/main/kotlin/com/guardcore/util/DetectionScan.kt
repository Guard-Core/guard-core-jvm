package com.guardcore.util

import com.guardcore.engine.detection.BinaryPrefix
import com.guardcore.engine.suspatterns.firstAcceptedRegexThreat
import com.guardcore.engine.suspatterns.normalizeContext
import com.guardcore.engine.suspatterns.sanitizeForReporting
import com.guardcore.handlers.DetectionScanRedaction

/**
 * Port of `guard_core/_utils/detection_scan.py` (G-7b): the scan-value walker. The budget
 * contextvars live in [DetectionScanBudget]; the redaction slice lives in [DetectionScanRedaction]
 * (G-10, unions registered live by [PenetrationDetection]).
 */
public object DetectionScan {
  /**
   * Test seam mirroring the python tests' `patch.object` of the shared SusPatternsManager detect:
   * when set, `checkValueEnhanced` resolves through it instead of the engine singleton (production
   * code never sets it).
   */
  @Volatile
  internal var enhancedDetectOverride:
      (
          content: String,
          ipAddress: String,
          context: String,
          correlationId: String,
          enabledCategories: Set<String>?,
      ) -> com.guardcore.engine.suspatterns.DetectResult? =
      { _, _, _, _, _ ->
        null
      }

  /** Python `_MAX_USER_AGENT_MATCH_LENGTH` (detection_scan.py:194). */
  public const val MAX_USER_AGENT_MATCH_LENGTH: Int = 512

  /** Python `_build_threat_message` (detection_scan.py:179). */
  public fun buildThreatMessage(threat: com.guardcore.engine.suspatterns.Threat): String {
    if (threat.type == "regex") {
      return "Value matched pattern '${DetectionScanRedaction.redactPatternSource(threat.pattern)}'"
    } else if (threat.type == "semantic") {
      val attackType = threat.attackType ?: "suspicious"
      val score = threat.probability ?: threat.threatScore ?: 0.0
      return "Semantic attack: $attackType (score: %.2f)".format(score)
    } else if (threat.type == "pattern_timeout") {
      return "Pattern exceeded scan time budget: '${DetectionScanRedaction.redactPatternSource(threat.pattern)}'"
    }
    return "Threat detected"
  }

  /**
   * Python `_build_threats_message`: when a per-pattern timeout or the spent scan budget tips the
   * request, the trigger names it behind a non-timeout first threat.
   */
  public fun buildThreatsMessage(threats: List<com.guardcore.engine.suspatterns.Threat>): String {
    val message = buildThreatMessage(threats.first())
    if (threats.first().type == "pattern_timeout") {
      return message
    }
    val timeout = threats.drop(1).firstOrNull { it.type == "pattern_timeout" } ?: return message
    return "$message; ${buildThreatMessage(timeout)}"
  }

  /** Python `_fallback_pattern_check` (detection_scan.py:211): the engine-exception fallback. */
  public suspend fun fallbackPatternCheck(
      value: String,
      clientIp: String,
      context: String,
  ): Pair<Boolean, String> {
    val manager = com.guardcore.engine.suspatterns.SusPatternsManager.shared()
    val normalizedContext = normalizeContext(context)
    val allCompiled = manager.getAllCompiledPatterns()
    val binaryPrefix = BinaryPrefix.buildBinaryPrefix(value)
    val scanBudget = DetectionScanBudget.scanTimeBudget()
    scanBudget?.openPass()
    try {
      for (row in allCompiled) {
        if (scanBudget != null && scanBudget.exhausted()) {
          return true to "Scan time budget exhausted (fallback)"
        }
        val patternStart = System.nanoTime()
        val threat =
            try {
              val matches = row.compiled.finditer(value, deadlineNanos = Long.MAX_VALUE)
              firstAcceptedRegexThreat(
                  matches,
                  row.compiled,
                  row.category,
                  patternStart,
                  normalizedContext,
                  binaryPrefix,
              )
            } catch (e: StackOverflowError) {
              // Python catches ONLY RecursionError here (detection_scan.py:216-222): the pattern
              // whose engine search blows the recursion limit is logged with its redacted source,
              // skipped, and the fallback scan continues; every other failure propagates. The JVM
              // recursion-limit analog is StackOverflowError (an Error, which the previous
              // catch-all Exception both missed and over-swallowed real exceptions with).
              DetectionScanContext.guardLogger.warning(
                  "Fallback pattern search hit the regex engine's recursion limit on pattern " +
                      "'${DetectionScanRedaction.redactPatternSource(row.compiled.source)}'; " +
                      "skipping it and continuing the fallback scan",
              )
              null
            }
        scanBudget?.charge()
        if (threat != null) {
          return true to "Value matched pattern (fallback)"
        }
      }
      return false to ""
    } finally {
      scanBudget?.closePass()
    }
  }

  /** Python `_resolve_json_redact_all` (detection_scan.py:245). */
  public fun resolveJsonRedactAll(contentPreview: String?, jsonRedactAll: Boolean?): Boolean {
    if (jsonRedactAll != null) {
      return jsonRedactAll
    }
    return contentPreview != null
  }

  /** The quadruple the python scan helpers return: (detected, trigger, threats, log_override). */
  public data class ScanHit(
      val detected: Boolean,
      val trigger: String,
      val threats: List<com.guardcore.engine.suspatterns.Threat>,
      val logOverride: String? = null,
  ) {
    public companion object {
      public val MISS: ScanHit = ScanHit(false, "", emptyList(), null)
    }
  }

  /** Python `_check_embedded_json_if_applicable` (detection_scan.py:253). */
  public suspend fun checkEmbeddedJsonIfApplicable(
      value: String,
      context: String,
      clientIp: String,
      correlationId: String,
      enabledCategories: Set<String>?,
      scanEmbeddedJson: Boolean,
      contentPreview: String?,
      sensitiveBodyFields: Set<String>,
      excludedBodyFields: Set<String>,
      jsonRedactAll: Boolean?,
      sensitiveParams: Set<String> = emptySet(),
  ): ScanHit? {
    if (!scanEmbeddedJson || context == "request_body") {
      return null
    }

    val jsonResult =
        EmbeddedJsonScan.checkEmbeddedJson(
            value,
            context,
            clientIp,
            correlationId,
            enabledCategories,
            excludedBodyFields,
            sensitiveBodyFields,
            redactAll = resolveJsonRedactAll(contentPreview, jsonRedactAll),
            sensitiveParams = sensitiveParams,
        ) ?: return null
    if (!jsonResult.detected) {
      return null
    }
    return jsonResult
  }

  /** Python async `_check_value_enhanced` (detection_scan.py:287). */
  public suspend fun checkValueEnhanced(
      value: String,
      context: String,
      clientIp: String,
      correlationId: String,
      enabledCategories: Set<String>? = null,
      scanEmbeddedJson: Boolean = true,
      contentPreview: String? = null,
      sensitiveBodyFields: Set<String> = emptySet(),
      excludedBodyFields: Set<String> = emptySet(),
      jsonRedactAll: Boolean? = null,
      sensitiveParams: Set<String> = emptySet(),
  ): ScanHit {
    if (DetectionScanBudget.scanBudgetExhausted(clientIp, value)) {
      return ScanHit.MISS
    }

    val jsonHit =
        checkEmbeddedJsonIfApplicable(
            value,
            context,
            clientIp,
            correlationId,
            enabledCategories,
            scanEmbeddedJson,
            contentPreview,
            sensitiveBodyFields,
            excludedBodyFields,
            jsonRedactAll,
            sensitiveParams,
        )
    if (jsonHit != null) {
      return jsonHit
    }

    val result =
        try {
          enhancedDetectOverride?.invoke(value, clientIp, context, correlationId, enabledCategories)
              ?: com.guardcore.engine.suspatterns.SusPatternsManager.shared()
                  .detect(
                      content = value,
                      ipAddress = clientIp,
                      context = context,
                      correlationId = correlationId,
                      enabledCategories = enabledCategories,
                      skipSemantic = DetectionScanBudget.contextHeaderIsSemanticExcluded(context),
                      scanBudget = DetectionScanBudget.scanTimeBudget(),
                  )
        } catch (e: java.util.concurrent.ExecutionException) {
          // Python re-raises RecursionError ahead of the generic handler (detection_scan.py:
          // 337-339): the recursion class escapes `_check_value_enhanced` untouched and every
          // other engine failure falls back to the basic scan. The engine pool delivers worker
          // failures as ExecutionException, so unwrap: a StackOverflowError cause is the
          // recursion class and must escape, any other cause takes the fallback branch.
          val cause = e.cause
          if (cause is StackOverflowError) {
            throw cause
          }
          DetectionScanContext.guardLogger.severe(
              "Enhanced detection failed: ${cause ?: e}, falling back to basic check",
          )
          val (detected, trigger) = fallbackPatternCheck(value, clientIp, context)
          return ScanHit(detected, trigger, emptyList(), null)
        } catch (e: Exception) {
          DetectionScanContext.guardLogger.severe(
              "Enhanced detection failed: $e, falling back to basic check",
          )
          val (detected, trigger) = fallbackPatternCheck(value, clientIp, context)
          return ScanHit(detected, trigger, emptyList(), null)
        }

    if (!result.isThreat) {
      return ScanHit.MISS
    }

    val threats = result.threats.toList()
    if (threats.isNotEmpty()) {
      return ScanHit(true, buildThreatsMessage(threats), threats, null)
    }

    return ScanHit(true, "Threat detected", threats, null)
  }

  /** Python `_log_detected_component` (detection_scan.py:348). */
  public fun logDetectedComponent(
      value: String,
      componentName: String,
      clientIp: String,
      logLevel: String?,
  ) {
    if (logLevel == null) {
      return
    }
    val message = "Potential attack detected from"
    val details =
        if (value.length > 100) {
          "${clientIp}: ${value.substring(0, 100)}..."
        } else {
          "$clientIp: $value"
        }
    val reasonMessage = "Suspicious pattern in $componentName"
    DetectionScanBudget.logAtLevel(logLevel, "$message $details - $reasonMessage")
  }

  /** Python async `_check_request_component` (detection_scan.py:363). */
  public suspend fun checkRequestComponent(
      value: String,
      context: String,
      componentName: String,
      clientIp: String,
      correlationId: String,
      enabledCategories: Set<String>?,
      logLevel: String?,
      scanEmbeddedJson: Boolean = true,
      contentPreview: String? = null,
      sensitiveBodyFields: Set<String> = emptySet(),
      excludedBodyFields: Set<String> = emptySet(),
      jsonRedactAll: Boolean? = null,
      sensitiveParams: Set<String> = emptySet(),
  ): Triple<Boolean, String, List<com.guardcore.engine.suspatterns.Threat>> {
    val hit =
        checkValueEnhanced(
            value,
            context,
            clientIp,
            correlationId,
            enabledCategories,
            scanEmbeddedJson,
            contentPreview = contentPreview,
            sensitiveBodyFields = sensitiveBodyFields,
            excludedBodyFields = excludedBodyFields,
            jsonRedactAll = jsonRedactAll,
            sensitiveParams = sensitiveParams,
        )
    if (hit.detected) {
      val fallback = contentPreview ?: value
      logDetectedComponent(
          hit.logOverride ?: fallback,
          componentName,
          clientIp,
          logLevel,
      )
    }
    return Triple(hit.detected, hit.trigger, hit.threats)
  }

  /** Python async `_scan_component_name` (detection_scan.py:402). */
  public suspend fun scanComponentName(
      name: String,
      context: String,
      label: String,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      contentPreview: String? = null,
  ): Triple<Boolean, String, List<com.guardcore.engine.suspatterns.Threat>> =
      checkRequestComponent(
          name,
          context,
          label,
          clientIp,
          correlationId,
          enabledCategories,
          logLevel,
          scanEmbeddedJson = false,
          contentPreview = contentPreview,
      )

  /** Python `_check_always_scan_header` (detection_scan.py:425). */
  public fun checkAlwaysScanHeader(
      value: String,
  ): Triple<Boolean, String, List<com.guardcore.engine.suspatterns.Threat>> {
    for (pattern in com.guardcore.engine.suspatterns.ALWAYS_SCAN_HEADER_PATTERNS) {
      val match = pattern.search(value, 0, Long.MAX_VALUE) ?: continue
      val threat =
          com.guardcore.engine.suspatterns.Threat(
              type = "regex",
              pattern = pattern.source,
              match = sanitizeForReporting(match.group()),
              position = match.start(),
              executionTime = 0.0,
              category = "cmd_injection",
              weight = 1.0,
          )
      val trigger =
          "Value matched pattern '${DetectionScanRedaction.redactPatternSource(pattern.source)}'"
      return Triple(true, trigger, listOf(threat))
    }
    return Triple(false, "", emptyList())
  }
}
