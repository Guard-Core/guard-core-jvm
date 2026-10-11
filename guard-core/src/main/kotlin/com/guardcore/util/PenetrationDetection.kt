package com.guardcore.util

import com.guardcore.DetectionResult
import com.guardcore.config.SecurityConfig
import com.guardcore.decorators.RouteConfig
import com.guardcore.engine.suspatterns.DetectionConfigView
import com.guardcore.engine.suspatterns.SusPatternsManager
import com.guardcore.handlers.DetectionScanRedaction
import com.guardcore.protocols.GuardRequest

/**
 * Port of `guard_core/_utils/penetration_detection.py` (G-7d, penetration_detection.py:46-224): the
 * auto-configure penetration entry driving the request surface and body scans.
 *
 * G-10 closure: the DetectionScanRedaction sensitive-name unions register here from the live config
 * at configure time (python: sus_patterns_handler.configure, _suspatterns_enhanced.py:29-38).
 */
public object PenetrationDetection {
  /** Python `_ensure_detection_singleton_configured` (penetration_detection.py:149). */
  public fun configureDetection(config: SecurityConfig?) {
    if (config == null) {
      return
    }
    // G-10: the unions accumulate across configure() calls exactly like the reference
    // (`cls._sensitive_params_union = self._sensitive_params_union | config.log_sensitive_params`).
    val params = DetectionScanRedaction.sensitiveParamsUnion + config.logSensitiveParams
    val bodyFields = DetectionScanRedaction.sensitiveBodyFieldsUnion + config.logSensitiveBodyFields
    val headers = DetectionScanRedaction.sensitiveHeadersUnion + config.logSensitiveHeaders
    DetectionScanRedaction.sensitiveParamsUnion = params
    DetectionScanRedaction.sensitiveBodyFieldsUnion = bodyFields
    DetectionScanRedaction.sensitiveHeadersUnion = headers

    val manager = SusPatternsManager.shared()
    if (manager.config == null || lastConfigured !== config) {
      manager.configure(asDetectionConfigView(config))
      lastConfigured = config
    }
  }

  /** Python `sus_patterns_handler._config` identity tracking (penetration_detection.py:154-160). */
  private var lastConfigured: SecurityConfig? = null

  /** SecurityConfig through the engine's detection-config view (the W2 runner mapping). */
  public fun asDetectionConfigView(config: SecurityConfig): DetectionConfigView =
      object : DetectionConfigView {
        override val detectionCompilerTimeout: Double = config.detectionCompilerTimeout
        override val detectionMaxTrackedPatterns: Int = config.detectionMaxTrackedPatterns
        override val detectionMaxContentLength: Int = config.detectionMaxContentLength
        override val detectionPreserveAttackPatterns: Boolean =
            config.detectionPreserveAttackPatterns
        override val detectionAnomalyThreshold: Double = config.detectionAnomalyThreshold
        override val detectionSlowPatternThreshold: Double = config.detectionSlowPatternThreshold
        override val detectionMonitorHistorySize: Int = config.detectionMonitorHistorySize
        override val detectionAnomalyEmissionCooldown: Double =
            config.detectionAnomalyEmissionCooldown
        override val detectionMinSamplesForAnomaly: Int = config.detectionMinSamplesForAnomaly
        override val detectionSemanticThreshold: Double = config.detectionSemanticThreshold
        override val detectionThreatScoreThreshold: Double = config.detectionThreatScoreThreshold
        override val detectionMaxBodyInspectBytes: Int = config.detectionMaxBodyInspectBytes
        override val detectionPatternValidationCachePath: String? =
            config.detectionPatternValidationCachePath
      }

  /** Python async `_scan_request_surface` (penetration_detection.py:46). */
  private suspend fun scanRequestSurface(
      request: GuardRequest,
      excludedParams: Set<String>,
      excludedHeaders: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveHeaders: Set<String>,
      sensitiveParams: Set<String>,
      sensitiveBodyFields: Set<String> = emptySet(),
      excludedBodyFields: Set<String> = emptySet(),
  ): DetectionResult? {
    val (paramsDetected, paramsTrigger, paramsThreats) =
        BodyContentScan.scanQueryParams(
            request,
            excludedParams,
            enabledCategories,
            clientIp,
            correlationId,
            logLevel,
            sensitiveParams,
            sensitiveBodyFields,
            excludedBodyFields,
            sensitiveHeaders,
        )
    if (paramsDetected) {
      return DetectionResultBuilders.buildDetectionHit(paramsTrigger, paramsThreats)
    }

    val redactedUrlPath =
        RequestLogging.redactUrlForDisplay(
            request.urlPath,
            sensitiveParams,
            sensitiveBodyFields,
            sensitiveHeaders,
        )
    val (pathDetected, pathTrigger, pathThreats) =
        DetectionScan.checkRequestComponent(
            request.urlPath,
            "url_path",
            "URL path",
            clientIp,
            correlationId,
            enabledCategories,
            logLevel,
            contentPreview = redactedUrlPath,
            sensitiveBodyFields = sensitiveBodyFields,
            excludedBodyFields = excludedBodyFields,
            jsonRedactAll = false,
        )
    if (pathDetected) {
      return DetectionResultBuilders.buildDetectionHit("URL path: $pathTrigger", pathThreats)
    }

    val (headersDetected, headersTrigger, headersThreats) =
        BodyContentScan.scanHeaders(
            request,
            excludedHeaders,
            enabledCategories,
            clientIp,
            correlationId,
            logLevel,
            sensitiveHeaders,
            sensitiveBodyFields,
            excludedBodyFields,
            sensitiveParams,
        )
    if (headersDetected) {
      return DetectionResultBuilders.buildDetectionHit(headersTrigger, headersThreats)
    }

    return null
  }

  /** Python async `_scan_body_surface` (penetration_detection.py:111). */
  private suspend fun scanBodySurface(
      request: GuardRequest,
      config: SecurityConfig?,
      routeConfig: RouteConfig?,
      excludedBodyFields: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String>,
      sensitiveParams: Set<String> = emptySet(),
  ): DetectionResult {
    if (!DetectionConfig.resolveScanBody(config, routeConfig)) {
      return DetectionResultBuilders.buildDetectionMiss()
    }

    val bodyBytes =
        BodyReader.readCappedBody(request, config, clientIp)
            ?: return DetectionResultBuilders.buildDetectionMiss()

    val rawBody = decodeSurrogateEscape(bodyBytes)

    val contentType = request.headers["content-type"] ?: ""
    val (detected, trigger, threats) =
        BodyContentScan.scanRequestBody(
            rawBody,
            contentType,
            excludedBodyFields,
            enabledCategories,
            clientIp,
            correlationId,
            logLevel,
            sensitiveBodyFields,
            sensitiveParams,
        )
    if (detected) {
      return DetectionResultBuilders.buildDetectionHit(trigger, threats)
    }
    return DetectionResultBuilders.buildDetectionMiss()
  }

  /**
   * Port of `raw_body = body_bytes.decode("utf-8", errors="surrogateescape")`
   * (penetration_detection.py:130): undecodable bytes become lone surrogates U+DC80..U+DCFF.
   */
  public fun decodeSurrogateEscape(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size + 8)
    var i = 0
    while (i < bytes.size) {
      val b = bytes[i].toInt() and 0xFF
      if (b < 0x80) {
        sb.append(b.toChar())
        i += 1
        continue
      }
      val length =
          when {
            b and 0xE0 == 0xC0 -> 2
            b and 0xF0 == 0xE0 -> 3
            b and 0xF8 == 0xF0 -> 4
            else -> 1
          }
      var isValid = i + length <= bytes.size
      if (isValid) {
        when (length) {
          2 -> isValid = b and 0x1E != 0
          3 ->
              isValid =
                  !(b == 0xE0 && bytes[i + 1].toInt() and 0xFF < 0xA0) &&
                      !(b == 0xED && bytes[i + 1].toInt() and 0xFF > 0x9F)
          4 -> isValid = b and 0x07 != 0 && b < 0xF5
        }
        if (isValid) {
          for (j in 1 until length) {
            if (bytes[i + j].toInt() and 0xC0 != 0x80) {
              isValid = false
              break
            }
          }
        }
      }
      if (isValid) {
        when (length) {
          2 -> sb.append((((b and 0x1F) shl 6) or (bytes[i + 1].toInt() and 0x3F)).toChar())
          3 -> {
            val cp =
                ((b and 0x0F) shl 12) or
                    ((bytes[i + 1].toInt() and 0x3F) shl 6) or
                    (bytes[i + 2].toInt() and 0x3F)
            sb.append(cp.toChar())
          }
          4 -> {
            val cp =
                ((b and 0x07) shl 18) or
                    ((bytes[i + 1].toInt() and 0x3F) shl 12) or
                    ((bytes[i + 2].toInt() and 0x3F) shl 6) or
                    (bytes[i + 3].toInt() and 0x3F)
            val v = cp - 0x10000
            sb.append((0xD800 or (v shr 10)).toChar())
            sb.append((0xDC00 or (v and 0x3FF)).toChar())
          }
        }
        i += length
      } else {
        sb.append((0xDC00 + b - 0x80).toChar())
        i += 1
      }
    }
    return sb.toString()
  }

  /** Python async `detect_penetration_attempt` (penetration_detection.py:162). */
  public suspend fun detectPenetrationAttempt(
      request: GuardRequest,
      config: SecurityConfig? = null,
      routeConfig: RouteConfig? = null,
  ): DetectionResult {
    configureDetection(config)

    val clientIp =
        if (config != null) {
          IpExtraction.extractClientIp(request, config)
        } else {
          val host = request.clientHost
          if (host != null) {
            IpExtraction.canonicalizeIp(host)
          } else {
            IpExtraction.UNKNOWN_CLIENT_IDENTITY
          }
        }
    val correlationId = java.util.UUID.randomUUID().toString()

    val excludedParams = DetectionConfig.resolveExcludedParams(config, routeConfig)
    val excludedBodyFields = DetectionConfig.resolveExcludedBodyFields(config, routeConfig)
    val enabledCategories = DetectionConfig.resolveEnabledCategories(config, routeConfig)
    val excludedHeaders = DetectionConfig.resolveExcludedHeaders(config, routeConfig)
    val logLevel = DetectionConfig.resolveLogLevel(config)
    val sensitiveHeaders = DetectionConfig.resolveSensitiveLogHeaders(config)
    val sensitiveParams = DetectionConfig.resolveSensitiveLogParams(config)
    val sensitiveBodyFields = DetectionConfig.resolveSensitiveLogBodyFields(config)
    val maxScanValues = DetectionConfig.resolveMaxScanValues(config)
    val maxJsonDepth = DetectionConfig.resolveMaxJsonDepth(config)
    val maxScanChars = DetectionConfig.resolveMaxScanChars(config)
    val binaryMinRun = DetectionConfig.resolveBinaryMinRunLength(config)

    return DetectionScanBudget.withScanBudget(
        maxValues = maxScanValues,
        maxJsonDepth = maxJsonDepth,
        maxScanChars = maxScanChars,
        binaryMinRunLength = binaryMinRun,
    ) {
      val surfaceHit =
          scanRequestSurface(
              request,
              excludedParams,
              excludedHeaders,
              enabledCategories,
              clientIp,
              correlationId,
              logLevel,
              sensitiveHeaders,
              sensitiveParams,
              sensitiveBodyFields,
              excludedBodyFields,
          )
      if (surfaceHit != null) {
        return@withScanBudget surfaceHit
      }

      scanBodySurface(
          request,
          config,
          routeConfig,
          excludedBodyFields,
          enabledCategories,
          clientIp,
          correlationId,
          logLevel,
          sensitiveBodyFields,
          sensitiveParams,
      )
    }
  }
}
