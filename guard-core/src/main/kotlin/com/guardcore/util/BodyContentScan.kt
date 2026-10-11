package com.guardcore.util

import com.guardcore.engine.suspatterns.Threat

/**
 * Port of `guard_core/_utils/body_content_scan.py` (G-7c, body_content_scan.py:56-478): the
 * request-surface scanners (query params, headers, body fields, blob body) that route into
 * [DetectionScan] and the body family.
 */
public object BodyContentScan {
  /** Python `_non_sensitive_display` (body_content_scan.py:56). */
  private fun nonSensitiveDisplay(
      value: String,
      sensitiveParams: Set<String>,
      sensitiveBodyFields: Set<String>,
      sensitiveHeaders: Set<String> = emptySet(),
  ): Pair<String?, Boolean?> {
    val redacted =
        RequestLogging.redactBlobForDisplay(
            value,
            sensitiveParams,
            sensitiveBodyFields,
            sensitiveHeaders,
        )
    if (redacted == value) {
      return null to null
    }
    return redacted to false
  }

  /** Python async `_scan_query_param_value` (body_content_scan.py:70). */
  public suspend fun scanQueryParamValue(
      key: String,
      keyPreview: String,
      value: String,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveParams: Set<String>,
      sensitiveBodyFields: Set<String> = emptySet(),
      excludedBodyFields: Set<String> = emptySet(),
      sensitiveHeaders: Set<String> = emptySet(),
  ): Triple<Boolean, String, List<Threat>> {
    val normalizedKey = key.trim().lowercase()
    val isSensitive = normalizedKey in sensitiveParams || normalizedKey in sensitiveHeaders
    val (contentPreview, jsonRedactAll) =
        if (isSensitive) {
          "[REDACTED]" to null
        } else {
          nonSensitiveDisplay(value, sensitiveParams, sensitiveBodyFields, sensitiveHeaders)
        }
    val (detected, trigger, threats) =
        DetectionScan.checkRequestComponent(
            value,
            "query_param:$keyPreview",
            "query param '$keyPreview'",
            clientIp,
            correlationId,
            enabledCategories,
            if (isSensitive) null else logLevel,
            contentPreview = contentPreview,
            sensitiveBodyFields = sensitiveBodyFields,
            excludedBodyFields = excludedBodyFields,
            jsonRedactAll = jsonRedactAll,
            sensitiveParams = sensitiveParams,
        )
    if (detected && isSensitive) {
      DetectionScan.logDetectedComponent(
          "[REDACTED]",
          "query param '$keyPreview'",
          clientIp,
          logLevel,
      )
    }
    return Triple(detected, trigger, threats)
  }

  /** Python async `_scan_query_params` (body_content_scan.py:115). */
  public suspend fun scanQueryParams(
      request: com.guardcore.protocols.GuardRequest,
      excludedParams: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveParams: Set<String> = emptySet(),
      sensitiveBodyFields: Set<String> = emptySet(),
      excludedBodyFields: Set<String> = emptySet(),
      sensitiveHeaders: Set<String> = emptySet(),
  ): Triple<Boolean, String, List<Threat>> {
    for ((key, value) in request.queryParams) {
      if (key.lowercase() in excludedParams) {
        continue
      }
      val keyPreview =
          RequestLogging.redactBlobForDisplay(
              key,
              sensitiveParams,
              sensitiveBodyFields,
              sensitiveHeaders,
          )
      val (nameDetected, nameTrigger, nameThreats) =
          DetectionScan.scanComponentName(
              key,
              "query_param:$keyPreview",
              "query param name '$keyPreview'",
              enabledCategories,
              clientIp,
              correlationId,
              logLevel,
              contentPreview = keyPreview,
          )
      if (nameDetected) {
        return Triple(true, "Query param name '$keyPreview': $nameTrigger", nameThreats)
      }
      val (detected, trigger, threats) =
          scanQueryParamValue(
              key,
              keyPreview,
              value,
              enabledCategories,
              clientIp,
              correlationId,
              logLevel,
              sensitiveParams,
              sensitiveBodyFields,
              excludedBodyFields,
              sensitiveHeaders,
          )
      if (detected) {
        return Triple(true, "Query param '$keyPreview': $trigger", threats)
      }
    }
    return Triple(false, "", emptyList())
  }

  /** Python async `_scan_excluded_header_component` (body_content_scan.py:163). */
  public suspend fun scanExcludedHeaderComponent(
      key: String,
      value: String,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveParams: Set<String> = emptySet(),
      sensitiveBodyFields: Set<String> = emptySet(),
      excludedBodyFields: Set<String> = emptySet(),
      sensitiveHeaders: Set<String> = emptySet(),
  ): Triple<Boolean, String, List<Threat>>? {
    if (enabledCategories == null || "cmd_injection" in enabledCategories) {
      val (nameDetected, nameTrigger, nameThreats) = DetectionScan.checkAlwaysScanHeader(key)
      if (nameDetected) {
        DetectionScan.logDetectedComponent(key, "header name '$key'", clientIp, logLevel)
        return Triple(true, "Header name '$key': $nameTrigger", nameThreats)
      }
      val (valDetected, valTrigger, valThreats) = DetectionScan.checkAlwaysScanHeader(value)
      if (valDetected) {
        val display =
            RequestLogging.redactBlobForDisplay(
                value,
                sensitiveParams,
                sensitiveBodyFields,
                sensitiveHeaders,
            )
        DetectionScan.logDetectedComponent(display, "header '$key'", clientIp, logLevel)
        return Triple(true, "Header '$key': $valTrigger", valThreats)
      }
    }

    val effectiveCategories =
        DetectionConfig.excludedHeaderEffectiveCategories(key, value, enabledCategories)
    if (effectiveCategories != null && effectiveCategories.isEmpty()) {
      return null
    }
    return scanNormalHeaderComponent(
        key,
        value,
        effectiveCategories,
        clientIp,
        correlationId,
        logLevel,
        sensitiveBodyFields = sensitiveBodyFields,
        excludedBodyFields = excludedBodyFields,
        sensitiveParams = sensitiveParams,
        sensitiveHeaders = sensitiveHeaders,
    )
  }

  /** Python async `_scan_normal_header_component` (body_content_scan.py:207). */
  public suspend fun scanNormalHeaderComponent(
      key: String,
      value: String,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      contentPreview: String? = null,
      sensitiveBodyFields: Set<String> = emptySet(),
      excludedBodyFields: Set<String> = emptySet(),
      sensitiveParams: Set<String> = emptySet(),
      sensitiveHeaders: Set<String> = emptySet(),
  ): Triple<Boolean, String, List<Threat>>? {
    val (nameDetected, nameTrigger, nameThreats) =
        DetectionScan.scanComponentName(
            key,
            "header:$key",
            "header name '$key'",
            enabledCategories,
            clientIp,
            correlationId,
            logLevel,
        )
    if (nameDetected) {
      return Triple(true, "Header name '$key': $nameTrigger", nameThreats)
    }
    var jsonRedactAll: Boolean? = null
    var preview = contentPreview
    if (preview == null) {
      val (redacted, redactAll) =
          nonSensitiveDisplay(value, sensitiveParams, sensitiveBodyFields, sensitiveHeaders)
      preview = redacted
      jsonRedactAll = redactAll
    }
    val (detected, trigger, threats) =
        DetectionScan.checkRequestComponent(
            value,
            "header:$key",
            "header '$key'",
            clientIp,
            correlationId,
            enabledCategories,
            logLevel,
            contentPreview = preview,
            sensitiveBodyFields = sensitiveBodyFields,
            excludedBodyFields = excludedBodyFields,
            jsonRedactAll = jsonRedactAll,
            sensitiveParams = sensitiveParams,
        )
    if (detected) {
      return Triple(true, "Header '$key': $trigger", threats)
    }
    return null
  }

  /** Python async `_scan_sensitive_header` (body_content_scan.py:255). */
  public suspend fun scanSensitiveHeader(
      key: String,
      value: String,
      excludedHeaders: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String> = emptySet(),
      excludedBodyFields: Set<String> = emptySet(),
  ): Triple<Boolean, String, List<Threat>>? {
    val hit =
        if (key.trim().lowercase() in excludedHeaders) {
          scanExcludedHeaderComponent(
              key,
              value,
              enabledCategories,
              clientIp,
              correlationId,
              null,
              sensitiveBodyFields = sensitiveBodyFields,
              excludedBodyFields = excludedBodyFields,
          )
        } else {
          scanNormalHeaderComponent(
              key,
              value,
              enabledCategories,
              clientIp,
              correlationId,
              null,
              contentPreview = "[REDACTED]",
              sensitiveBodyFields = sensitiveBodyFields,
              excludedBodyFields = excludedBodyFields,
          )
        }
    if (hit != null) {
      DetectionScan.logDetectedComponent("[REDACTED]", "header '$key'", clientIp, logLevel)
    }
    return hit
  }

  /** Python async `_scan_headers` (body_content_scan.py:294). */
  public suspend fun scanHeaders(
      request: com.guardcore.protocols.GuardRequest,
      excludedHeaders: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveHeaders: Set<String> = emptySet(),
      sensitiveBodyFields: Set<String> = emptySet(),
      excludedBodyFields: Set<String> = emptySet(),
      sensitiveParams: Set<String> = emptySet(),
  ): Triple<Boolean, String, List<Threat>> {
    for ((key, value) in request.headers) {
      val hit =
          when {
            key.trim().lowercase() in sensitiveHeaders ->
                scanSensitiveHeader(
                    key,
                    value,
                    excludedHeaders,
                    enabledCategories,
                    clientIp,
                    correlationId,
                    logLevel,
                    sensitiveBodyFields,
                    excludedBodyFields,
                )
            key.trim().lowercase() in excludedHeaders ->
                scanExcludedHeaderComponent(
                    key,
                    value,
                    enabledCategories,
                    clientIp,
                    correlationId,
                    logLevel,
                    sensitiveParams,
                    sensitiveBodyFields,
                    excludedBodyFields,
                    sensitiveHeaders,
                )
            else ->
                scanNormalHeaderComponent(
                    key,
                    value,
                    enabledCategories,
                    clientIp,
                    correlationId,
                    logLevel,
                    sensitiveBodyFields = sensitiveBodyFields,
                    excludedBodyFields = excludedBodyFields,
                    sensitiveParams = sensitiveParams,
                    sensitiveHeaders = sensitiveHeaders,
                )
          }
      if (hit != null) {
        return hit
      }
    }
    return Triple(false, "", emptyList())
  }

  /** Python async `_scan_body_field` (body_content_scan.py:350). */
  public suspend fun scanBodyField(
      value: String,
      label: String,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String> = emptySet(),
      display: String? = null,
      context: String = "request_body",
      previewOverride: String? = null,
      sensitiveParams: Set<String> = emptySet(),
  ): BodyJsonScan.ScanHit {
    val isSensitive = label.lowercase() in sensitiveBodyFields
    var computedDisplay: String? = display
    if (previewOverride == null && display == null && !isSensitive) {
      val (redacted, _) = nonSensitiveDisplay(value, sensitiveParams, sensitiveBodyFields)
      computedDisplay = redacted
    }
    val logValue = previewOverride ?: (if (isSensitive) "[REDACTED]" else computedDisplay)
    val (detected, trigger, threats) =
        DetectionScan.checkRequestComponent(
            value,
            context,
            label,
            clientIp,
            correlationId,
            enabledCategories,
            if (logValue != null) null else logLevel,
            contentPreview = logValue,
            sensitiveParams = sensitiveParams,
        )
    if (!detected) {
      return BodyJsonScan.ScanHit.MISS
    }
    if (logValue != null) {
      DetectionScan.logDetectedComponent(logValue, label, clientIp, logLevel)
    }
    return BodyJsonScan.ScanHit(true, "Request body field '$label': $trigger", threats)
  }

  /** Python async `_scan_blob_body` (body_content_scan.py:391). */
  public suspend fun scanBlobBody(
      rawBody: String,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveParams: Set<String> = emptySet(),
      sensitiveBodyFields: Set<String> = emptySet(),
      forceRedacted: Boolean = false,
  ): BodyJsonScan.ScanHit {
    val contentPreview =
        if (forceRedacted) {
          "[REDACTED]"
        } else {
          RequestLogging.redactBlobForDisplay(rawBody, sensitiveParams, sensitiveBodyFields)
        }
    val (detected, trigger, threats) =
        DetectionScan.checkRequestComponent(
            rawBody,
            "request_body",
            "request body",
            clientIp,
            correlationId,
            enabledCategories,
            logLevel,
            contentPreview = contentPreview,
        )
    if (detected) {
      return BodyJsonScan.ScanHit(true, "Request body: $trigger", threats)
    }
    return BodyJsonScan.ScanHit.MISS
  }

  /** Python async `_scan_request_body` (body_content_scan.py:421). */
  public suspend fun scanRequestBody(
      rawBody: String,
      contentType: String,
      excludedBodyFields: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String> = emptySet(),
      sensitiveParams: Set<String> = emptySet(),
  ): BodyJsonScan.ScanHit {
    val lowered = contentType.lowercase()
    if ("application/x-www-form-urlencoded" in lowered) {
      return BodyFormScan.scanFormBody(
          rawBody,
          excludedBodyFields,
          enabledCategories,
          clientIp,
          correlationId,
          logLevel,
          sensitiveBodyFields,
          sensitiveParams,
      )
    }
    if ("multipart/form-data" in lowered) {
      return BodyFormScan.scanMultipartBody(
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
    }

    if ("json" in lowered) {
      val jsonHit =
          BodyJsonScan.scanJsonContent(
              rawBody,
              excludedBodyFields,
              enabledCategories,
              clientIp,
              correlationId,
              logLevel,
              sensitiveBodyFields,
              sensitiveParams,
          )
      if (jsonHit != null) {
        return jsonHit
      }
    }
    return scanBlobBody(
        rawBody,
        enabledCategories,
        clientIp,
        correlationId,
        logLevel,
        sensitiveParams,
        sensitiveBodyFields,
    )
  }
}
