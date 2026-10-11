package com.guardcore.util

import com.guardcore.engine.suspatterns.Threat
import com.guardcore.engine.suspatterns.sanitizeForReporting
import com.guardcore.util.py.PyJson

/**
 * Port of `guard_core/_utils/body_json_scan.py` (G-7c, body_json_scan.py:15-291): the JSON body
 * scanner with the mongo operator key gate, the depth-capped subtree scan and the iterative
 * dict/list walk.
 */
public object BodyJsonScan {
  /** Python `_MONGO_OPERATOR_KEY_RE` (body_json_scan.py:15). */
  private val MONGO_OPERATOR_KEY_RE: kotlin.text.Regex =
      kotlin.text.Regex(
          "^\\$(?:ne|gt|gte|lt|lte|eq|in|nin|nor|and|or|not|all|size|exists|type|" +
              "mod|options|where|regex|expr|function|elemMatch)$",
      )

  /** The triple the python scan helpers return: (detected, trigger, threats). */
  public data class ScanHit(
      val detected: Boolean,
      val trigger: String,
      val threats: List<Threat>,
  ) {
    public companion object {
      public val MISS: ScanHit = ScanHit(false, "", emptyList())
    }
  }

  /** Python `_mongo_operator_key_hit` (body_json_scan.py:21). */
  private fun mongoOperatorKeyHit(keyStr: String): ScanHit {
    val threat =
        Threat(
            type = "regex",
            pattern = MONGO_OPERATOR_KEY_RE.pattern,
            match = sanitizeForReporting(keyStr),
            position = 0,
            executionTime = 0.0,
            category = "nosql",
            weight = 1.0,
        )
    return ScanHit(
        true,
        "JSON operator key '$keyStr': matched pattern '${MONGO_OPERATOR_KEY_RE.pattern}'",
        listOf(threat),
    )
  }

  /** Python async `_scan_json_dict_entry_key` (body_json_scan.py:37). */
  public suspend fun scanJsonDictEntryKey(
      key: Any?,
      excludedBodyFields: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      context: String = "request_body",
      redactKeys: Boolean = false,
  ): ScanHit? {
    val keyStr = key.toString()
    if (keyStr.lowercase() in excludedBodyFields) {
      return null
    }
    if (MONGO_OPERATOR_KEY_RE.containsMatchIn(keyStr)) {
      return mongoOperatorKeyHit(keyStr)
    }
    val keyDisplay = if (redactKeys) "[REDACTED]" else keyStr
    val nameHit =
        DetectionScan.scanComponentName(
            keyStr,
            "$context:$keyDisplay",
            "JSON key '$keyDisplay'",
            enabledCategories,
            clientIp,
            correlationId,
            logLevel,
            contentPreview = if (redactKeys) "[REDACTED]" else null,
        )
    if (nameHit.first) {
      return ScanHit(true, "JSON key '$keyDisplay': ${nameHit.second}", nameHit.third)
    }
    return ScanHit.MISS
  }

  /** Python async `_scan_capped_json_subtree` (body_json_scan.py:68). */
  public suspend fun scanCappedJsonSubtree(
      value: Any?,
      keyLabel: String,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String> = emptySet(),
      context: String = "request_body",
      previewOverride: String? = null,
      sensitiveParams: Set<String> = emptySet(),
  ): ScanHit {
    DetectionScanBudget.warnJsonDepthCapReachedOnce(clientIp)
    val serialized = PyJson.dumps(value)
    val redacted =
        LoggingUtils.redactSensitiveJson(
            value,
            sensitiveParams,
            sensitiveBodyFields,
            DetectionScanBudget.jsonDepthCapValue(),
        )
    val display = PyJson.dumps(redacted)
    return BodyContentScan.scanBodyField(
        serialized,
        keyLabel,
        enabledCategories,
        clientIp,
        correlationId,
        logLevel,
        sensitiveBodyFields,
        display = display,
        context = context,
        previewOverride = previewOverride,
        sensitiveParams = sensitiveParams,
    )
  }

  private sealed class Frame {
    data class Entry(val key: Any?, val item: Any?, val depth: Int, val redact: Boolean) : Frame()

    data class Value(val value: Any?, val label: String, val depth: Int, val redact: Boolean) :
        Frame()
  }

  /** Python async `_scan_json_container_frame` (body_json_scan.py:102). */
  private suspend fun scanJsonContainerFrame(
      current: Any?,
      label: String,
      depth: Int,
      redact: Boolean,
      maxDepth: Int,
      stack: ArrayDeque<Frame>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String>,
      context: String,
      previewOverride: String?,
      sensitiveParams: Set<String>,
  ): ScanHit? {
    if (depth >= maxDepth) {
      val cappedPreview = previewOverride ?: (if (redact) "[REDACTED]" else null)
      val hit =
          scanCappedJsonSubtree(
              current,
              label,
              enabledCategories,
              clientIp,
              correlationId,
              logLevel,
              sensitiveBodyFields,
              context,
              cappedPreview,
              sensitiveParams,
          )
      return if (hit.detected) hit else null
    }
    if (current is Map<*, *>) {
      for ((key, item) in current.entries.toList().asReversed()) {
        stack.addLast(Frame.Entry(key, item, depth, redact))
      }
      return null
    }
    for (item in (current as List<*>).asReversed()) {
      stack.addLast(Frame.Value(item, label, depth + 1, redact))
    }
    return null
  }

  /** Python async `_scan_json_entry_frame` (body_json_scan.py:146). */
  private suspend fun scanJsonEntryFrame(
      key: Any?,
      item: Any?,
      depth: Int,
      redact: Boolean,
      stack: ArrayDeque<Frame>,
      excludedBodyFields: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String>,
      context: String,
      redactKeys: Boolean,
  ): ScanHit? {
    val keyResult =
        scanJsonDictEntryKey(
            key,
            excludedBodyFields,
            enabledCategories,
            clientIp,
            correlationId,
            logLevel,
            context,
            redactKeys,
        ) ?: return null
    if (keyResult.detected) {
      return keyResult
    }
    val keyStr = key.toString()
    val ownRedact = redact || keyStr.lowercase() in sensitiveBodyFields
    stack.addLast(Frame.Value(item, keyStr, depth + 1, ownRedact))
    return null
  }

  /** Python async `_scan_json_value` (body_json_scan.py:181). */
  public suspend fun scanJsonValue(
      value: Any?,
      keyLabel: String,
      excludedBodyFields: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String> = emptySet(),
      context: String = "request_body",
      previewOverride: String? = null,
      redactKeys: Boolean = false,
      sensitiveParams: Set<String> = emptySet(),
  ): ScanHit {
    val maxDepth = DetectionScanBudget.jsonDepthCapValue()
    val stack = ArrayDeque<Frame>()
    stack.addLast(Frame.Value(value, keyLabel, 1, false))
    while (stack.isNotEmpty()) {
      val frame = stack.removeLast()
      if (frame is Frame.Entry) {
        val hit =
            scanJsonEntryFrame(
                frame.key,
                frame.item,
                frame.depth,
                frame.redact,
                stack,
                excludedBodyFields,
                enabledCategories,
                clientIp,
                correlationId,
                logLevel,
                sensitiveBodyFields,
                context,
                redactKeys,
            )
        if (hit != null) {
          return hit
        }
        continue
      }
      frame as Frame.Value
      val current = frame.value
      val label = frame.label
      if (current is Map<*, *> || current is List<*>) {
        val hit =
            scanJsonContainerFrame(
                current,
                label,
                frame.depth,
                frame.redact,
                maxDepth,
                stack,
                enabledCategories,
                clientIp,
                correlationId,
                logLevel,
                sensitiveBodyFields,
                context,
                previewOverride,
                sensitiveParams,
            )
        if (hit != null) {
          return hit
        }
        continue
      }
      val leafPreview = previewOverride ?: (if (frame.redact) "[REDACTED]" else null)
      val scalarHit =
          BodyContentScan.scanBodyField(
              current.toString(),
              label,
              enabledCategories,
              clientIp,
              correlationId,
              logLevel,
              sensitiveBodyFields,
              context = context,
              previewOverride = leafPreview,
              sensitiveParams = sensitiveParams,
          )
      if (scalarHit.detected) {
        return scalarHit
      }
    }
    return ScanHit.MISS
  }

  /** Python async `_scan_json_content` (body_json_scan.py:265). */
  public suspend fun scanJsonContent(
      rawBody: String,
      excludedBodyFields: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String> = emptySet(),
      sensitiveParams: Set<String> = emptySet(),
  ): ScanHit? {
    val parsedBody =
        try {
          PyJson.loads(rawBody)
        } catch (e: Exception) {
          null
        }
    if (parsedBody is Map<*, *> || parsedBody is List<*>) {
      return scanJsonValue(
          parsedBody,
          "",
          excludedBodyFields,
          enabledCategories,
          clientIp,
          correlationId,
          logLevel,
          sensitiveBodyFields,
          sensitiveParams = sensitiveParams,
      )
    }
    return null
  }
}
