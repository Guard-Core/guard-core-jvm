package com.guardcore.util

import com.guardcore.engine.suspatterns.EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX
import com.guardcore.util.py.PyJson

/**
 * Port of `guard_core/_utils/embedded_json_scan.py` (G-7c, embedded_json_scan.py:11-77): the
 * embedded-JSON detection inside non-body values.
 */
public object EmbeddedJsonScan {
  /** Python `_parse_embedded_json` (embedded_json_scan.py:12). */
  private fun parseEmbeddedJson(value: String, clientIp: String): Any? {
    val data =
        try {
          PyJson.loads(value)
        } catch (e: Exception) {
          return null
        }
    if (data !is Map<*, *> && data !is List<*>) {
      return null
    }
    return data
  }

  /** Python `_embedded_json_display` (embedded_json_scan.py:25). */
  private fun embeddedJsonDisplay(
      data: Any?,
      sensitiveBodyFields: Set<String>,
      redactAll: Boolean,
      sensitiveParams: Set<String>,
  ): String {
    if (redactAll) {
      return "[REDACTED]"
    }
    return PyJson.dumps(
        LoggingUtils.redactSensitiveJson(
            data,
            sensitiveParams,
            sensitiveBodyFields,
            DetectionScanBudget.jsonDepthCapValue(),
        ),
    )
  }

  /** The quadruple shape of python `_check_embedded_json` folded into DetectionScan.ScanHit. */
  public suspend fun checkEmbeddedJson(
      value: String,
      context: String,
      clientIp: String,
      correlationId: String,
      enabledCategories: Set<String>?,
      excludedBodyFields: Set<String>,
      sensitiveBodyFields: Set<String>,
      redactAll: Boolean,
      sensitiveParams: Set<String> = emptySet(),
  ): DetectionScan.ScanHit? {
    val data = parseEmbeddedJson(value, clientIp) ?: return null

    val (detected, trigger, threats) =
        BodyJsonScan.scanJsonValue(
            data,
            "",
            excludedBodyFields,
            enabledCategories,
            clientIp,
            correlationId,
            null,
            sensitiveBodyFields,
            context = "$context$EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX",
            previewOverride = if (redactAll) "[REDACTED]" else null,
            redactKeys = redactAll,
            sensitiveParams = sensitiveParams,
        )
    if (!detected) {
      return DetectionScan.ScanHit.MISS
    }

    val display = embeddedJsonDisplay(data, sensitiveBodyFields, redactAll, sensitiveParams)
    return DetectionScan.ScanHit(true, trigger, threats, display)
  }
}
