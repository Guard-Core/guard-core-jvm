package com.guardcore.handlers

import com.guardcore.util.RequestLogging

/**
 * Port of the `_redact_pattern_source` slice of `guard_core/_utils/detection_scan.py:154-178` that
 * the W3 handler surface uses for log/event redaction.
 *
 * The sensitive-name unions come from the suspatterns handler state
 * (`sus_patterns_handler._sensitive_params_union` et al, _suspatterns_state.py); those land with
 * the W4 scan callers (KNOWN_GAPS G-7b). Until then the unions default to empty, which yields the
 * reference behavior under default config (empty unions) and is registered live in W4.
 */
public object DetectionScanRedaction {
  @Volatile public var sensitiveParamsUnion: Set<String> = linkedSetOf()

  @Volatile public var sensitiveBodyFieldsUnion: Set<String> = linkedSetOf()

  @Volatile public var sensitiveHeadersUnion: Set<String> = linkedSetOf()

  /** Python `_PATTERN_SOURCE_NON_TOKEN_RE` (detection_scan.py:137). */
  private val PATTERN_SOURCE_NON_TOKEN_RE = Regex("[^a-z0-9_-]+")

  /** Python `_PATTERN_SOURCE_ESCAPE_RE` (detection_scan.py:138). */
  private val PATTERN_SOURCE_ESCAPE_RE =
      Regex("\\\\(?:[xX]([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|([0-7]{1,3}))")

  private fun decodePatternSourceEscape(match: MatchResult): String {
    val hexBody =
        match.groupValues[1].ifEmpty {
          match.groupValues[2].ifEmpty {
            match.groupValues[3].ifEmpty { null }
          }
        }
    val code =
        if (hexBody != null) {
          hexBody.toInt(16)
        } else {
          match.groupValues[4].toInt(8)
        }
    return if (code <= 0x10FFFF) code.toChar().toString() else match.groupValues[0]
  }

  /** Port of `_pattern_source_names_a_sensitive_field` (detection_scan.py:148). */
  public fun patternSourceNamesASensitiveField(
      patternSource: String,
      sensitiveNames: Set<String>,
  ): Boolean {
    val decoded = PATTERN_SOURCE_ESCAPE_RE.replace(patternSource) { decodePatternSourceEscape(it) }
    val normalized = PATTERN_SOURCE_NON_TOKEN_RE.replace(decoded.lowercase(), "")
    return sensitiveNames.any { it in normalized }
  }

  /** Port of `_redact_pattern_source` (detection_scan.py:154). */
  public fun redactPatternSource(patternSource: String): String {
    val bodyFields = RequestLogging.mergeSensitiveLogBodyFields(sensitiveBodyFieldsUnion)
    val sensitiveNames =
        RequestLogging.mergedSensitiveNames(
            sensitiveParamsUnion,
            bodyFields,
            sensitiveHeadersUnion,
        )
    if (patternSourceNamesASensitiveField(patternSource, sensitiveNames)) {
      return "[REDACTED]"
    }
    return RequestLogging.redactBlobForDisplay(
        patternSource,
        sensitiveParamsUnion,
        sensitiveBodyFieldsUnion,
        sensitiveHeadersUnion,
    )
  }
}
