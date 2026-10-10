package com.guardcore.engine.suspatterns

/**
 * Threat value type: the dict shape the reference builds (type, pattern, match, position,
 * execution_time, category, weight; semantic threats carry attack_type / probability / analysis
 * instead).
 *
 * Port of the threat dicts in _suspatterns_regex.py and _suspatterns_enhanced.py; execution time is
 * carried but dropped by the corpus comparison contract.
 */
public class Threat(
    public val type: String,
    public val pattern: String,
    public val match: String,
    public val position: Int,
    public val executionTime: Double,
    public val category: String,
    public val weight: Double,
    public val attackType: String? = null,
    public val probability: Double? = null,
    public val threatScore: Double? = null,
    public val analysis: Map<String, Any>? = null,
) {
  public fun toMap(): Map<String, Any?> =
      if (type == "semantic") {
        mutableMapOf<String, Any?>(
                "type" to type,
                "attack_type" to attackType,
            )
            .also {
              if (probability != null) it["probability"] = probability
              if (threatScore != null) it["threat_score"] = threatScore
              if (analysis != null) it["analysis"] = analysis
            }
      } else {
        mutableMapOf<String, Any?>(
            "type" to type,
            "pattern" to pattern,
            "match" to match,
            "position" to position,
            "execution_time" to executionTime,
            "category" to category,
            "weight" to weight,
        )
      }
}

/** Result of detect(): the observable verdict surface. */
public class DetectResult(
    public val isThreat: Boolean,
    public val threatScore: Double,
    public val threats: List<Threat>,
    public val context: String,
    public val originalLength: Int,
    public val processedLength: Int,
    public val executionTime: Double,
    public val detectionMethod: String,
    public val timeouts: List<String>,
    public val correlationId: String?,
)

/** sanitize_for_reporting: surrogateescape bytes become backslash escapes. */
public fun sanitizeForReporting(value: String): String {
  val out = StringBuilder(value.length + 8)
  for (ch in value) {
    val cp = ch.code
    if (cp in 0xDC80..0xDCFF) {
      // python surrogateescape: encode("utf-8", "surrogateescape") recovers the raw byte,
      // and decode with "backslashreplace" renders it as \xNN.
      out.append("\\x")
      out.append("%02x".format(cp - 0xDC80 + 0x80))
    } else if (cp >= 0xD800 && cp <= 0xDFFF) {
      out.append("\\x")
      out.append("%02x".format(cp and 0xFF))
    } else {
      out.append(ch)
    }
  }
  return out.toString()
}
