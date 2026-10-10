package com.guardcore.util

/**
 * Port of `guard_core/core/validation/path_matching.py` normalize_url_path (path_matching.py:51)
 * and its helpers. The SecurityConfig exclude_paths validator consumes this at construction and
 * revalidation time (guard_core/_security_config_field_validators.py:45-58).
 */
public object PathMatching {
  private const val MAX_DECODE_ROUNDS = 4

  private val PERCENT_RUN = Regex("(?:%[0-9A-Fa-f]{2})+")

  /** Port of `_decode_percent_once` (path_matching.py:13): strict utf-8. */
  private fun decodePercentOnce(value: String): String? {
    if ('%' !in value) return value
    val out = StringBuilder()
    val run = java.io.ByteArrayOutputStream()
    var i = 0
    val n = value.length
    val strictDecoder =
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)

    fun flushRun() {
      if (run.size() > 0) {
        try {
          out.append(strictDecoder.decode(java.nio.ByteBuffer.wrap(run.toByteArray())))
        } catch (_: java.nio.charset.CharacterCodingException) {
          throw UnicodeDecodeFailure()
        }
        run.reset()
      }
    }
    try {
      while (i < n) {
        val c = value[i]
        if (c == '%' && i + 2 < n && value[i + 1].isHexDigit() && value[i + 2].isHexDigit()) {
          val b =
              ((Character.digit(value[i + 1], 16) shl 4) or Character.digit(value[i + 2], 16))
                  .toByte()
          run.write(b.toInt())
          i += 3
        } else {
          flushRun()
          out.append(c)
          i++
        }
      }
      flushRun()
    } catch (_: UnicodeDecodeFailure) {
      return null
    }
    return out.toString()
  }

  private class UnicodeDecodeFailure : Exception()

  private fun Char.isHexDigit(): Boolean = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

  /** Port of `_decode_percent_recursive` (path_matching.py:20). */
  private fun decodePercentRecursive(rawPath: String): String? {
    var decoded = rawPath
    repeat(MAX_DECODE_ROUNDS) {
      val next = decodePercentOnce(decoded) ?: return null
      decoded = next
      return@repeat
    }
    if (PERCENT_RUN.containsMatchIn(decoded)) return null
    return decoded
  }

  /** Port of `_fold_dot_segment_params` (path_matching.py:32). */
  private fun foldDotSegmentParams(segment: String): String {
    val base = segment.substringBefore(";", segment)
    return if (base == "." || base == "..") base else segment
  }

  /** Port of `_collapse_dot_segments` (path_matching.py:37). */
  private fun collapseDotSegments(decoded: String): String {
    val segments = ArrayList<String>()
    for (rawSegment in decoded.replace("\\", "/").split("/")) {
      val segment = foldDotSegmentParams(rawSegment)
      if (segment.isEmpty() || segment == ".") continue
      if (segment == "..") {
        if (segments.isNotEmpty()) segments.removeAt(segments.size - 1)
        continue
      }
      segments.add(segment)
    }
    return "/" + segments.joinToString("/")
  }

  /** Port of `normalize_url_path` (path_matching.py:51). */
  public fun normalizeUrlPath(rawPath: String): String? {
    val decoded = decodePercentRecursive(rawPath) ?: return null
    return collapseDotSegments(decoded)
  }

  /** Port of `_is_subtree_or_equal` (path_matching.py:58). */
  public fun isSubtreeOrEqual(path: String, excluded: String): Boolean =
      if (excluded == "/") true else path == excluded || path.startsWith(excluded + "/")

  /** Port of `normalize_exclude_paths` (path_matching.py:64). */
  public fun normalizeExcludePaths(excludePaths: List<String>): List<String> =
      excludePaths.mapNotNull {
        normalizeUrlPath(it)
      }

  /** Port of `path_matches_exclusions` (path_matching.py:69). */
  public fun pathMatchesExclusions(
      normalizedPath: String,
      normalizedExclusions: List<String>,
  ): Boolean = normalizedExclusions.any { isSubtreeOrEqual(normalizedPath, it) }

  /** Port of `path_is_excluded` (path_matching.py:78). */
  public fun pathIsExcluded(urlPath: String, excludePaths: List<String>): Boolean {
    val normalizedPath = normalizeUrlPath(urlPath) ?: return false
    return pathMatchesExclusions(normalizedPath, normalizeExcludePaths(excludePaths))
  }
}
