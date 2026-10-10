package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyRePattern

/**
 * Binary-prefix density and binary island extraction for the noise gates.
 *
 * Port of guard_core/detection_engine/binary_prefix.py and binary_islands.py.
 */
public object BinaryPrefix {
  // Char-class body from python: control chars, DEL, latin-1 artifacts, U+0180-U+024F, U+FFFD,
  // and the surrogateescape range (surrogates emitted as raw chars: java classes accept them
  // as code units, and escape sequences for lone surrogates are spotty).
  private val SURROGATE_RANGE_PREFIX: Char = 0xDC80.toChar()
  private val SURROGATE_RANGE_SUFFIX: Char = 0xDCFF.toChar()
  private val SURROGATE_RANGE: String = "$SURROGATE_RANGE_PREFIX-$SURROGATE_RANGE_SUFFIX"

  private val ARTIFACT_CLASS: String =
      "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x80-\\xa2\\xa4\\xa6-\\xa9\\xab-\\xaf" +
          "\\xb4\\xb6-\\xb8\\xbb-\\xbf\\u0180-\\u024f\\ufffd" +
          SURROGATE_RANGE +
          "]"

  private val BINARY_ARTIFACT_RE: PyRePattern = PyRe.compile(ARTIFACT_CLASS, 0)

  private const val BINARY_DENSITY_RADIUS = 64
  private const val BINARY_DENSITY_LIMIT = 4

  /** build_binary_prefix: cumulative artifact count at every char offset (+1 slots). */
  public fun buildBinaryPrefix(content: String): IntArray {
    val prefix = IntArray(content.length + 1)
    var count = 0
    var filled = 0
    for (match in BINARY_ARTIFACT_RE.finditer(content, Long.MAX_VALUE)) {
      count += 1
      val boundary = match.charEnd()
      for (i in filled + 1 until boundary) {
        prefix[i] = count - 1
      }
      if (boundary <= content.length) prefix[boundary] = count
      filled = boundary
    }
    for (i in filled..content.length) {
      prefix[i] = count
    }
    return prefix
  }

  /** match_is_binary_dense: >= LIMIT artifacts within the radius window. */
  public fun matchIsBinaryDense(binaryPrefix: IntArray?, match: PyReMatch): Boolean {
    if (binaryPrefix == null) return false
    val high = minOf(match.charEnd() + BINARY_DENSITY_RADIUS, binaryPrefix.size - 1)
    val low = maxOf(match.charStart() - BINARY_DENSITY_RADIUS, 0)
    return binaryPrefix[high] - binaryPrefix[low] >= BINARY_DENSITY_LIMIT
  }
}

public object BinaryIslands {
  // ISLAND_RUN_RE from python: printable runs (tab, LF, CR, space, U+00A1-U+D7FF,
  // U+E000-U+FFFC, U+FFFE-U+10FFFF).
  private val ISLAND_RUN_RE: PyRePattern =
      PyRe.compile(
          "[\\t\\n\\r\\x20-\\x7e\\u00a1-\\ud7ff\\ue000-\\ufffc\\ufffe-\\uffff]+",
          0,
      )

  private const val BINARY_LIKE_ARTIFACT_RATIO = 0.2

  private val artifactLike: PyRePattern =
      PyRe.compile(
          "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x80-\\xa2\\xa4\\xa6-\\xa9\\xab-\\xaf" +
              "\\xb4\\xb6-\\xb8\\xbb-\\xbf\\u0180-\\u024f\\ufffd\\udc80-\\udcff]",
          0,
      )

  /** value_is_binary_like. */
  public fun valueIsBinaryLike(content: String): Boolean {
    if (content.isEmpty()) return false
    var artifactCount = 0
    for (m in artifactLike.finditer(content, Long.MAX_VALUE)) artifactCount++
    return artifactCount.toDouble() / content.length >= BINARY_LIKE_ARTIFACT_RATIO
  }

  /** extract_binary_islands. */
  public fun extractBinaryIslands(content: String, minRunLength: Int): List<String> {
    if (minRunLength <= 1) return listOf(content)
    return ISLAND_RUN_RE.finditer(content, Long.MAX_VALUE)
        .map { it.group() }
        .filter { it.length >= minRunLength }
  }
}
