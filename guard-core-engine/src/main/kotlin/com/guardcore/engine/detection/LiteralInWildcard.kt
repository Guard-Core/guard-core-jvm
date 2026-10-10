package com.guardcore.engine.detection

/**
 * Quantified class that can absorb the mandatory literal immediately following it.
 *
 * Port of guard_core/detection_engine/_redos_literal_in_wildcard.py.
 */
private fun literalRunAt(pattern: String, i: Int): Pair<String, Int> {
  var j = i
  val n = pattern.length
  while (
      j < n &&
          (pattern[j].isAsciiLetterInternal() || pattern[j].isDigitInternal() || pattern[j] == '-')
  ) {
    j++
  }
  return Pair(pattern.substring(i, j), j)
}

private fun wildcardAbsorbsLiteral(pattern: String, i: Int, end: Int): String? {
  val qlen = outerQuantifierLen(pattern, end)
  if (qlen == 0) return null
  val classChars = atomCharSet(pattern.substring(i, end))
  if (classChars.isEmpty()) return null
  val (literal, _) = literalRunAt(pattern, end + qlen)
  if (literal.length < 2 || !classChars.containsAll(literal.toList())) return null
  return "${pattern.substring(i, end + qlen)} then literal '$literal'"
}

/** _detect_ambiguous_literal_boundary: the finding, or null. */
public fun detectAmbiguousLiteralBoundary(pattern: String): String? {
  var i = 0
  val n = pattern.length
  while (i < n) {
    if (pattern[i] != '[') {
      i++
      continue
    }
    val end = skipCharClass(pattern, i)
    val finding = wildcardAbsorbsLiteral(pattern, i, end)
    if (finding != null) return finding
    i = end
  }
  return null
}
