package com.guardcore.engine.detection

/**
 * Broad scan whose terminator cannot be reached by repeating its own prefix.
 *
 * Port of guard_core/detection_engine/_redos_unreachable_terminator.py.
 */
private val PREFIX_RESET_CHARS = "()|^$".toSet()
private val TERMINATOR_NON_LITERAL_LEADERS = "()|^$.*+?{".toSet()

private fun skipSymbolQuantifierAt(text: String, k: Int): Int {
  var end = k + 1
  if (end < text.length && text[end] == '?') end++
  return end - k
}

private fun skipBraceQuantifierAt(text: String, k: Int): Int {
  val endBrace = text.indexOf('}', k)
  if (endBrace == -1) return 0
  val parts = text.substring(k + 1, endBrace).split(",")
  if (
      !parts.all { it.isEmpty() || it.all { c -> c.isDigitInternal() } } ||
          parts.all { it.isEmpty() }
  ) {
    return 0
  }
  var end = endBrace + 1
  if (end < text.length && text[end] == '?') end++
  return end - k
}

private fun skipQuantifierAt(text: String, k: Int): Int {
  if (k >= text.length) return 0
  return when (val c = text[k]) {
    '*',
    '+',
    '?' -> skipSymbolQuantifierAt(text, k)
    '{' -> skipBraceQuantifierAt(text, k)
    else -> {
      c // unused
      0
    }
  }
}

private fun quantifierAtAllowsZero(text: String, k: Int): Boolean {
  if (skipQuantifierAt(text, k) == 0) return false
  val c = text[k]
  if (c == '*' || c == '?') return true
  if (c != '{') return false
  val endBrace = text.indexOf('}', k)
  val low = text.substring(k + 1, endBrace).split(",")[0]
  return low.isEmpty() || low == "0"
}

/** The literal chars a terminator token at [j] can end with; null when unknown. */
private fun terminatorCharsAt(text: String, j: Int): Set<Char>? {
  if (j >= text.length) return null
  val c = text[j]
  if (c == '[') {
    val end = skipCharClass(text, j)
    val inner = text.substring(j + 1, end - 1)
    if (inner.startsWith("^") || inner.isEmpty()) return null
    return inner.toSet()
  }
  if (c == '\\' && j + 1 < text.length) {
    val next = text[j + 1]
    return if (next.isDigitInternal() || next.isAsciiLetterInternal()) null else setOf(next)
  }
  if (c in TERMINATOR_NON_LITERAL_LEADERS) return null
  return setOf(c)
}

/** (scan end, excluded prefix chars) for a broad scan atom at [i]. */
private fun broadScanExcludedChars(pattern: String, i: Int): Pair<Int, Set<Char>?> {
  val c = pattern[i]
  if (c == '.') return Pair(i + 1, emptySet())
  val j = skipCharClass(pattern, i)
  val inner = pattern.substring(i + 1, j - 1)
  if (!inner.startsWith("^")) return Pair(j, null)
  return Pair(j, inner.substring(1).toSet())
}

private fun classTerminatorFinding(
    pattern: String,
    i: Int,
    scanEnd: Int,
    prefixChars: Set<Char>,
    excluded: Set<Char>,
): String? {
  if (outerQuantifierLen(pattern, scanEnd) == 0) return null
  val termPos = scanEnd + skipQuantifierAt(pattern, scanEnd)
  val terminatorChars = terminatorCharsAt(pattern, termPos)
  if (
      terminatorChars != null &&
          prefixChars.isNotEmpty() &&
          prefixChars.intersect(excluded).isEmpty() &&
          prefixChars.intersect(terminatorChars).isEmpty()
  ) {
    val sorted = prefixChars.sorted().joinToString("")
    return "${pattern.substring(i, scanEnd)} preceded by $sorted"
  }
  return null
}

private fun unreachableTerminatorBroadScanStep(
    pattern: String,
    i: Int,
    prefixChars: Set<Char>,
): Triple<Int, Set<Char>, String?> {
  val (scanEnd, excluded) = broadScanExcludedChars(pattern, i)
  if (excluded == null) return Triple(scanEnd, emptySet(), null)
  val finding = classTerminatorFinding(pattern, i, scanEnd, prefixChars, excluded)
  if (finding != null) return Triple(scanEnd, prefixChars, finding)
  val nextI = scanEnd + skipQuantifierAt(pattern, scanEnd)
  return Triple(nextI, emptySet(), null)
}

private fun unreachableTerminatorEscapeStep(
    pattern: String,
    i: Int,
    prefixChars: Set<Char>,
): Pair<Int, Set<Char>> {
  val next = pattern[i + 1]
  val tokenEnd = i + 2
  val nextPrefix =
      when {
        !next.isDigitInternal() && !next.isAsciiLetterInternal() -> prefixChars + next
        quantifierAtAllowsZero(pattern, tokenEnd) -> prefixChars
        else -> emptySet()
      }
  return Pair(tokenEnd + skipQuantifierAt(pattern, tokenEnd), nextPrefix)
}

private fun unreachableTerminatorGroupOpenStep(
    pattern: String,
    i: Int,
    prefixChars: Set<Char>,
): Pair<Int, Set<Char>> {
  if (pattern.length >= i + 3 && pattern.substring(i + 1, i + 3) == "?:") {
    return Pair(i + 3, prefixChars)
  }
  if (i + 1 < pattern.length && pattern[i + 1] == '?') {
    val endParen = pattern.indexOf(')', i)
    val nextI = if (endParen != -1) endParen + 1 else i + 1
    return Pair(nextI, emptySet())
  }
  return Pair(i + 1, emptySet())
}

private fun unreachableTerminatorStep(
    pattern: String,
    i: Int,
    prefixChars: Set<Char>,
): Triple<Int, Set<Char>, String?> {
  when (val c = pattern[i]) {
    '(' -> {
      val (nextI, nextPrefix) = unreachableTerminatorGroupOpenStep(pattern, i, prefixChars)
      return Triple(nextI, nextPrefix, null)
    }
    in PREFIX_RESET_CHARS -> return Triple(i + 1, emptySet(), null)
    '[',
    '.' -> return unreachableTerminatorBroadScanStep(pattern, i, prefixChars)
    '\\' -> {
      if (i + 1 < pattern.length) {
        val (nextI, nextPrefix) = unreachableTerminatorEscapeStep(pattern, i, prefixChars)
        return Triple(nextI, nextPrefix, null)
      }
      return Triple(i + 1, prefixChars, null)
    }
    else -> return Triple(i + 1 + skipQuantifierAt(pattern, i + 1), prefixChars + c, null)
  }
}

/** _detect_unreachable_terminator_scan: the finding text, or null. */
public fun detectUnreachableTerminatorScan(pattern: String): String? {
  var prefixChars: Set<Char> = emptySet()
  var i = 0
  val n = pattern.length
  while (i < n) {
    val (nextI, nextPrefix, finding) = unreachableTerminatorStep(pattern, i, prefixChars)
    prefixChars = nextPrefix
    i = nextI
    if (finding != null) return finding
  }
  return null
}

internal fun Char.isDigitInternal(): Boolean = this in '0'..'9'

internal fun Char.isAsciiLetterInternal(): Boolean = this in 'a'..'z' || this in 'A'..'Z'
