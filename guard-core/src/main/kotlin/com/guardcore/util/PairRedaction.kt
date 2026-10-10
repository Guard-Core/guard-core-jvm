package com.guardcore.util

import com.guardcore.util.py.PyUnicode

/**
 * Port of `guard_core/_utils/pair_redaction.py`: the pair-grammar scanner that walks `name=value` /
 * `name: value` text and redacts sensitive values.
 */
public object PairRedaction {
  private const val NON_NAME_RUN_REGEX = "[^A-Za-z0-9_.\\-%+'\"]+"

  // Python's sentinel for protecting '+' during slow name decoding
  // (pair_redaction.py:44): U+E000, a private-use character.
  private const val PLUS_SENTINEL: Char = '\uE000'

  /** Port of `_NAME_BOUNDARY_RE` (pair_redaction.py:45). */
  private val NAME_BOUNDARY_REGEX =
      Regex("[^A-Za-z0-9_.\\-" + Regex.escape(PLUS_SENTINEL.toString()) + "]")

  /** Port of `_advance_past_non_name` (pair_redaction.py:39). */
  private fun advancePastNonName(text: String, pos: Int): Int {
    val match = Regex(NON_NAME_RUN_REGEX).matchAt(text, pos)
    return if (match != null) pos + match.value.length else pos + 1
  }

  /** Port of `_finish_name_segment` (pair_redaction.py:48). */
  private fun finishNameSegment(segment: String): String =
      segment.replace(PLUS_SENTINEL.toString(), " ").trim().lowercase()

  /** Port of `_decode_pair_name_slow` (pair_redaction.py:52). */
  private fun decodePairNameSlow(bareName: String, sensitive: Set<String>): String {
    val protectedName = bareName.replace("+", PLUS_SENTINEL.toString())
    val decoded = PairValueScan.boundedPercentDecode(protectedName, plusToSpace = false).trim()
    val boundaries = NAME_BOUNDARY_REGEX.findAll(decoded).toList()
    if (boundaries.isEmpty()) return finishNameSegment(decoded)
    val starts = listOf(0) + boundaries.map { it.range.last + 1 }
    val ends = boundaries.map { it.range.first } + listOf(decoded.length)
    val candidates =
        starts.zip(ends) { start, end -> finishNameSegment(decoded.substring(start, end)) }
    for (candidate in candidates) {
      if (candidate.isNotEmpty() && candidate in sensitive) return candidate
    }
    val last = candidates.last()
    return if (last.isNotEmpty()) last else candidates.first()
  }

  /** One anchored head match: name run bounds and assignment end (-1 when absent). */
  private class HeadMatch(
      val nameEnd: Int,
      val assignEnd: Int,
  )

  private fun isHex(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

  /** Consumes a NAME_CORE run from pos; returns the end index or null. */
  private fun matchNameCore(text: String, pos: Int): Int? {
    var j = pos
    val n = text.length
    while (j < n) {
      val c = text[j]
      val consumed =
          when {
            (c.code < 128 && c.isLetterOrDigit()) || c == '_' || c == '.' || c == '-' || c == '+' ->
                1
            c == '%' && j + 2 < n && isHex(text[j + 1]) && isHex(text[j + 2]) -> 3
            else -> 0
          }
      if (consumed == 0) break
      j += consumed
    }
    return if (j > pos) j else null
  }

  private fun isSoftSpaceNoNewline(c: Char): Boolean =
      c != '\r' && c != '\n' && PyUnicode.isSpace(c)

  /**
   * Anchored port of `_PAIR_HEAD_RE.match(text, i)` (pair_redaction.py:32). Pattern:
   * `(?P<name>"NAME"|'NAME'|NAME)(?P<assign>(?:[^\S\r\n]*[=:])+[^\S\r\n]*)?`
   */
  private fun matchPairHead(text: String, i: Int): HeadMatch? {
    val n = text.length
    val first = text[i]
    val nameEnd =
        if (first == '"' || first == '\'') {
          // Quoted alternative: NAME_CORE strictly between the quotes.
          val innerEnd = matchNameCore(text, i + 1)
          if (innerEnd == null || innerEnd >= n || text[innerEnd] != first) return null
          innerEnd + 1
        } else {
          matchNameCore(text, i) ?: return null
        }
    // Assign group: `(?:[^\S\r\n]*[=:])+[^\S\r\n]*`, optional, greedy.
    var pos = nameEnd
    var assignEnd = -1
    while (true) {
      var k = pos
      while (k < n && isSoftSpaceNoNewline(text[k])) k++
      if (k < n && (text[k] == '=' || text[k] == ':')) {
        var m = k + 1
        while (m < n && isSoftSpaceNoNewline(text[m])) m++
        pos = m
        assignEnd = m
      } else {
        break
      }
    }
    return HeadMatch(nameEnd, assignEnd)
  }

  /** Port of `_apply_result` (pair_redaction.py:70). */
  private fun applyResult(
      out: StringBuilder,
      text: String,
      flushStart: Int,
      valueStart: Int,
      result: Pair<String, Int>,
  ): Pair<Int, Int> {
    out.append(text.substring(flushStart, valueStart))
    out.append(result.first)
    return result.second to result.second
  }

  /** Port of `_resolve_pair_result` (pair_redaction.py:83). */
  private fun resolvePairResult(
      text: String,
      valueStart: Int,
      decodedName: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): Pair<String, Int>? {
    if (
        decodedName in sensitive ||
            ('%' in decodedName &&
                PairValueScan.PERCENT_ESCAPE_REGEX.toRegex().containsMatchIn(decodedName))
    ) {
      return PairValueScan.redactSensitivePairValue(text, valueStart)
    }
    if (text.getOrNull(valueStart) in PairValueScan.JSON_LIKELY_CHARS) {
      return PairValueScan.tryRedactJsonSpan(
          text,
          valueStart,
          sensitive,
          sensitiveBodyFields,
          maxDepth,
      )
    }
    return null
  }

  /** Port of `_redact_pairs_in_text_ex` (pair_redaction.py:102). */
  internal fun redactPairsInTextEx(
      text: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String> = emptySet(),
      maxDepth: Int = 32,
  ): Pair<String, Boolean> {
    val out = StringBuilder()
    var flushStart = 0
    var i = 0
    val n = text.length
    var dangling = false
    val gapCache = HashMap<Int, Int>()
    while (i < n) {
      dangling = false
      val headMatch = matchPairHead(text, i)
      if (headMatch == null) {
        i = advancePastNonName(text, i)
        continue
      }
      val rawRun = text.substring(i, headMatch.nameEnd)
      var valueStart: Int
      if (headMatch.assignEnd == -1) {
        val handled =
            PairHiddenAssign.handleNoLiteralAssign(
                text,
                headMatch.nameEnd,
                rawRun,
                sensitive,
                out,
                flushStart,
                i,
                sensitiveBodyFields,
                maxDepth,
                gapCache,
            )
        i = handled.first
        flushStart = handled.second
        if (handled.third == null) continue
        valueStart = handled.third!!
      } else {
        valueStart = headMatch.assignEnd
      }
      val bareName =
          if (rawRun.isNotEmpty() && rawRun[0] in PairValueScan.QUOTE_CHARS) {
            rawRun.substring(1, rawRun.length - 1)
          } else {
            rawRun
          }
      val decodedName =
          if ('%' !in bareName && '+' !in bareName) {
            bareName.lowercase()
          } else {
            decodePairNameSlow(bareName, sensitive)
          }
      val result =
          resolvePairResult(text, valueStart, decodedName, sensitive, sensitiveBodyFields, maxDepth)
      if (result != null) {
        dangling = result.second == valueStart && result.second == n
        val applied = applyResult(out, text, flushStart, valueStart, result)
        i = applied.first
        flushStart = applied.second
        continue
      }
      i = valueStart
    }
    out.append(text.substring(flushStart, i))
    return out.toString() to dangling
  }

  /** Port of `_redact_pairs_in_text` (pair_redaction.py:159). */
  public fun redactPairsInText(
      text: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String> = emptySet(),
      maxDepth: Int = 32,
  ): String = redactPairsInTextEx(text, sensitive, sensitiveBodyFields, maxDepth).first
}
