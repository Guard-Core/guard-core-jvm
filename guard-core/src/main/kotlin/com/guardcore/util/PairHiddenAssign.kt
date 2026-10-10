package com.guardcore.util

import com.guardcore.util.py.PyUnicode

/**
 * Port of `guard_core/_utils/pair_hidden_assign.py`: detection of "hidden" name=value assignments
 * (whitespace/escaped gaps, percent-encoded assign tokens, smuggled separators) during redaction.
 */
public object PairHiddenAssign {
  private const val REDACTED_MARKER = "[REDACTED]"

  private val HIDDEN_ASSIGN_TOKEN_LENGTHS = intArrayOf(3, 5, 7)

  private val SMUGGLED_SEPARATOR_REGEX = Regex("[&;,?|]")

  /**
   * Port of `_ESCAPED_GAP_RE` (pair_hidden_assign.py:20). Kotlin Regex has no scoped match, so the
   * decoders re-derive the matched body per alternative.
   */
  private val ESCAPED_GAP_REGEX =
      Regex(
          "\\\\+(?:(?<short>[tnrfvb\"'])|(?<octal>[0-7]{1,3})" +
              "|[xX](?<hex>[0-9A-Fa-f]{2})|u(?<u4>[0-9A-Fa-f]{4})" +
              "|u\\{(?<ubrace>[0-9A-Fa-f]{1,6})\\}|U(?<u8>[0-9A-Fa-f]{8})" +
              "|N\\{(?<named>[A-Za-z0-9 -]+)\\})",
      )

  /** Port of `_codepoint` (pair_hidden_assign.py:28). */
  private fun codepoint(body: String, base: Int): Char? {
    val code = body.toIntOrNull(base) ?: return null
    return if (code <= 0x10FFFF) code.toChar() else null
  }

  /** Port of `_named_codepoint` (pair_hidden_assign.py:33). */
  private fun namedCodepoint(body: String): Char? = PyUnicode.lookupNamedCodepoint(body)

  private val ESCAPE_DECODERS: Map<String, (String) -> Char?> =
      mapOf(
          "short" to { _ -> '\u0000' },
          "octal" to { body -> codepoint(body, 8) },
          "hex" to { body -> codepoint(body, 16) },
          "u4" to { body -> codepoint(body, 16) },
          "ubrace" to { body -> codepoint(body, 16) },
          "u8" to { body -> codepoint(body, 16) },
          "named" to { body -> namedCodepoint(body) },
      )

  /**
   * Port of `_ESCAPE_DECODERS["short"]` semantics: the Python lambda returns the null character
   * "\x00" for every short escape (pair_hidden_assign.py:41).
   */
  private fun shortEscapeDecoder(): Char = '\u0000'

  /** Port of `_is_gap_char` (pair_hidden_assign.py:51). */
  private fun isGapChar(decoded: Char?): Boolean =
      decoded != null &&
          (PyUnicode.isSpace(decoded) || decoded in PairValueScan.QUOTE_CHARS || decoded.code < 32)

  /** Port of `_escaped_gap_length` (pair_hidden_assign.py:57). */
  private fun escapedGapLength(text: String, pos: Int): Int {
    val match = ESCAPED_GAP_REGEX.matchAt(text, pos) ?: return 0
    val groupNames = listOf("short", "octal", "hex", "u4", "ubrace", "u8", "named")
    for (name in groupNames) {
      val body = match.groups[name]?.value ?: continue
      val decoded =
          if (name == "short") {
            shortEscapeDecoder()
          } else {
            ESCAPE_DECODERS[name]?.invoke(body)
          }
      return if (isGapChar(decoded)) match.value.length else 0
    }
    return 0
  }

  /** Port of `_match_hidden_assign_token` (pair_hidden_assign.py:65). */
  private fun matchHiddenAssignToken(text: String, pos: Int): Int? {
    if (pos < text.length && (text[pos] == '=' || text[pos] == ':')) return pos + 1
    val n = text.length
    for (length in HIDDEN_ASSIGN_TOKEN_LENGTHS) {
      val end = pos + length
      if (end > n) break
      if (
          PairValueScan.boundedPercentDecode(text.substring(pos, end)) == "=" ||
              PairValueScan.boundedPercentDecode(text.substring(pos, end)) == ":"
      ) {
        return end
      }
    }
    return null
  }

  /** Port of `_skip_hidden_assign_gap` (pair_hidden_assign.py:78). */
  private fun skipHiddenAssignGap(text: String, pos: Int, gapCache: MutableMap<Int, Int>): Int {
    var cursor = pos
    val visited = ArrayList<Int>()
    visited.add(pos)
    while (true) {
      val cached = gapCache[cursor]
      if (cached != null) {
        cursor = cached
        break
      }
      var nextCursor = PairValueScan.skipSoftWhitespace(text, cursor)
      nextCursor += escapedGapLength(text, nextCursor)
      if (nextCursor == cursor) break
      cursor = nextCursor
      visited.add(cursor)
    }
    for (boundary in visited) gapCache[boundary] = cursor
    return cursor
  }

  /** Port of `_match_hidden_assign` (pair_hidden_assign.py:97). */
  internal fun matchHiddenAssign(
      text: String,
      pos: Int,
      gapCache: MutableMap<Int, Int>? = null,
  ): Int? {
    val cache = gapCache ?: HashMap()
    var cursor = skipHiddenAssignGap(text, pos, cache)
    var matched = false
    while (true) {
      val tokenEnd = matchHiddenAssignToken(text, cursor) ?: break
      matched = true
      cursor = skipHiddenAssignGap(text, tokenEnd, cache)
    }
    return if (matched) cursor else null
  }

  /** Port of `_skip_assign_run_tail` (pair_hidden_assign.py:112). */
  private fun skipAssignRunTail(token: String, pos: Int): Int {
    var i = pos
    val n = token.length
    while (i < n && (token[i] == '=' || token[i] == ':')) {
      i++
      while (i < n && (token[i] == ' ' || token[i] == '\t')) i++
    }
    return i
  }

  /** Port of `_hidden_pair_split` (pair_hidden_assign.py:122). */
  private fun hiddenPairSplit(token: String): Pair<String, Int>? {
    val eqPos = token.indexOf("=")
    val colonPos = token.indexOf(":")
    val candidates = listOf(eqPos, colonPos).filter { it != -1 }
    if (candidates.isEmpty()) return null
    val splitPos = candidates.min()
    val valuePos = skipAssignRunTail(token, splitPos)
    return token.substring(0, splitPos).trim().lowercase() to valuePos
  }

  /** Port of `_redact_adjacent_sensitive_value` (pair_hidden_assign.py:133). */
  private fun redactAdjacentSensitiveValue(text: String, pos: Int): Pair<String, Int>? {
    val valueStart = PairValueScan.skipSoftWhitespace(text, pos)
    if (valueStart >= text.length || text[valueStart] in PairValueScan.HARD_SEP_CHARS) return null
    val leadingWs = text.substring(pos, valueStart)
    val (replacement, end) = PairValueScan.redactSensitivePairValue(text, valueStart)
    return (leadingWs + replacement) to end
  }

  /** Port of `_open_quote_at_end` (pair_hidden_assign.py:142). */
  private fun openQuoteAtEnd(replacement: String): Char {
    if (!replacement.endsWith(REDACTED_MARKER)) return PairValueScan.NO_QUOTE
    val quotePos = replacement.length - REDACTED_MARKER.length - 1
    if (quotePos < 0) return PairValueScan.NO_QUOTE
    val candidate = replacement[quotePos]
    return if (candidate in PairValueScan.QUOTE_CHARS) candidate else PairValueScan.NO_QUOTE
  }

  /** Port of `_close_dangling_quote_in_continuation` (pair_hidden_assign.py:152). */
  private fun closeDanglingQuoteInContinuation(
      redactedLocal: String,
      continuation: String,
  ): Pair<String, Int> {
    val quoteChar = openQuoteAtEnd(redactedLocal)
    if (quoteChar == PairValueScan.NO_QUOTE || continuation.isEmpty()) return redactedLocal to 0
    val idx = continuation.indexOf(quoteChar)
    if (idx == -1) return redactedLocal to continuation.length
    return (redactedLocal + quoteChar) to (idx + 1)
  }

  /** Port of `_rescan_decoded_run` (pair_hidden_assign.py:164). */
  private fun rescanDecodedRun(
      decodedRun: String,
      continuation: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): Pair<String, Int>? {
    if (decodedRun.firstOrNull() in PairValueScan.JSON_START_CHARS) {
      val wholeJson =
          PairValueScan.redactEmbeddedJsonValue(
              decodedRun,
              sensitive,
              sensitiveBodyFields,
              maxDepth,
          )
      if (wholeJson != null) return wholeJson to 0
    }
    if (PairValueScan.hasUndecodedPercentEscape(decodedRun)) return null
    val (redactedLocal, dangling) =
        PairRedaction.redactPairsInTextEx(decodedRun, sensitive, sensitiveBodyFields, maxDepth)
    if (redactedLocal == decodedRun) return null
    if (openQuoteAtEnd(redactedLocal) != PairValueScan.NO_QUOTE) {
      return closeDanglingQuoteInContinuation(redactedLocal, continuation)
    }
    if (dangling) {
      val adjacent = redactAdjacentSensitiveValue(continuation, 0)
      if (adjacent != null) {
        return (redactedLocal + adjacent.first) to adjacent.second
      }
    }
    return redactedLocal to 0
  }

  /** Port of `_redact_hidden_encoded_pair` (pair_hidden_assign.py:196). */
  internal fun redactHiddenEncodedPair(
      text: String,
      runEnd: Int,
      rawRun: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String> = emptySet(),
      maxDepth: Int = 32,
  ): Pair<String, Int>? {
    val decodedRun = PairValueScan.boundedPercentDecode(rawRun)
    val tokens = SMUGGLED_SEPARATOR_REGEX.split(decodedRun)
    for (token in tokens) {
      val split = hiddenPairSplit(token) ?: continue
      val name = split.first
      val valuePos = split.second
      if (name in sensitive || PairValueScan.hasUndecodedPercentEscape(name)) {
        if (tokens.size == 1 && valuePos >= token.length) {
          val adjacent = redactAdjacentSensitiveValue(text, runEnd)
          if (adjacent != null) {
            return (REDACTED_MARKER + adjacent.first) to adjacent.second
          }
        }
        return REDACTED_MARKER to runEnd
      }
    }
    if (decodedRun != rawRun) {
      val rescanned =
          rescanDecodedRun(
              decodedRun,
              text.substring(runEnd),
              sensitive,
              sensitiveBodyFields,
              maxDepth,
          )
      if (rescanned != null) {
        val replacement = rescanned.first
        val consumed = rescanned.second
        return replacement to (runEnd + consumed)
      }
    }
    return null
  }

  /**
   * Port of `_handle_no_literal_assign` (pair_hidden_assign.py:231). Returns (newFlushStart, newI,
   * valueStartOrNull).
   */
  internal fun handleNoLiteralAssign(
      text: String,
      runEnd: Int,
      rawRun: String,
      sensitive: Set<String>,
      out: StringBuilder,
      flushStart: Int,
      i: Int,
      sensitiveBodyFields: Set<String> = emptySet(),
      maxDepth: Int = 32,
      gapCache: MutableMap<Int, Int>? = null,
  ): Triple<Int, Int, Int?> {
    val valueStart = matchHiddenAssign(text, runEnd, gapCache)
    if (valueStart != null) return Triple(i, flushStart, valueStart)
    val result =
        redactHiddenEncodedPair(text, runEnd, rawRun, sensitive, sensitiveBodyFields, maxDepth)
    if (result == null) return Triple(runEnd, flushStart, null)
    val replacement = result.first
    val end = result.second
    out.append(text.substring(flushStart, i))
    out.append(replacement)
    return Triple(end, end, null)
  }
}
