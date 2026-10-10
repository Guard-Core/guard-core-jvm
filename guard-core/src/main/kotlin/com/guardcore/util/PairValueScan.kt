package com.guardcore.util

import com.guardcore.util.py.PyJson
import com.guardcore.util.py.PyUnicode
import com.guardcore.util.py.PyUrllib

/**
 * Port of `guard_core/_utils/pair_value_scan.py`: bounded percent decoding and the sensitive
 * pair-value redaction scanner that finds the extent of a value after `name=` / `name:` and
 * replaces it with `[REDACTED]`.
 */
public object PairValueScan {
  // Python represents the no-quote marker with the empty string; the Kotlin
  // port uses the NUL character, which can never appear as a quote.
  internal const val NO_QUOTE: Char = '\u0000'

  internal const val MAX_DECODE_ROUNDS: Int = 3

  internal val JSON_START_CHARS: Set<Char> = setOf('{', '[')

  internal val HARD_SEP_CHARS: Set<Char> =
      setOf('&', ';', ',', '?', '|', '/', '[', ']', '{', '}', '(', ')', '\r', '\n', '<', '>')

  internal val QUOTE_CHARS: Set<Char> = setOf('\'', '"')

  private val HARD_WS_CHARS: Set<Char> = setOf('\r', '\n')

  internal const val PERCENT_ESCAPE_REGEX: String = "%[0-9A-Fa-f]{2}"

  /** Port of `_bounded_percent_decode` (pair_value_scan.py:10). */
  internal fun boundedPercentDecode(
      text: String,
      plusToSpace: Boolean = true,
  ): String {
    if ('%' !in text && '+' !in text) return text
    var decoded = text
    repeat(MAX_DECODE_ROUNDS) {
      val next = if (plusToSpace) PyUrllib.unquotePlus(decoded) else PyUrllib.unquote(decoded)
      if (next == decoded) return decoded
      decoded = next
      return@repeat
    }
    return decoded
  }

  /** Port of `_has_undecoded_percent_escape` (pair_value_scan.py:32). */
  internal fun hasUndecodedPercentEscape(text: String): Boolean =
      '%' in text && PERCENT_ESCAPE_REGEX.toRegex().containsMatchIn(text)

  /** Port of `_is_soft_ws` (pair_value_scan.py:36): Python isspace minus \r\n. */
  internal fun isSoftWs(ch: Char): Boolean = PyUnicode.isSpace(ch) && ch !in HARD_WS_CHARS

  /** Port of `_pair_starts_at` (pair_value_scan.py:40). */
  private fun pairStartsAt(text: String, pos: Int): Boolean {
    val nameEnd = matchNameRun(text, pos) ?: return false
    return matchAssign(text, nameEnd) != null
  }

  /** `(?:[A-Za-z0-9_.\-]|%[0-9A-Fa-f]{2}|\+)+` anchored at pos; returns end. */
  private fun matchNameRun(text: String, pos: Int): Int? {
    var i = pos
    val n = text.length
    while (i < n) {
      val c = text[i]
      when {
        c.isLetterOrDigit() && c.code < 128 || c == '_' || c == '.' || c == '-' || c == '+' -> i++
        c == '%' && i + 2 < n && isHex(text[i + 1]) && isHex(text[i + 2]) -> i += 3
        else -> return if (i > pos) i else null
      }
    }
    return if (i > pos) i else null
  }

  /** `[^\S\r\n]*[=:][^\S\r\n]*` anchored at pos; returns end index or null. */
  private fun matchAssign(text: String, pos: Int): Int? {
    var i = skipNonNewlineWs(text, pos)
    if (i >= text.length || (text[i] != '=' && text[i] != ':')) return null
    i++
    return skipNonNewlineWs(text, i)
  }

  private fun skipNonNewlineWs(text: String, pos: Int): Int {
    var i = pos
    while (i < text.length) {
      val c = text[i]
      if (c != '\r' && c != '\n' && PyUnicode.isSpace(c)) i++ else break
    }
    return i
  }

  private fun isHex(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

  /** Port of `_skip_soft_whitespace` (pair_value_scan.py:47). */
  internal fun skipSoftWhitespace(text: String, pos: Int): Int {
    var j = pos
    while (j < text.length && isSoftWs(text[j])) j++
    return j
  }

  /** Port of `_unquoted_value_extent` (pair_value_scan.py:55). */
  internal fun unquotedValueExtent(
      text: String,
      start: Int,
      limit: Int? = null,
      separators: Set<Char> = HARD_SEP_CHARS,
      quotes: Set<Char> = QUOTE_CHARS,
  ): Int {
    val n = if (limit == null) text.length else minOf(text.length, limit)
    var i = start
    while (i < n) {
      val ch = text[i]
      if (ch in separators || ch in quotes) return i
      if (isSoftWs(ch)) {
        val j = skipSoftWhitespace(text, i)
        if (pairStartsAt(text, j)) return i
        i = j
        continue
      }
      i++
    }
    return i
  }

  /** Port of `_sensitive_value_extent` (pair_value_scan.py:78). */
  private fun sensitiveValueExtent(text: String, start: Int, quoteChar: Char): Int =
      if (quoteChar != NO_QUOTE) {
        val idx = text.indexOf(quoteChar, start)
        if (idx == -1) text.length else idx
      } else {
        unquotedValueExtent(text, start)
      }

  /** Port of `_restart_value_extent_at_quote` (pair_value_scan.py:85). */
  private fun restartValueExtentAtQuote(
      text: String,
      bodyEnd: Int,
      @Suppress("UNUSED_PARAMETER") quoteChar: Char,
      blankBefore: Boolean,
  ): Pair<Char, Int> {
    val candidateQuote = text[bodyEnd]
    val closingIdx = text.indexOf(candidateQuote, bodyEnd + 1)
    return if (closingIdx == -1) {
      if (blankBefore) candidateQuote to text.length else candidateQuote to bodyEnd
    } else {
      candidateQuote to closingIdx
    }
  }

  /** Port of `_quote_char_at` (pair_value_scan.py:95). */
  internal fun quoteCharAt(text: String, pos: Int): Char =
      if (pos < text.length && text[pos] in QUOTE_CHARS) text[pos] else NO_QUOTE

  private const val ANGLE_OPEN = '<'

  private val ANGLE_VALUE_SEP_CHARS: Set<Char> = HARD_SEP_CHARS - setOf('<', '>')

  /** Port of `_angle_value_extent` (pair_value_scan.py:103). */
  private fun angleValueExtent(text: String, openPos: Int): Int =
      unquotedValueExtent(text, openPos, separators = ANGLE_VALUE_SEP_CHARS, quotes = emptySet())

  /** Port of `_build_redaction_result` (pair_value_scan.py:109). */
  private fun buildRedactionResult(text: String, quoteChar: Char, bodyEnd: Int): Pair<String, Int> {
    val n = text.length
    val closed = quoteChar != NO_QUOTE && bodyEnd < n && text[bodyEnd] == quoteChar
    val openQuote = if (quoteChar == NO_QUOTE) "" else quoteChar.toString()
    val replacement = openQuote + "[REDACTED]" + (if (closed) openQuote else "")
    val end = bodyEnd + (if (closed) 1 else 0)
    return replacement to end
  }

  /** Port of `_redact_sensitive_pair_value` (pair_value_scan.py:119). */
  internal fun redactSensitivePairValue(text: String, valueStart: Int): Pair<String, Int> {
    val n = text.length
    var quoteChar = quoteCharAt(text, valueStart)
    val bodyStart = valueStart + (if (quoteChar != NO_QUOTE) 1 else 0)
    var bodyEnd = sensitiveValueExtent(text, bodyStart, quoteChar)
    if (quoteChar == NO_QUOTE && bodyEnd < n && text[bodyEnd] in QUOTE_CHARS) {
      val blankBefore = boundedPercentDecode(text.substring(bodyStart, bodyEnd)).isBlank()
      val restarted = restartValueExtentAtQuote(text, bodyEnd, quoteChar, blankBefore)
      quoteChar = restarted.first
      bodyEnd = restarted.second
    }
    if (
        quoteChar == NO_QUOTE && bodyEnd == bodyStart && bodyEnd < n && text[bodyEnd] == ANGLE_OPEN
    ) {
      return "[REDACTED]" to angleValueExtent(text, bodyEnd)
    }
    return buildRedactionResult(text, quoteChar, bodyEnd)
  }

  private const val JSON_SNIFF_WINDOW = 8

  /** Port of `_looks_like_json_start` (pair_value_scan.py:142). */
  private fun looksLikeJsonStart(text: String, pos: Int): Boolean {
    if (pos >= text.length) return false
    val ch = text[pos]
    if (ch in JSON_START_CHARS) return true
    if (ch != '%') return false
    val end = minOf(text.length, pos + JSON_SNIFF_WINDOW)
    val decodedPrefix = boundedPercentDecode(text.substring(pos, end))
    return decodedPrefix.isNotEmpty() && decodedPrefix[0] in JSON_START_CHARS
  }

  /** Port of `_redact_embedded_json_value` (pair_value_scan.py:154). */
  internal fun redactEmbeddedJsonValue(
      candidate: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): String? {
    val decoded = boundedPercentDecode(candidate)
    // Python catches ValueError only (pair_value_scan.py:165); a
    // RecursionError propagates, so only JsonDecodeError is caught here.
    val parsed =
        try {
          PyJson.loads(decoded)
        } catch (_: PyJson.JsonDecodeError) {
          return null
        }
    if (parsed !is Map<*, *> && parsed !is List<*>) return null
    val redacted =
        LoggingUtils.redactSensitiveJson(parsed, sensitive, sensitiveBodyFields, maxDepth)
    if (redacted == parsed) {
      // Python compares the parsed structures; an unchanged structure
      // means nothing was redacted.
      return null
    }
    val serialized = PyJson.dumps(redacted, ensureAscii = false)
    return PyUrllib.quote(serialized, safe = "")
  }

  private const val JSON_CANDIDATE_MAX_LEN = 16384

  /** Port of `_redact_embedded_json_span` (pair_value_scan.py:181). */
  private fun redactEmbeddedJsonSpan(
      text: String,
      valueStart: Int,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): Pair<String, Int>? {
    val valueEnd = unquotedValueExtent(text, valueStart, valueStart + JSON_CANDIDATE_MAX_LEN)
    val redacted =
        redactEmbeddedJsonValue(
            text.substring(valueStart, valueEnd),
            sensitive,
            sensitiveBodyFields,
            maxDepth,
        ) ?: return null
    return redacted to valueEnd
  }

  internal val JSON_LIKELY_CHARS: Set<Char> = setOf('{', '[', '%')

  /** Port of `_try_redact_json_span` (pair_value_scan.py:202). */
  internal fun tryRedactJsonSpan(
      text: String,
      valueStart: Int,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): Pair<String, Int>? {
    if (!looksLikeJsonStart(text, valueStart)) return null
    return redactEmbeddedJsonSpan(text, valueStart, sensitive, sensitiveBodyFields, maxDepth)
  }
}
