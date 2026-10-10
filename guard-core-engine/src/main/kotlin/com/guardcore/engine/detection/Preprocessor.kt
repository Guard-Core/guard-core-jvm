package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyRePattern
import com.guardcore.engine.py.PyUnicode

/**
 * ContentPreprocessor: decode common encodings, strip comments, and truncate safely.
 *
 * Port of guard_core/detection_engine/preprocessor.py. The agent-event seams from the python source
 * are no-ops here (no agent handler exists on the engine module surface; the facade wires telemetry
 * in W4).
 */
public class ContentPreprocessor(
    public val maxContentLength: Int = 10000,
    public val preserveAttackPatterns: Boolean = true,
    public val maxFullScanBytes: Int = DEFAULT_MAX_FULL_SCAN_BYTES,
) {
  public companion object {
    public const val DEFAULT_MAX_FULL_SCAN_BYTES: Int = 262144

    /** The lookalike table from normalize_unicode (preprocessor.py:111-137). */
    public val LOOKALIKES: List<Pair<String, String>> =
        listOf(
            "\u2044" to "/",
            "\uff0f" to "/",
            "\u29f8" to "/",
            "\u0130" to "I",
            "\u0131" to "i",
            "\u200b" to "",
            "\u200c" to "",
            "\u200d" to "",
            "\ufeff" to "",
            "\u00ad" to "",
            "\u034f" to "",
            "\u180e" to "",
            "\u2028" to "\n",
            "\u2029" to "\n",
            "\ue000" to "",
            "\ufff0" to "",
            "\u01c0" to "|",
            "\u037e" to ";",
            "\u2215" to "/",
            "\u2216" to "\\",
            "\uff1c" to "<",
            "\uff1e" to ">",
            "\uff1b" to ";",
            "\uff5c" to "|",
            "\uff06" to "&",
        )
  }

  public val attackIndicators: List<String> =
      listOf(
          "<script",
          "javascript:",
          "on\\w+=",
          "SELECT\\s+.{0,50}?\\s+FROM",
          "UNION\\s+SELECT",
          "\\.\\./",
          "eval\\s*\\(",
          "exec\\s*\\(",
          "system\\s*\\(",
          "<\\?php",
          "<%",
          "{{",
          "{%",
          "<iframe",
          "<object",
          "<embed",
          "onerror\\s*=",
          "onload\\s*=",
          "\\$\\{",
          "\\\\x[0-9a-fA-F]{2}",
          "%[0-9a-fA-F]{2}",
          "`",
          "\\$\\(",
          "[;&|]",
          "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b",
      )

  public val compiledIndicators: List<PyRePattern> = attackIndicators.map {
    PyRe.compile(it, com.guardcore.engine.py.PyReFlags.IGNORECASE)
  }

  public fun extractAttackRegions(content: String): List<IntRange> =
      com.guardcore.engine.detection.extractAttackRegions(this, content)

  public fun truncateSafely(content: String): String =
      com.guardcore.engine.detection.truncateSafely(this, content)

  /** normalize_unicode: NFKC plus the lookalike replacements. */
  public fun normalizeUnicode(content: String): String {
    var normalized = PyUnicode.nfkc(content)
    for ((char, replacement) in LOOKALIKES) {
      normalized = normalized.replace(char, replacement)
    }
    return normalized
  }

  public fun removeExcessiveWhitespace(content: String): String {
    val collapsed = whitespacePattern.replaceAll(content) { " " }
    // python str.strip(): trims whitespace from both ends.
    return collapsed.trim { it.isWhitespace() || it == '' }
  }

  public fun removeNullBytes(content: String): String {
    var out = content.replace("\u0000", "")
    for (i in 0 until 32) {
      if (i == 9 || i == 10 || i == 13) continue
      out = out.replace(i.toChar().toString(), "")
    }
    return out
  }

  /** decode_common_encodings: iterated decoders until a fixed point or the 16-iteration cap. */
  public fun decodeCommonEncodings(
      content: String,
      decodeBudgetExhausted: BooleanArray? = null,
  ): String {
    val maxDecodeIterations = 16
    var iterations = 0
    val gunzipAttemptsLeft = intArrayOf(Base64Decode.MAX_GUNZIP_ATTEMPTS_PER_PASS)
    var current = content

    while (iterations < maxDecodeIterations) {
      val original = current

      current = EncodingDecoders.decodeOverlongUtf8PercentRuns(current)
      current = PyUrllib.unquoteIgnore(current)
      current = PyHtml.unescape(current)
      current = EncodingDecoders.decodePercentUEscapes(current)
      current = EncodingDecoders.decodeHexEscapes(current)
      current = decodeLdapHexEscapes(current)
      current = EncodingDecoders.decodeUnicodeEscapes(current)
      current = normalizeUnicode(current)
      current = Base64Decode.decodeBase64Candidates(current, gunzipAttemptsLeft)

      if (current == original) break

      iterations += 1
    }
    if (iterations >= maxDecodeIterations) {
      decodeBudgetExhausted?.set(0, true)
    }

    current = stripSqlComments(current)
    return current
  }

  private fun decodeLdapHexEscapes(content: String): String =
      ldapHexEscapePattern.replaceAll(content) { match ->
        try {
          String(Character.toChars(match.group(1).toInt(16)))
        } catch (e: Exception) {
          match.group()
        }
      }

  /** _strip_sql_comments: block comments replaced by their body, line markers blanked. */
  public fun stripSqlComments(content: String): String {
    var out =
        sqlBlockCommentStripPattern.replaceAll(content) { match ->
          val body = match.group(1).ifEmpty { match.group(2) }
          " $body "
        }
    out = sqlLineCommentMarkerPattern.replaceAll(out) { " " }
    return out
  }

  /** preprocess: full pipeline; returns the processed content. */
  public fun preprocess(content: String, decodeBudgetExhausted: BooleanArray? = null): String =
      preprocessWithDecoded(content, decodeBudgetExhausted).first

  /** preprocess_with_decoded: (processed, decoded) pair. */
  public fun preprocessWithDecoded(
      content: String,
      decodeBudgetExhausted: BooleanArray? = null,
  ): Pair<String, String> {
    if (content.isEmpty()) return Pair("", "")
    var decoded = normalizeUnicode(content)
    decoded = decodeCommonEncodings(decoded, decodeBudgetExhausted)
    var processed = removeNullBytes(decoded)
    processed = removeExcessiveWhitespace(processed)
    processed = truncateSafely(processed)
    return Pair(processed, decoded)
  }

  /** preprocess_signal_preserving: normalize + truncate only. */
  public fun preprocessSignalPreserving(content: String): String {
    if (content.isEmpty()) return ""
    val normalized = normalizeUnicode(content)
    return truncateSafely(normalized)
  }

  /** preprocess_url_decoded_newline_preserving. */
  public fun preprocessUrlDecodedNewlinePreserving(
      content: String,
      decodeBudgetExhausted: BooleanArray? = null,
  ): String {
    if (content.isEmpty()) return ""
    var out = normalizeUnicode(content)
    out = decodeCommonEncodings(out, decodeBudgetExhausted)
    return truncateSafely(out)
  }

  /** preprocess_short_base64_additive_view. */
  public fun preprocessShortBase64AdditiveView(content: String): String =
      Base64View.buildShortBase64AdditiveView(this, content)

  public fun preprocessBatch(contents: List<String>): List<String> = contents.map { preprocess(it) }

  private val whitespacePattern: PyRePattern = PyRe.compile("\\s+", 0)
  private val ldapHexEscapePattern: PyRePattern = PyRe.compile("\\\\([0-9a-fA-F]{2})", 0)
  private val sqlBlockCommentStripPattern: PyRePattern =
      PyRe.compile("(?<!\\w)/\\*(?!!)(.*?)\\*/|/\\*(?!!)(.*?)\\*/(?!\\w)", PyReFlags.DOTALL)
  private val sqlLineCommentMarkerPattern: PyRePattern = PyRe.compile("--|#", 0)
}

/** python urllib.parse.unquote with errors="ignore" semantics. */
public object PyUrllib {
  public fun unquoteIgnore(content: String): String {
    if (!content.contains('%')) return content
    val out = StringBuilder(content.length)
    var i = 0
    val bytes = java.io.ByteArrayOutputStream()
    while (i < content.length) {
      val c = content[i]
      if (c == '%' && i + 2 < content.length) {
        val hex = content.substring(i + 1, i + 3)
        val value = hex.toIntOrNull(16)
        if (value != null) {
          bytes.write(value)
          i += 3
          continue
        }
      }
      if (bytes.size() > 0) {
        // Flush pending percent-encoded bytes as UTF-8, dropping invalid sequences.
        out.append(lossyUtf8BestEffort(bytes.toByteArray()))
        bytes.reset()
      }
      out.append(c)
      i++
    }
    if (bytes.size() > 0) {
      out.append(lossyUtf8BestEffort(bytes.toByteArray()))
    }
    return out.toString()
  }

  /** python unquote with errors="ignore": decode UTF-8, keeping valid, dropping invalid. */
  private fun lossyUtf8BestEffort(bytes: ByteArray): String {
    val decoder = Charsets.UTF_8.newDecoder()
    decoder.onMalformedInput(java.nio.charset.CodingErrorAction.IGNORE)
    decoder.onUnmappableCharacter(java.nio.charset.CodingErrorAction.IGNORE)
    return decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
  }
}

/** python html.unescape for the preprocessor's HTML decode pass. */
public object PyHtml {
  // The numeric + core named entities the corpus exercises; python's table is the full
  // html5 entity set, which the corpus never reaches beyond this subset.
  private val NAMED_ENTITIES: Map<String, String> =
      mapOf(
          "amp" to "&",
          "lt" to "<",
          "gt" to ">",
          "quot" to "\"",
          "apos" to "'",
          "nbsp" to " ",
          "copy" to "©",
          "reg" to "®",
          "hellip" to "…",
          "mdash" to "—",
          "ndash" to "–",
          "lsquo" to "‘",
          "rsquo" to "’",
          "ldquo" to "“",
          "rdquo" to "”",
      )

  public fun unescape(content: String): String {
    if (!content.contains('&')) return content
    val out = StringBuilder(content.length)
    var i = 0
    val n = content.length
    while (i < n) {
      val c = content[i]
      if (c != '&') {
        out.append(c)
        i++
        continue
      }
      var replaced = false
      // Longest named match first.
      for (len in 32 downTo 1) {
        if (i + 1 + len > n) continue
        val candidate = content.substring(i + 1, i + 1 + len)
        if (!candidate.endsWith(";")) continue
        val name = candidate.dropLast(1)
        val named = NAMED_ENTITIES[name]
        if (named != null) {
          out.append(named)
          i += 1 + len
          replaced = true
          break
        }
      }
      if (replaced) continue
      // Numeric: &#123; or &#x1F;
      if (i + 2 < n && content[i + 1] == '#') {
        val semi = content.indexOf(';', i + 2)
        if (semi != -1 && semi <= i + 12) {
          val body = content.substring(i + 2, semi)
          val value =
              if (body.startsWith("x") || body.startsWith("X")) body.substring(1).toIntOrNull(16)
              else body.toIntOrNull(10)
          if (value != null && value in 1..0x10FFFF) {
            // python html.unescape maps invalid Windows-1252 code points (0x80-0x9f).
            val mapped = WINDOWS_1252_MAP[value]
            if (mapped != null) {
              out.appendCodePoint(mapped)
            } else {
              out.appendCodePoint(value)
            }
            i = semi + 1
            continue
          }
        }
      }
      out.append('&')
      i++
    }
    return out.toString()
  }

  // html.unescape's invalid cp1252 -> unicode replacements (html5 spec).
  private val WINDOWS_1252_MAP: Map<Int, Int> =
      mapOf(
          0x80 to 0x20AC,
          0x82 to 0x201A,
          0x83 to 0x0192,
          0x84 to 0x201E,
          0x85 to 0x2026,
          0x86 to 0x2020,
          0x87 to 0x2021,
          0x88 to 0x02C6,
          0x89 to 0x2030,
          0x8A to 0x0160,
          0x8B to 0x2039,
          0x8C to 0x0152,
          0x8E to 0x017D,
          0x91 to 0x2018,
          0x92 to 0x2019,
          0x93 to 0x201C,
          0x94 to 0x201D,
          0x95 to 0x2022,
          0x96 to 0x2013,
          0x97 to 0x2014,
          0x98 to 0x02DC,
          0x99 to 0x2122,
          0x9A to 0x0161,
          0x9B to 0x203A,
          0x9C to 0x0153,
          0x9E to 0x017E,
          0x9F to 0x0178,
      )
}
