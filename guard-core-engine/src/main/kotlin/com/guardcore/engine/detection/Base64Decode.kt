package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyRePattern
import com.guardcore.engine.py.PyUnicode

/**
 * Base64 candidate decoding over free text: run detection, gunzip peeling, and reassembly.
 *
 * Port of guard_core/detection_engine/base64_decode.py.
 */
public object Base64Decode {
  public const val MIN_RUN_LENGTH: Int = 12
  public const val MAX_GUNZIP_ATTEMPTS_PER_PASS: Int = 8
  public const val MAX_GUNZIP_OUTPUT_BYTES: Int = 8192
  public const val PRINTABLE_RATIO_THRESHOLD: Double = 0.5
  public const val FALLBACK_PRINTABLE_RATIO_THRESHOLD: Double = 0.95
  public const val MAX_REPLACEMENT_CHAR_RATIO: Double = 0.2

  /** Regex class body shared by the run regexes (python: DATA_ALPHABET). */
  private const val DATA_ALPHABET = "A-Za-z0-9+/_\\-"

  private val escapedSeparators: String = escapeClassBody(Base64Alphabet.SEPARATOR_CHARS)

  private val runUnit = "[$DATA_ALPHABET][$escapedSeparators]*"

  public val BASE64_RE: PyRePattern =
      PyRe.compile(
          "(?<![$DATA_ALPHABET])" +
              "(?:(?:$runUnit){$MIN_RUN_LENGTH,}={0,2}" +
              "|(?:$runUnit){${MIN_RUN_LENGTH - 1},}=" +
              "|(?:$runUnit){${MIN_RUN_LENGTH - 2},}==" +
              ")(?![$DATA_ALPHABET=])",
          0,
      )

  public val RUN_RE: PyRePattern =
      PyRe.compile(
          "(?<![$DATA_ALPHABET])[$DATA_ALPHABET]{$MIN_RUN_LENGTH,}={0,2}(?![$DATA_ALPHABET=])",
          0,
      )

  public val SUB_FLOOR_RUN_RE: PyRePattern =
      PyRe.compile(
          "(?<![$DATA_ALPHABET])" +
              "[$DATA_ALPHABET]{1,${MIN_RUN_LENGTH - 1}}" +
              "(?![$DATA_ALPHABET])",
          0,
      )

  public val HEX_LITERAL_RE: PyRePattern = PyRe.compile("0[xX][0-9a-fA-F]+", 0)

  private val WHITESPACE_RE: PyRePattern =
      PyRe.compile("[${escapeClassBody(Base64Alphabet.SEPARATOR_CHARS)}]+", 0)

  /** Class-body escape valid under both the python grammar check and java. */
  private fun escapeClassBody(chars: String): String {
    val sb = StringBuilder()
    for (ch in chars) {
      val cp = ch.code
      when {
        cp < 0x20 || cp == 0x7F -> sb.append("\\x%02x".format(cp))
        ch == '\\' || ch == ']' || ch == '^' || ch == '-' || ch == '[' -> sb.append('\\').append(ch)
        else -> sb.append(ch)
      }
    }
    return sb.toString()
  }

  private val widenedMarker = Base64Alphabet.WIDENED_SEPARATOR_CHARS.toSet()

  public fun isHexLiteral(token: String): Boolean =
      HEX_LITERAL_RE.matchesFull(token, Long.MAX_VALUE) != null

  public fun printableRatio(text: String): Double {
    if (text.isEmpty()) return 0.0
    var printable = 0
    for (ch in text) {
      if (PyUnicode.isPrintable(ch)) printable++
    }
    return printable.toDouble() / text.length
  }

  public fun replacementCharRatio(text: String): Double {
    if (text.isEmpty()) return 0.0
    var count = 0
    for (ch in text) {
      if (ch == replacementChar) count++
    }
    return count.toDouble() / text.length
  }

  private const val replacementChar: Char = '\uFFFD'

  /** bounded_gunzip: gzip magic check plus a capped inflate (null on any failure). */
  public fun boundedGunzip(
      raw: ByteArray,
      maxOutputBytes: Int = MAX_GUNZIP_OUTPUT_BYTES,
  ): ByteArray? {
    if (raw.size < 2 || raw[0] != 0x1F.toByte() || raw[1] != 0x8B.toByte()) return null
    return try {
      val stream = java.util.zip.GZIPInputStream(raw.inputStream())
      val out = java.io.ByteArrayOutputStream()
      val buf = ByteArray(4096)
      var total = 0
      while (true) {
        val n = stream.read(buf)
        if (n < 0) break
        total += n
        if (total > maxOutputBytes) {
          stream.close()
          return null
        }
        out.write(buf, 0, n)
      }
      stream.close()
      out.toByteArray()
    } catch (e: java.util.zip.ZipException) {
      null
    } catch (e: java.io.IOException) {
      null
    }
  }

  private fun strictUtf8Decode(payload: ByteArray): String? =
      try {
        val decoder = Charsets.UTF_8.newDecoder()
        decoder.onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
        decoder.onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        decoder.decode(java.nio.ByteBuffer.wrap(payload)).toString()
      } catch (e: java.nio.charset.CharacterCodingException) {
        null
      }

  private fun decodeCleaned(
      cleaned: String,
      minPrintableRatio: Double,
      gunzipAttemptsLeft: IntArray?,
  ): String? {
    val padding = (4 - cleaned.length % 4) % 4
    val padded = cleaned + "=".repeat(padding)
    val raw: ByteArray =
        try {
          java.util.Base64.getDecoder().decode(padded)
        } catch (e: IllegalArgumentException) {
          return null
        }
    var payload = raw
    if (raw.size >= 2 && raw[0] == 0x1F.toByte() && raw[1] == 0x8B.toByte()) {
      if (gunzipAttemptsLeft == null || gunzipAttemptsLeft[0] <= 0) {
        // No attempts left: the raw gzip bytes fail the UTF-8 gates below.
        payload = raw
      } else {
        gunzipAttemptsLeft[0] -= 1
        val gunzipped = boundedGunzip(raw)
        if (gunzipped != null) payload = gunzipped
      }
    }
    val decoded = strictUtf8Decode(payload)
    if (decoded == null) {
      val decodedLossy = String(payload, Charsets.UTF_8)
      if (replacementCharRatio(decodedLossy) > MAX_REPLACEMENT_CHAR_RATIO) return null
      if (printableRatio(decodedLossy) >= minPrintableRatio) return decodedLossy
      return null
    }
    if (printableRatio(decoded) >= minPrintableRatio) return decoded
    return null
  }

  private fun decodeToken(
      token: String,
      minPrintableRatio: Double,
      gunzipAttemptsLeft: IntArray?,
  ): String? {
    if (isHexLiteral(token)) return null
    val cleaned = WHITESPACE_RE.replaceAll(token) { "" }
    val translated = cleaned.map { Base64Alphabet.urlsafeTranslate(it) }.joinToString("")
    val urlsafeDecoded = decodeCleaned(translated, minPrintableRatio, gunzipAttemptsLeft)
    if (urlsafeDecoded != null) return urlsafeDecoded
    if (cleaned.contains('-') || cleaned.contains('_')) {
      return decodeCleaned(
          cleaned.replace("-", "").replace("_", ""),
          minPrintableRatio,
          gunzipAttemptsLeft,
      )
    }
    return null
  }

  private fun decodeRuns(token: String, gunzipAttemptsLeft: IntArray?): String =
      RUN_RE.replaceAll(token) { match ->
        val segment = match.group()
        val decoded = decodeToken(segment, FALLBACK_PRINTABLE_RATIO_THRESHOLD, gunzipAttemptsLeft)
        decoded ?: segment
      }

  /** decode_base64_candidates: replace decodable base64 runs with their decoded text. */
  public fun decodeBase64Candidates(
      content: String,
      gunzipAttemptsLeft: IntArray? = null,
  ): String =
      BASE64_RE.replaceAll(content) { match ->
        val token = match.group()
        val widened = token.any { Base64Alphabet.isWidenedSeparatorChar(it) }
        val primaryThreshold =
            if (widened) FALLBACK_PRINTABLE_RATIO_THRESHOLD else PRINTABLE_RATIO_THRESHOLD
        val decoded = decodeToken(token, primaryThreshold, gunzipAttemptsLeft)
        val base = decoded ?: decodeRuns(token, gunzipAttemptsLeft)
        val fragments =
            SUB_FLOOR_RUN_RE.finditer(token, Long.MAX_VALUE).joinToString("") { it.group() }
        val reassembled =
            if (fragments.length >= MIN_RUN_LENGTH) {
              decodeToken(fragments, FALLBACK_PRINTABLE_RATIO_THRESHOLD, gunzipAttemptsLeft)
            } else {
              null
            }
        if (reassembled == null || base.contains(reassembled)) return@replaceAll base
        "$base $reassembled"
      }
}

/** python re.sub semantics over PyRe matches. */
public fun PyRePattern.replaceAll(text: String, transform: (PyReMatch) -> String): String {
  val sb = StringBuilder()
  var last = 0
  for (match in finditer(text, Long.MAX_VALUE)) {
    sb.append(text, last, match.charStart())
    sb.append(transform(match))
    last = match.charEnd()
  }
  sb.append(text, last, text.length)
  return sb.toString()
}

public fun PyRePattern.replaceFirst(text: String, transform: (PyReMatch) -> String): String {
  val match = search(text, 0, Long.MAX_VALUE) ?: return text
  val sb = StringBuilder()
  sb.append(text, 0, match.charStart())
  sb.append(transform(match))
  sb.append(text, match.charEnd(), text.length)
  return sb.toString()
}
