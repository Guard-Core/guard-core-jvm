package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyRePattern

/**
 * Escape decoders: hex, unicode, percent-u, and overlong UTF-8 percent runs.
 *
 * Port of guard_core/detection_engine/encoding_decoders.py.
 */
public object EncodingDecoders {
  private val HEX_ESCAPE_RE: PyRePattern = PyRe.compile("\\\\x([0-9a-fA-F]{2})", 0)
  private val UNICODE_ESCAPE_RE: PyRePattern = PyRe.compile("\\\\u([0-9a-fA-F]{4})", 0)
  private val PERCENT_U_ESCAPE_RE: PyRePattern = PyRe.compile("%u([0-9a-fA-F]{4})", 0)
  private val PERCENT_BYTE_RUN_RE: PyRePattern = PyRe.compile("(?:%[0-9a-fA-F]{2})+", 0)

  /** OVERLONG_LEAD_SPECS: lead byte -> (length, lead mask, first-lo, first-hi). */
  private val OVERLONG_LEAD_SPECS: Map<Int, List<Int>> =
      mapOf(
          0xC0 to listOf(2, 0x1F, 0x80, 0xBF),
          0xC1 to listOf(2, 0x1F, 0x80, 0xBF),
          0xE0 to listOf(3, 0x0F, 0x80, 0x9F),
          0xF0 to listOf(4, 0x07, 0x80, 0x8F),
      )

  public fun decodeHexEscapes(content: String): String =
      HEX_ESCAPE_RE.replaceAll(content) { match ->
        val text = match.group(1)
        val value = text.toInt(16)
        // python chr() accepts any code point; lone surrogates carry through as chars.
        String(Character.toChars(value))
      }

  public fun decodeUnicodeEscapes(content: String): String =
      UNICODE_ESCAPE_RE.replaceAll(content) { match ->
        String(Character.toChars(match.group(1).toInt(16)))
      }

  public fun decodePercentUEscapes(content: String): String =
      PERCENT_U_ESCAPE_RE.replaceAll(content) { match ->
        String(Character.toChars(match.group(1).toInt(16)))
      }

  private fun decodeOverlongSequenceAt(raw: ByteArray, index: Int): Pair<String, Int>? {
    val spec = OVERLONG_LEAD_SPECS[raw[index].toInt() and 0xFF] ?: return null
    if (index + spec[0] > raw.size) return null
    val sequenceLength = spec[0]
    val firstMin = spec[2]
    val firstMax = spec[3]
    val continuations = raw.copyOfRange(index + 1, index + sequenceLength)
    val first = continuations[0].toInt() and 0xFF
    if (first !in firstMin..firstMax) return null
    for (i in 1 until continuations.size) {
      val b = continuations[i].toInt() and 0xFF
      if (b !in 0x80..0xBF) return null
    }
    var codePoint = (raw[index].toInt() and 0xFF) and spec[1]
    for (b in continuations) {
      codePoint = (codePoint shl 6) or (b.toInt() and 0x3F)
    }
    return Pair(String(Character.toChars(codePoint)), sequenceLength)
  }

  /** lenient_overlong_utf8_decode. */
  public fun lenientOverlongUtf8Decode(raw: ByteArray): String {
    val chars = StringBuilder()
    var index = 0
    while (index < raw.size) {
      val overlong = decodeOverlongSequenceAt(raw, index)
      if (overlong != null) {
        chars.append(overlong.first)
        index += overlong.second
      } else {
        val b = raw[index].toInt() and 0xFF
        if (b < 0x80) {
          chars.append(b.toChar())
        }
        index += 1
      }
    }
    return chars.toString()
  }

  /** decode_overlong_utf8_percent_runs. */
  public fun decodeOverlongUtf8PercentRuns(content: String): String =
      PERCENT_BYTE_RUN_RE.replaceAll(content) { match ->
        val run = match.group()
        val raw = ByteArray(run.length / 3)
        for (i in raw.indices) {
          raw[i] = run.substring(i * 3 + 1, i * 3 + 3).toInt(16).toByte()
        }
        val valid = strictUtf8(raw)
        if (valid != null) run else lenientOverlongUtf8Decode(raw)
      }

  private fun strictUtf8(raw: ByteArray): String? =
      try {
        val decoder = Charsets.UTF_8.newDecoder()
        decoder.onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
        decoder.onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        decoder.decode(java.nio.ByteBuffer.wrap(raw)).toString()
      } catch (e: java.nio.charset.CharacterCodingException) {
        null
      }
}
