package com.guardcore.engine.detection

/**
 * Base64 alphabet tables for the candidate decoder.
 *
 * Port of guard_core/detection_engine/base64_alphabet.py. SEPARATOR_CHARS is every char outside the
 * data alphabet, plus Python's surrogateescape range (U+DC80..U+DCFF) which the JVM carries as
 * isolated surrogate chars in strings decoded from binary bodies.
 */
public object Base64Alphabet {
  public val DATA_CHARS: Set<Char> =
      (('a'..'z') + ('A'..'Z') + ('0'..'9') + setOf('+', '/', '_', '-')).toSet()

  public val SEPARATOR_CHARS: String = buildString {
    for (byte in 0x00..0x7F) {
      val ch = byte.toChar()
      if (ch !in DATA_CHARS) append(ch)
    }
    // Python's surrogateescape range (bytes 0x80-0xFF via errors="surrogateescape").
    for (codePoint in 0xDC80..0xDCFF) {
      append(codePoint.toChar())
    }
  }

  public val WIDENED_SEPARATOR_CHARS: String =
      SEPARATOR_CHARS.toList()
          .filter { it != '\r' && it != '\n' && it != '=' }
          .joinToString(separator = "") + "_-"

  /** str.maketrans("-_", "+/"). */
  public fun urlsafeTranslate(ch: Char): Char =
      when (ch) {
        '-' -> '+'
        '_' -> '/'
        else -> ch
      }

  private val widenedMarker = WIDENED_SEPARATOR_CHARS.toSet()

  public fun isWidenedSeparatorChar(ch: Char): Boolean = ch in widenedMarker
}
