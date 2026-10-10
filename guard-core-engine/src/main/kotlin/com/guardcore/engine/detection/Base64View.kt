package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyRePattern

/**
 * Short base64 additive view: decode 4..11 char base64 runs into appended fragments.
 *
 * Port of guard_core/detection_engine/base64_view.py.
 */
public object Base64View {
  private const val RUN_FLOOR = 12
  private const val MAX_SHORT_BASE64_TOKEN_LENGTH = RUN_FLOOR - 1
  private const val MAX_SHORT_BASE64_CANDIDATES = 20000
  private const val PRINTABLE_RATIO_THRESHOLD = 0.95

  private val SHORT_BASE64_TOKEN_RE: PyRePattern = PyRe.compile("[A-Za-z0-9+/]{4,}", 0)
  private val SHORT_BASE64_MARKER_CHARS = "\${}#".toSet()

  private fun decodeToken(token: String): String? {
    if (token.length > MAX_SHORT_BASE64_TOKEN_LENGTH) return null
    val padding = (4 - token.length % 4) % 4
    val raw: ByteArray =
        try {
          java.util.Base64.getDecoder().decode(token + "=".repeat(padding))
        } catch (e: IllegalArgumentException) {
          return null
        }
    val decoded = strictUtf8(raw) ?: return null
    return decoded
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

  private fun isQualifyingFragment(text: String): Boolean {
    var printable = 0
    for (ch in text) {
      if (com.guardcore.engine.py.PyUnicode.isPrintable(ch)) printable++
    }
    if (printable.toDouble() / text.length < PRINTABLE_RATIO_THRESHOLD) return false
    return text.any { it in SHORT_BASE64_MARKER_CHARS }
  }

  private fun decodeCandidate(token: String): String? {
    val decoded = decodeToken(token) ?: return null
    if (!isQualifyingFragment(decoded)) return null
    return decoded
  }

  /** build_short_base64_additive_view. */
  public fun buildShortBase64AdditiveView(
      preprocessor: ContentPreprocessor,
      content: String,
  ): String {
    if (content.isEmpty()) return ""
    val normalized = preprocessor.normalizeUnicode(content)
    val truncated = preprocessor.truncateSafely(normalized)

    val decodedFragments = ArrayList<String>()
    var attempts = 0
    for (match in SHORT_BASE64_TOKEN_RE.finditer(truncated, Long.MAX_VALUE)) {
      if (attempts >= MAX_SHORT_BASE64_CANDIDATES) break
      attempts += 1
      val decoded = decodeCandidate(match.group()) ?: continue
      decodedFragments.add(decoded)
    }

    return decodedFragments.joinToString("\n")
  }
}
