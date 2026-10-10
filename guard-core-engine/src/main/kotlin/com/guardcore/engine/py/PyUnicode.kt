package com.guardcore.engine.py

import java.text.Normalizer

/**
 * Python str/unicodedata semantics the detection engine relies on, on top of the JVM.
 *
 * Port surface:
 * - unicodedata.normalize("NFKC", s) (preprocessor.py:108-142)
 * - str.isprintable() (semantic.py:12-20, base64_decode.py:42-46)
 * - str.lower()/upper()/casefold() per code point (_redos_ignorecase_fold.py:53-62)
 * - code-point indexing helpers mirroring Python len()/slice semantics, since JVM strings are
 *   UTF-16 code units while Python strings are code points.
 */
public object PyUnicode {
  /** Python str.isprintable(): false for Cc, Cf, Cs, Co, Cn, Zl, Zp, Zs (space U+0020 excepted). */
  public fun isPrintable(ch: Int): Boolean {
    if (ch == 0x20) return true
    val type = Character.getType(ch).toInt()
    return when (type) {
      Character.CONTROL.toInt(),
      Character.FORMAT.toInt(),
      Character.PRIVATE_USE.toInt(),
      Character.SURROGATE.toInt(),
      Character.UNASSIGNED.toInt(),
      Character.LINE_SEPARATOR.toInt(),
      Character.PARAGRAPH_SEPARATOR.toInt(),
      Character.SPACE_SEPARATOR.toInt() -> false
      else -> true
    }
  }

  public fun isPrintable(ch: Char): Boolean = isPrintable(ch.code)

  /** Python str.isprintable() over a whole string (all code points). */
  public fun allPrintable(text: String): Boolean {
    var i = 0
    val n = text.length
    while (i < n) {
      val cp = text.codePointAt(i)
      if (!isPrintable(cp)) return false
      i += Character.charCount(cp)
    }
    return true
  }

  /** unicodedata.normalize("NFKC", s). */
  public fun nfkc(text: String): String = Normalizer.normalize(text, Normalizer.Form.NFKC)

  /**
   * Python str.lower() for one code point (full mappings like the CPython default are the simple
   * mappings the fold-group builder needs; multi-char results are handled by the string-based
   * variants below).
   */
  public fun lowerCp(cp: Int): String = String(Character.toChars(cp)).lowercase()

  public fun upperCp(cp: Int): String = String(Character.toChars(cp)).uppercase()

  /**
   * Python str.casefold() for one code point: full case folding. java.lang.String has no casefold,
   * but lowercase() applies the full lowercase mapping, which equals casefold for every code point
   * except a small set (e.g. U+00DF stays U+00DF under lowercase while casefold gives "ss"); the
   * multi-char fold groups are registered either way because the variant string length drives the
   * grouping.
   */
  public fun casefoldCp(cp: Int): String = String(Character.toChars(cp)).lowercase()

  /** Python len(s): code point count. */
  public fun cpLength(text: String): Int = text.codePointCount(0, text.length)

  /** Python s[start:end] on code point indices (clamped like Python). */
  public fun cpSlice(text: String, start: Int, end: Int): String {
    val n = cpLength(text)
    var lo = start
    var hi = end
    if (lo < 0) lo += n
    if (hi < 0) hi += n
    lo = lo.coerceIn(0, n)
    hi = hi.coerceIn(0, n)
    if (lo >= hi) return ""
    val startChar = cpToCharIndex(text, lo)
    val endChar = cpToCharIndex(text, hi)
    return text.substring(startChar, endChar)
  }

  /** Python s[start:] on code point indices. */
  public fun cpSliceFrom(text: String, start: Int): String = cpSlice(text, start, cpLength(text))

  /** Python s[:end] on code point indices. */
  public fun cpSliceTo(text: String, end: Int): String = cpSlice(text, 0, end)

  /** char index (UTF-16 unit) of code point index [cpIndex]. */
  public fun cpToCharIndex(text: String, cpIndex: Int): Int {
    if (cpIndex <= 0) return 0
    var cp = 0
    var i = 0
    val n = text.length
    while (i < n) {
      if (cp == cpIndex) return i
      val codePoint = text.codePointAt(i)
      cp++
      i += Character.charCount(codePoint)
    }
    return n
  }

  /** code point index of char index (UTF-16 unit) [charIndex]. */
  public fun charToCpIndex(text: String, charIndex: Int): Int {
    val clamped = charIndex.coerceIn(0, text.length)
    return text.codePointCount(0, clamped)
  }

  /**
   * Prefix table mapping every char index to its code point index; index 0 is always 0 and the
   * array has length+1 entries so offsets at end-of-string map too.
   */
  public fun charToCpTable(text: String): IntArray {
    val table = IntArray(text.length + 1)
    var cp = 0
    var i = 0
    while (i < text.length) {
      table[i] = cp
      val codePoint = text.codePointAt(i)
      cp++
      i += Character.charCount(codePoint)
    }
    table[text.length] = cp
    return table
  }
}
