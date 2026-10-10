package com.guardcore.util.py

import com.guardcore.errors.ConfigValidationError
import com.guardcore.errors.PyRecursionError
import java.math.BigInteger
import java.util.Locale

/**
 * Port of the CPython `json` module subset guard-core's redaction and logging paths use:
 * `json.loads` / `json.dumps` with CPython-compatible grammar, value mapping, error classes, and
 * number/string rendering.
 *
 * Value mapping (mirrors CPython):
 * - object -> LinkedHashMap<String, Any?> (insertion ordered; duplicate keys: last wins)
 * - array -> ArrayList<Any?>
 * - string -> String (lone surrogates preserved, as in Python str)
 * - integer -> Long, or BigInteger beyond the 64-bit range
 * - real -> Double (so "1e999" -> Infinity; "NaN"/"Infinity" literals accepted)
 * - true/false/null -> Boolean / null
 *
 * Rendering mirrors `json.dumps(value, separators=(",", ":"))` in both ensure_ascii modes: the
 * guard-core redaction paths pass ensure_ascii=False, the JSON log formatter uses the default True.
 */
public object PyJson {
  /**
   * Nesting guard standing in for the Python recursion limit; catch sites treat it exactly like the
   * RecursionError they catch in Python.
   */
  public const val MAX_PARSE_DEPTH: Int = 1000

  /** Port of `json.JSONDecodeError` (a ValueError subclass in Python). */
  public class JsonDecodeError(message: String) : ConfigValidationError(message)

  // ---------------------------------------------------------------- parse

  /** Port of `json.loads` for str input (strict=True default). */
  public fun loads(text: String): Any? {
    val p = Parser(text)
    val value = p.parseValue(0)
    p.skipWhitespace()
    if (!p.atEnd()) throw p.error("Extra data")
    return value
  }

  private class Parser(private val text: String) {
    var pos: Int = 0

    fun atEnd(): Boolean = pos >= text.length

    fun error(message: String): JsonDecodeError =
        JsonDecodeError("$message: line ${lineOf(pos)} column ${columnOf(pos)} (char $pos)")

    private fun lineOf(p: Int): Int {
      var line = 1
      for (i in 0 until p) if (text[i] == '\n') line++
      return line
    }

    private fun columnOf(p: Int): Int {
      for (i in p - 1 downTo 0) if (text[i] == '\n') return p - i
      return p + 1
    }

    fun skipWhitespace() {
      while (pos < text.length) {
        when (text[pos]) {
          ' ',
          '\t',
          '\n',
          '\r' -> pos++
          else -> return
        }
      }
    }

    fun parseValue(depth: Int): Any? {
      if (depth > MAX_PARSE_DEPTH) throw PyRecursionError("Maximum JSON nesting depth exceeded")
      skipWhitespace()
      if (atEnd()) throw error("Expecting value")
      return when (text[pos]) {
        '{' -> parseObject(depth)
        '[' -> parseArray(depth)
        '"' -> parseString()
        't' -> parseLiteral("true", true)
        'f' -> parseLiteral("false", false)
        'n' -> parseLiteral("null", null)
        'N' -> parseLiteral("NaN", Double.NaN)
        'I' -> parseLiteral("Infinity", Double.POSITIVE_INFINITY)
        '-' -> parseNumber()
        else -> parseNumber()
      }
    }

    private fun parseLiteral(word: String, value: Any?): Any? {
      if (pos + word.length <= text.length && text.regionMatches(pos, word, 0, word.length)) {
        pos += word.length
        return value
      }
      throw error("Expecting value")
    }

    private fun parseObject(depth: Int): Any? {
      pos++ // consume '{'
      val result = LinkedHashMap<String, Any?>()
      skipWhitespace()
      if (!atEnd() && text[pos] == '}') {
        pos++
        return result
      }
      while (true) {
        skipWhitespace()
        if (atEnd() || text[pos] != '"') {
          throw error("Expecting property name enclosed in double quotes")
        }
        val key = parseString()
        skipWhitespace()
        if (atEnd() || text[pos] != ':') throw error("Expecting ':' delimiter")
        pos++
        result[key] = parseValue(depth + 1)
        skipWhitespace()
        when {
          atEnd() -> throw error("Expecting ',' delimiter")
          text[pos] == ',' -> pos++
          text[pos] == '}' -> {
            pos++
            return result
          }
          else -> throw error("Expecting ',' delimiter")
        }
      }
    }

    private fun parseArray(depth: Int): Any? {
      pos++ // consume '['
      val result = ArrayList<Any?>()
      skipWhitespace()
      if (!atEnd() && text[pos] == ']') {
        pos++
        return result
      }
      while (true) {
        result.add(parseValue(depth + 1))
        skipWhitespace()
        when {
          atEnd() -> throw error("Expecting ',' delimiter")
          text[pos] == ',' -> pos++
          text[pos] == ']' -> {
            pos++
            return result
          }
          else -> throw error("Expecting ',' delimiter")
        }
      }
    }

    fun parseString(): String {
      pos++ // consume opening quote
      val sb = StringBuilder()
      while (true) {
        if (atEnd()) throw error("Unterminated string starting at")
        val c = text[pos]
        when {
          c == '"' -> {
            pos++
            return sb.toString()
          }
          c == '\\' -> {
            pos++
            if (atEnd()) throw error("Unterminated string starting at")
            when (val esc = text[pos]) {
              '"' -> sb.append('"')
              '\\' -> sb.append('\\')
              '/' -> sb.append('/')
              'b' -> sb.append('\b')
              'f' -> sb.append('\u000C')
              'n' -> sb.append('\n')
              'r' -> sb.append('\r')
              't' -> sb.append('\t')
              'u' -> {
                val hex = hex4(pos + 1) ?: throw error("Invalid \\uXXXX escape")
                sb.append(hex.toChar())
                pos += 4
              }
              else -> throw error("Invalid \\escape: " + esc.toString())
            }
            pos++
          }
          else -> {
            // CPython rejects raw control characters inside strings
            // (strict=True, the guard-core call sites' default).
            if (c < ' ') throw error("Invalid control character")
            sb.append(c)
            pos++
          }
        }
      }
    }

    private fun hex4(start: Int): Int? {
      if (start + 4 > text.length) return null
      var v = 0
      for (i in start until start + 4) {
        val d = Character.digit(text[i], 16)
        if (d < 0) return null
        v = (v shl 4) or d
      }
      return v
    }

    fun parseNumber(): Any {
      val start = pos
      if (!atEnd() && text[pos] == '-') pos++
      if (atEnd() || text[pos] !in '0'..'9') throw error("Expecting value")
      // Leading zeros are invalid JSON: "01" parses "0" then fails on extra data.
      if (text[pos] == '0') {
        pos++
      } else {
        while (!atEnd() && text[pos] in '0'..'9') pos++
      }
      var isFloat = false
      if (!atEnd() && text[pos] == '.') {
        isFloat = true
        pos++
        if (atEnd() || text[pos] !in '0'..'9') throw error("Expecting value")
        while (!atEnd() && text[pos] in '0'..'9') pos++
      }
      if (!atEnd() && (text[pos] == 'e' || text[pos] == 'E')) {
        isFloat = true
        pos++
        if (!atEnd() && (text[pos] == '+' || text[pos] == '-')) pos++
        if (atEnd() || text[pos] !in '0'..'9') throw error("Expecting value")
        while (!atEnd() && text[pos] in '0'..'9') pos++
      }
      val token = text.substring(start, pos)
      return if (isFloat) {
        token.toDouble()
      } else if (token.length <= 18) {
        token.toLong()
      } else {
        try {
          token.toLong()
        } catch (_: NumberFormatException) {
          BigInteger(token)
        }
      }
    }
  }

  // --------------------------------------------------------------- dumps

  /**
   * Port of `json.dumps(value, separators=(",", ":"), ensure_ascii=ensureAscii,
   * sort_keys=sortKeys)`.
   */
  public fun dumps(value: Any?, ensureAscii: Boolean = false, sortKeys: Boolean = false): String {
    val sb = StringBuilder()
    write(sb, value, ensureAscii, sortKeys)
    return sb.toString()
  }

  private fun write(sb: StringBuilder, value: Any?, ensureAscii: Boolean, sortKeys: Boolean) {
    when (value) {
      null -> sb.append("null")
      is String -> writeString(sb, value, ensureAscii)
      is Boolean -> sb.append(if (value) "true" else "false")
      is Double -> sb.append(floatRepr(value))
      is Float -> sb.append(floatRepr(value.toDouble()))
      is Int,
      is Long,
      is Short,
      is Byte -> sb.append(value.toString())
      is BigInteger -> sb.append(value.toString())
      is Map<*, *> -> {
        sb.append('{')
        var first = true
        val entries =
            if (sortKeys) value.entries.sortedBy { it.key?.toString() ?: "" } else value.entries
        for ((k, v) in entries) {
          if (!first) sb.append(',')
          first = false
          writeString(sb, k as? String ?: k?.toString() ?: "null", ensureAscii)
          sb.append(':')
          write(sb, v, ensureAscii, sortKeys)
        }
        sb.append('}')
      }
      is Iterable<*> -> {
        sb.append('[')
        var first = true
        for (v in value) {
          if (!first) sb.append(',')
          first = false
          write(sb, v, ensureAscii, sortKeys)
        }
        sb.append(']')
      }
      else -> writeString(sb, value.toString(), ensureAscii)
    }
  }

  private fun writeString(sb: StringBuilder, s: String, ensureAscii: Boolean) {
    sb.append('"')
    if (ensureAscii) {
      for (c in s) {
        when {
          c == '"' -> sb.append("\\\"")
          c == '\\' -> sb.append("\\\\")
          c == '\b' -> sb.append("\\b")
          c == '\t' -> sb.append("\\t")
          c == '\n' -> sb.append("\\n")
          c == '\u000C' -> sb.append("\\f")
          c == '\r' -> sb.append("\\r")
          c.code < 0x20 -> unicodeEscape(sb, c.code)
          c.code in 0x20..0x7e -> sb.append(c)
          else -> unicodeEscape(sb, c.code)
        }
      }
    } else {
      for (c in s) {
        when {
          c == '"' -> sb.append("\\\"")
          c == '\\' -> sb.append("\\\\")
          c == '\b' -> sb.append("\\b")
          c == '\t' -> sb.append("\\t")
          c == '\n' -> sb.append("\\n")
          c == '\u000C' -> sb.append("\\f")
          c == '\r' -> sb.append("\\r")
          c.code < 0x20 -> unicodeEscape(sb, c.code)
          else -> sb.append(c)
        }
      }
    }
    sb.append('"')
  }

  private fun unicodeEscape(sb: StringBuilder, codeUnit: Int) {
    sb.append("\\u")
    sb.append(Integer.toHexString(codeUnit).padStart(4, '0'))
  }

  /**
   * Port of CPython `float.__repr__` as used by json.dumps: the shortest string that round-trips,
   * positional notation when the decimal exponent is in [-4, 16), otherwise signed
   * two-digit-minimum `e+NN` / `e-NN` form.
   */
  public fun floatRepr(d: Double): String =
      when {
        d.isNaN() -> "NaN"
        d == Double.POSITIVE_INFINITY -> "Infinity"
        d == Double.NEGATIVE_INFINITY -> "-Infinity"
        else -> {
          val neg = d < 0.0 || (d == 0.0 && 1.0 / d < 0)
          val abs = kotlin.math.abs(d)
          val (digits, exp) = shortestDigits(abs)
          val body = renderPythonFloat(neg, digits, exp)
          body
        }
      }

  /** Returns the shortest round-tripping mantissa digits and decimal exponent. */
  private fun shortestDigits(abs: Double): Pair<String, Int> {
    if (abs == 0.0) return "0" to 0
    for (p in 1..17) {
      val s = String.format(Locale.ROOT, "%." + p + "e", abs)
      if (s.toDouble() == abs) {
        val eIdx = s.indexOf('e')
        var mant = s.substring(0, eIdx)
        val exp = s.substring(eIdx + 1).toInt()
        if (mant.contains('.')) {
          mant = mant.trimEnd('0').trimEnd('.')
          mant = mant.replace(".", "")
        }
        return mant to exp
      }
    }
    // Unreachable for finite doubles.
    return abs.toString() to 0
  }

  private fun renderPythonFloat(neg: Boolean, digits: String, exp: Int): String {
    val sign = if (neg) "-" else ""
    return if (exp >= -4 && exp < 16) {
      // Positional form.
      val sb = StringBuilder()
      sb.append(sign)
      if (exp >= 0) {
        if (exp + 1 >= digits.length) {
          sb.append(digits)
          repeat(exp + 1 - digits.length) { sb.append('0') }
          sb.append(".0")
        } else {
          sb.append(digits.substring(0, exp + 1)).append('.').append(digits.substring(exp + 1))
        }
      } else {
        sb.append("0.")
        repeat(-exp - 1) { sb.append('0') }
        sb.append(digits)
      }
      sb.toString()
    } else {
      val expStr = buildString {
        append('e')
        if (exp >= 0) append('+') else append('-')
        append(kotlin.math.abs(exp).toString().padStart(2, '0'))
      }
      val mant =
          if (digits.length == 1) digits else digits.substring(0, 1) + "." + digits.substring(1)
      sign + mant + expStr
    }
  }
}
