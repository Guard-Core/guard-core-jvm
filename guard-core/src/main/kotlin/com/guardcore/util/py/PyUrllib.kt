package com.guardcore.util.py

/**
 * Port of the `urllib.parse` functions guard-core's redaction paths use: `unquote` / `unquote_plus`
 * (utf-8, errors='replace'), `quote`, `urlsplit` and `urlunsplit`. Semantics verified against
 * CPython 3.10.
 */
public object PyUrllib {
  private val HEX_DIGITS = "0123456789ABCDEF".toCharArray()

  private fun isHex(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

  private fun hexByte(c1: Char, c2: Char): Int =
      (Character.digit(c1, 16) shl 4) or Character.digit(c2, 16)

  /**
   * Port of `urllib.parse.unquote(string)` with the default encoding='utf-8', errors='replace'.
   * Maximal runs of %XX escapes are decoded together as utf-8; invalid hex leaves the '%' literal;
   * invalid utf-8 becomes U+FFFD.
   */
  public fun unquote(text: String): String {
    if ('%' !in text) return text
    val out = StringBuilder(text.length)
    val byteRun = java.io.ByteArrayOutputStream()
    var i = 0
    val n = text.length
    fun flushRun() {
      if (byteRun.size() > 0) {
        out.append(String(byteRun.toByteArray(), Charsets.UTF_8))
        byteRun.reset()
      }
    }
    while (i < n) {
      val c = text[i]
      if (c == '%' && i + 2 < n && isHex(text[i + 1]) && isHex(text[i + 2])) {
        byteRun.write(hexByte(text[i + 1], text[i + 2]))
        i += 3
      } else {
        flushRun()
        out.append(c)
        i++
      }
    }
    flushRun()
    return out.toString()
  }

  /** Port of `urllib.parse.unquote_plus` (the '+' to space fold happens first). */
  public fun unquotePlus(text: String): String =
      unquote(if ('+' in text) text.replace("+", " ") else text)

  private fun quoteSafe(ch: Char, safe: String): Boolean =
      ch in 'a'..'z' ||
          ch in 'A'..'Z' ||
          ch in '0'..'9' ||
          ch == '_' ||
          ch == '.' ||
          ch == '-' ||
          ch == '~' ||
          safe.indexOf(ch) >= 0

  /**
   * Port of `urllib.parse.quote(text, safe=safe)` with utf-8 encoding: always-safe
   * letters/digits/`_.-~` plus `safe` pass through, everything else is percent-encoded uppercase
   * hex.
   */
  public fun quote(text: String, safe: String = "/"): String {
    val out = StringBuilder(text.length)
    var i = 0
    while (i < text.length) {
      val cp = text.codePointAt(i)
      val charCount = Character.charCount(cp)
      if (cp < 128 && quoteSafe(text[i], safe)) {
        out.append(text[i])
      } else {
        val bytes = text.substring(i, i + charCount).toByteArray(Charsets.UTF_8)
        for (b in bytes) {
          val v = b.toInt() and 0xFF
          out.append('%').append(HEX_DIGITS[v ushr 4]).append(HEX_DIGITS[v and 0x0F])
        }
      }
      i += charCount
    }
    return out.toString()
  }

  /** Port of `urllib.parse.SplitResult` (tuple of scheme/netloc/path/query/fragment). */
  public data class SplitResult(
      val scheme: String,
      val netloc: String,
      val path: String,
      val query: String,
      val fragment: String,
  ) {
    override fun toString(): String = urlunsplit(scheme, netloc, path, query, fragment)
  }

  /** Port of `urllib.parse.urlsplit` (CPython 3.10 semantics). */
  public fun urlsplit(url: String): SplitResult {
    // CPython removes ASCII tab/newline characters anywhere in the URL.
    val cleaned =
        if (url.indexOf('\t') >= 0 || url.indexOf('\n') >= 0 || url.indexOf('\r') >= 0) {
          url.replace("\t", "").replace("\n", "").replace("\r", "")
        } else {
          url
        }
    var scheme = ""
    var rest = cleaned
    // scheme: leading ASCII letter then letters/digits/+-. before ':'.
    val colon = cleaned.indexOf(':')
    if (colon > 0) {
      val candidate = cleaned.substring(0, colon)
      if (candidate[0] in 'a'..'z' || candidate[0] in 'A'..'Z') {
        var valid = true
        for (c in candidate.substring(1)) {
          if (
              !(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '+' || c == '.' || c == '-')
          ) {
            valid = false
            break
          }
        }
        if (valid) {
          scheme = candidate.lowercase()
          rest = cleaned.substring(colon + 1)
        }
      }
    }
    var netloc = ""
    if (rest.startsWith("//")) {
      var end = -1
      for (i in 2 until rest.length) {
        val c = rest[i]
        if (c == '/' || c == '?' || c == '#') {
          end = i
          break
        }
      }
      netloc = if (end == -1) rest.substring(2) else rest.substring(2, end)
      rest = if (end == -1) "" else rest.substring(end)
    }
    var fragment = ""
    val hash = rest.indexOf('#')
    if (hash != -1) {
      fragment = rest.substring(hash + 1)
      rest = rest.substring(0, hash)
    }
    var path = rest
    var query = ""
    val qmark = rest.indexOf('?')
    if (qmark != -1) {
      query = rest.substring(qmark + 1)
      path = rest.substring(0, qmark)
    }
    return SplitResult(scheme, netloc, path, query, fragment)
  }

  // CPython 3.10 urllib.parse.uses_netloc (verbatim membership).
  private val USES_NETLOC: Set<String> =
      setOf(
          "",
          "ftp",
          "http",
          "gopher",
          "telnet",
          "imap",
          "wais",
          "file",
          "mms",
          "https",
          "shttp",
          "snews",
          "prospero",
          "rtsp",
          "rtspu",
          "rsync",
          "svn",
          "svn+ssh",
          "sftp",
          "nfs",
          "git",
          "git+ssh",
          "ws",
          "wss",
          "zeit",
          "irc",
          "ircs",
          "z39.50r",
          "z39.50s",
      )

  /** Port of `urllib.parse.urlunsplit`. */
  public fun urlunsplit(
      scheme: String,
      netloc: String,
      url: String,
      query: String,
      fragment: String,
  ): String {
    val sb = StringBuilder()
    var path = url
    if (
        netloc.isNotEmpty() ||
            (scheme.isNotEmpty() && scheme in USES_NETLOC) ||
            path.startsWith("//")
    ) {
      if (path.isNotEmpty() && !path.startsWith("/")) path = "/" + path
      path = "//$netloc$path"
    }
    if (scheme.isNotEmpty()) {
      sb.append(scheme).append(':')
    }
    sb.append(path)
    if (query.isNotEmpty()) sb.append('?').append(query)
    if (fragment.isNotEmpty()) sb.append('#').append(fragment)
    return sb.toString()
  }
}
