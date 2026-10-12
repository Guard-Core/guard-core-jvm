package com.guardcore.engine.suspatterns

import com.guardcore.engine.detection.boundedFinditer
import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyRePattern

/**
 * File-upload scan matchers and template expression region matchers.
 *
 * Port of guard_core/handlers/_suspatterns_file_upload.py and _suspatterns_templates.py.
 */
public object SusPatternsFileUpload {
  public val DANGEROUS_EXTENSIONS: Set<String> =
      setOf(
          "phar",
          "phtml",
          "pht",
          "exe",
          "jsp",
          "jspx",
          "aspx",
          "asp",
          "asa",
          "asax",
          "ascx",
          "ashx",
          "asmx",
          "cer",
          "phps",
          "shtml",
          "cfm",
          "cfc",
          "war",
          "bash",
          "sh",
          "rb",
          "py",
          "pl",
          "cgi",
          "com",
          "bat",
          "cmd",
          "vbs",
          "vbe",
          "js",
          "ws",
          "wsf",
          "msi",
          "hta",
      )

  // python: "php\\d*|" + "|".join(escaped ext for sorted by (-len, name))
  private fun alternation(extensions: Set<String>): String =
      "php\\d*|" +
          extensions
              .sortedWith(compareByDescending<String> { it.length }.thenBy { it })
              .joinToString("|") { PyRe.escapeSource(it) }

  public val DANGEROUS_EXT_ALTERNATION: String = alternation(DANGEROUS_EXTENSIONS)

  public val DOUBLE_EXT_EXTENSIONS: Set<String> = DANGEROUS_EXTENSIONS - setOf("com")

  public val DOUBLE_EXT_ALTERNATION: String = alternation(DOUBLE_EXT_EXTENSIONS)

  public val BENIGN_TERMINAL_EXTENSIONS: Set<String> =
      setOf(
          "jpg",
          "jpeg",
          "png",
          "gif",
          "bmp",
          "webp",
          "svg",
          "ico",
          "tif",
          "tiff",
          "pdf",
          "doc",
          "docx",
          "xls",
          "xlsx",
          "ppt",
          "pptx",
          "odt",
          "mp3",
          "mp4",
          "avi",
          "mov",
          "wav",
          "webm",
          "mkv",
      )

  public val BENIGN_TERMINAL_ALTERNATION: String =
      BENIGN_TERMINAL_EXTENSIONS.sortedWith(compareByDescending<String> { it.length }.thenBy { it })
          .joinToString("|") { PyRe.escapeSource(it) }

  public const val NULL_OR_SEPARATOR_TRUNCATION_RE: String =
      "(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00|;)"

  public const val ATTR_EQUALS_WHITESPACE_RE: String = "\\s*"

  public const val FILENAME_EQUALS_RE: String = "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*"

  public const val DOUBLE_EXTENSION_RE: String =
      "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"" +
          "']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|a" +
          "spx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cg" +
          "i|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py" +
          "|rb|sh|ws)(?![A-Za-z0-9])(?:[^ \\\"'][^\\\"']*)?" +
          "\\.(?:docx|jpeg|pptx|tiff|webm|webp|xlsx|avi|bmp|d" +
          "oc|gif|ico|jpg|mkv|mov|mp3|mp4|odt|pdf|png|ppt|svg" +
          "|tif|wav|xls)[\\\"']"

  public const val TRUNCATION_RE: String =
      "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"" +
          "']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|a" +
          "spx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cg" +
          "i|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py" +
          "|rb|sh|ws)(?![A-Za-z0-9])(?:(?:%00|\\\\u0000|\\\\x" +
          "00|\\\\0|\\x00|;)[^\\\"']*|\\.)[\\\"']"

  public const val DECODED_TRUNCATION_RE: String =
      "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"" +
          "']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|a" +
          "spx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cg" +
          "i|cmd|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|pl|py" +
          "|rb|sh|ws)(?![A-Za-z0-9])(?:(?:\\x00|;)[^\\\"']*|" +
          "\\.)[\\\"']"

  public const val DANGEROUS_EXTENSION_RE: String =
      "(?:\\A|[;,:\\n])\\s*filename\\s*=\\s*[\\\"'][^\\\"" +
          "']*\\.(?:php\\d*|phtml|shtml|asax|ascx|ashx|asmx|a" +
          "spx|bash|jspx|phar|phps|asa|asp|bat|cer|cfc|cfm|cg" +
          "i|cmd|com|exe|hta|jsp|msi|pht|vbe|vbs|war|wsf|js|p" +
          "l|py|rb|sh|ws)[\\\"']"

  /** _file_upload_scan_window. */
  public fun scanWindow(content: String): String {
    val lastDouble = content.lastIndexOf('"')
    val lastSingle = content.lastIndexOf('\'')
    val cut = maxOf(lastDouble, lastSingle)
    return if (cut < 0) "" else content.substring(0, cut + 1)
  }

  public val DOUBLE_EXT_PREFIX_RE: PyRePattern =
      PyRe.compile("filename\\s*=\\s*[\"']", PyReFlags.IGNORECASE)
  public val QUOTE_RE: PyRePattern = PyRe.compile("[\"']", 0)
  public val FILENAME_TOKEN_RE: PyRePattern = PyRe.compile("filename", PyReFlags.IGNORECASE)
  public val DANGEROUS_EXTENSION_MARKER_RE: PyRePattern =
      PyRe.compile("\\.(?:" + DOUBLE_EXT_ALTERNATION + ")(?![A-Za-z0-9])", PyReFlags.IGNORECASE)
  public val BENIGN_TERMINAL_EXTENSION_RE: PyRePattern =
      PyRe.compile("\\.(?:" + BENIGN_TERMINAL_ALTERNATION + ")\\Z", PyReFlags.IGNORECASE)
  public val DANGEROUS_TERMINAL_EXTENSION_RE: PyRePattern =
      PyRe.compile("\\.(?:" + DANGEROUS_EXT_ALTERNATION + ")\\Z", PyReFlags.IGNORECASE)
  public val TRUNCATION_MARKER_RE: PyRePattern =
      PyRe.compile("(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00|;|\\.\\Z)", PyReFlags.IGNORECASE)
  public val DECODED_TRUNCATION_MARKER_RE: PyRePattern = PyRe.compile("(?:\\x00|;|\\.\\Z)", 0)
  public val VALIDATED_SPAN_RE: PyRePattern = PyRe.compile(".*", PyReFlags.DOTALL)

  /** _file_upload_match_start. */
  public fun matchStart(content: String, filenameStart: Int): Int? {
    var cursor = filenameStart - 1
    var firstNewline = -1
    while (cursor >= 0 && content[cursor].isWhitespace()) {
      if (content[cursor] == '\n') firstNewline = cursor
      cursor--
    }
    if (cursor == -1) return 0
    if (content[cursor] in ";,:\n") return cursor
    return if (firstNewline != -1) firstNewline else null
  }

  private fun skipWhitespace(content: String, cursorIn: Int): Int {
    var cursor = cursorIn
    while (cursor < content.length && content[cursor].isWhitespace()) cursor++
    return cursor
  }

  /** _file_upload_quoted_candidate: (match_start, body_start, end). */
  public fun quotedCandidate(content: String, filenameStart: Int): Triple<Int, Int, Int>? {
    val start = matchStart(content, filenameStart) ?: return null
    var cursor = skipWhitespace(content, filenameStart + "filename".length)
    if (cursor == content.length || content[cursor] != '=') return null
    cursor = skipWhitespace(content, cursor + 1)
    if (cursor == content.length || (content[cursor] != '"' && content[cursor] != '\'')) return null
    val bodyStart = cursor + 1
    val quote = QUOTE_RE.search(content, bodyStart, Long.MAX_VALUE) ?: return null
    return Triple(start, bodyStart, quote.charEnd())
  }

  /** _file_upload_is_double_extension. */
  public fun isDoubleExtension(body: String): Boolean {
    if (BENIGN_TERMINAL_EXTENSION_RE.search(body, 0, Long.MAX_VALUE) == null) return false
    val finalDot = body.lastIndexOf('.')
    if (finalDot < 0) return false
    for (dangerous in DANGEROUS_EXTENSION_MARKER_RE.finditer(body, Long.MAX_VALUE)) {
      if (dangerous.charEnd() > finalDot) break
      val suffixStart = dangerous.charEnd()
      if (suffixStart == finalDot || (suffixStart < finalDot && body[suffixStart] !in " \"'")) {
        return true
      }
    }
    return false
  }

  /** _file_upload_is_truncation. */
  public fun isTruncation(body: String, decoded: Boolean): Boolean {
    val marker = if (decoded) DECODED_TRUNCATION_MARKER_RE else TRUNCATION_MARKER_RE
    for (dangerous in DANGEROUS_EXTENSION_MARKER_RE.finditer(body, Long.MAX_VALUE)) {
      if (marker.matchAt(body, dangerous.charEnd(), body.length, Long.MAX_VALUE) != null) {
        return true
      }
    }
    return false
  }

  /** _file_upload_kind_matches. */
  public fun kindMatches(body: String, source: String): Boolean =
      when (source) {
        DANGEROUS_EXTENSION_RE ->
            DANGEROUS_TERMINAL_EXTENSION_RE.search(body, 0, Long.MAX_VALUE) != null
        DOUBLE_EXTENSION_RE -> isDoubleExtension(body)
        TRUNCATION_RE -> isTruncation(body, decoded = false)
        DECODED_TRUNCATION_RE -> isTruncation(body, decoded = true)
        else -> false
      }

  /** _file_upload_scan_matches. */
  public fun scanMatches(content: String, compiled: PyRePattern): List<PyReMatch> {
    val matches = ArrayList<PyReMatch>()
    var lastEnd = 0
    for (filename in FILENAME_TOKEN_RE.finditer(content, Long.MAX_VALUE)) {
      val candidate = quotedCandidate(content, filename.charStart()) ?: continue
      val (start, bodyStart, end) = candidate
      if (start < lastEnd) continue
      if (!kindMatches(content.substring(bodyStart, end - 1), compiled.source)) continue
      val match = VALIDATED_SPAN_RE.matchAt(content, start, end, Long.MAX_VALUE) ?: continue
      matches.add(match)
      lastEnd = end
    }
    return matches
  }

  /** _file_upload_double_extension_scan_matches. */
  public fun doubleExtensionScanMatches(content: String, compiled: PyRePattern): List<PyReMatch> =
      boundedFinditer(content, compiled, DOUBLE_EXT_PREFIX_RE, QUOTE_RE)
}

/**
 * Template expression regions: keyword and expression matchers shared by the template rows.
 *
 * Port of guard_core/handlers/_suspatterns_templates.py.
 */
public object SusPatternsTemplates {
  private const val KEYWORD_INDICATOR: String = "(?:system|exec|popen|eval|require|include)\\s*\\Z"
  private const val DOLLAR_INDICATOR: String =
      "@[\\w.]+@|\\b\\w+\\s*\\(|(?<!\\d)\\d+\\s*[*/%+\\-]\\s*\\d+"
  private const val CURLY_INDICATOR: String =
      "@[\\w.]+@|\\b\\w+\\(\\s*\\)" + "|(?<!\\d)['\"]?\\d+['\"]?\\s*[*/%+\\-]\\s*['\"]?\\d+['\"]?"
  private const val HASH_INDICATOR: String =
      "@[\\w.]+@|\\b\\w+\\s*\\(" + "|(?<!\\d)['\"]?\\d+['\"]?\\s*[*/%+\\-]\\s*['\"]?\\d+['\"]?"
  private const val ASP_INDICATOR: String =
      "system|exec|eval|`|Runtime|IO\\.|File\\.|Dir\\." + "|(?<!\\d)\\d+\\s*[-+*/]\\s*\\d+"
  private const val DATE_INDICATOR: String = "(?=\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))"

  private val templateRegexCache: HashMap<Pair<String, Int>, PyRePattern> = HashMap()

  private fun templateRegex(source: String, flags: Int): PyRePattern {
    val key = Pair(source, flags)
    synchronized(templateRegexCache) {
      return templateRegexCache.getOrPut(key) { PyRe.compile(source, flags) }
    }
  }

  /** _template_regions: yields (start, barrier, end) for each opening/closing pair. */
  private fun templateRegions(
      content: String,
      opening: String,
      closing: String,
  ): List<Triple<Int, Int, Int>> {
    val out = ArrayList<Triple<Int, Int, Int>>()
    var cursor = 0
    while (true) {
      val start = content.indexOf(opening, cursor)
      if (start == -1) break
      val bodyStart = start + opening.length
      val barrier = content.indexOf(closing[0], bodyStart)
      if (barrier == -1) break
      cursor = maxOf(bodyStart, barrier - opening.length + 1)
      if (content.startsWith(closing, barrier)) {
        out.add(Triple(start, barrier, barrier + closing.length))
      }
    }
    return out
  }

  /** _template_frame: the normalized span match anchored at start. */
  private fun templateFrame(
      content: String,
      opening: String,
      closing: String,
      start: Int,
      end: Int,
      flags: Int,
  ): PyReMatch {
    val source =
        PyRe.escapeSource(opening) +
            "[^" +
            PyRe.escapeSource(closing[0].toString()) +
            "]*" +
            PyRe.escapeSource(closing)
    val compiled = templateRegex(source, flags)
    return compiled.matchAt(content, start, end, Long.MAX_VALUE)
        ?: error("template frame must match its own span")
  }

  /** template_keyword_matches. */
  public fun templateKeywordMatches(
      content: String,
      compiled: PyRePattern,
      opening: String,
      closing: String,
  ): List<PyReMatch> {
    val indicator = templateRegex(KEYWORD_INDICATOR, compiled.flags)
    val matches = ArrayList<PyReMatch>()
    for ((start, barrier, end) in templateRegions(content, opening, closing)) {
      // python's endpos TRUNCATES the subject for matching, so the indicator's \Z anchors at
      // the barrier; a java region never moves \Z (absolute end), so the truncation must be
      // applied to the subject itself.
      if (
          indicator.search(
              content.substring(0, barrier),
              start + opening.length + 1,
              Long.MAX_VALUE,
          ) != null
      ) {
        matches.add(templateFrame(content, opening, closing, start, end, compiled.flags))
      }
    }
    return matches
  }

  private fun templateAfterDates(
      content: String,
      opening: String,
      startIn: Int,
      barrier: Int,
      flags: Int,
  ): Int {
    val datePattern = templateRegex(DATE_INDICATOR, flags)
    var lastDate = -1
    for (match in datePattern.finditerWithin(content, startIn + 2, barrier)) {
      lastDate = match.charStart()
    }
    if (lastDate != -1) {
      return content.indexOf(opening, lastDate + 1).let { found ->
        if (found != -1 && found < barrier) found else -1
      }
    }
    return startIn
  }

  /** template_expression_matches. */
  public fun templateExpressionMatches(
      content: String,
      compiled: PyRePattern,
      kind: String,
  ): List<PyReMatch> {
    val (opening, closing, source) =
        when (kind) {
          "dollar" -> Triple("\${", "}", DOLLAR_INDICATOR)
          "curly" -> Triple("{{", "}}", CURLY_INDICATOR)
          "hash" -> Triple("#{", "}", HASH_INDICATOR)
          "asp" -> Triple("<%", "%>", ASP_INDICATOR)
          else -> error("unknown template kind $kind")
        }
    val indicator = templateRegex(source, compiled.flags)
    val matches = ArrayList<PyReMatch>()
    var lastEnd = 0
    for ((start0, barrier, end) in templateRegions(content, opening, closing)) {
      var start = start0
      if (start < lastEnd) continue
      if (kind == "curly" || kind == "hash") {
        start = templateAfterDates(content, opening, start, barrier, compiled.flags)
      }
      if (
          start != -1 &&
              indicator.search(
                  // python endpos truncation: \Z-style indicators anchor at the barrier.
                  content.substring(0, barrier),
                  start + opening.length,
                  Long.MAX_VALUE,
              ) != null
      ) {
        matches.add(templateFrame(content, opening, closing, start, end, compiled.flags))
        lastEnd = end
      }
    }
    return matches
  }

  /** finditer over [from, to) - python re.finditer(string, pos, endpos) analog. */
  private fun PyRePattern.finditerWithin(
      text: String,
      from: Int,
      to: Int,
  ): List<com.guardcore.engine.py.PyReMatch> {
    val out = ArrayList<com.guardcore.engine.py.PyReMatch>()
    var searchFrom = from
    while (searchFrom <= to) {
      val match = search(text, searchFrom, to.toLong()) ?: break
      out.add(match)
      searchFrom =
          if (match.charEnd() > match.charStart()) match.charEnd() else match.charStart() + 1
    }
    return out
  }
}
