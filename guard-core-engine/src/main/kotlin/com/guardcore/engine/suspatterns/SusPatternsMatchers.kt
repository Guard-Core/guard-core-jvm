package com.guardcore.engine.suspatterns

import com.guardcore.engine.detection.boundedFinditer
import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyRePattern

/**
 * Windowed matcher helpers: custom first-match walks for the patterns whose naive scan is quadratic
 * or noisy.
 *
 * Port of guard_core/handlers/_suspatterns_matchers.py.
 */
public const val ATTR_EQUALS_WHITESPACE_RE: String = "\\s{0,20}"
public const val HTML_TAG_OPEN_RE: String = "<[A-Za-z/]"

public val CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE: PyRePattern =
    PyRe.compile(CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE, PyReFlags.IGNORECASE)

private val CMD_INJECTION_ASSIGNMENT_PREFIX_RE: PyRePattern = PyRe.compile("\\n[^\\S\\r\\n]*", 0)
private val CMD_INJECTION_ASSIGNMENT_TOKEN_RE: PyRePattern =
    PyRe.compile("[^=\\s;|&]+=[^\\s;|&]+\\s+", PyReFlags.IGNORECASE)

/** _cmd_injection_shell_dash_c_finditer. */
public fun cmdInjectionShellDashCFinditer(text: String, compiled: PyRePattern): List<PyReMatch> {
  val out = ArrayList<PyReMatch>()
  var lastEnd = 0
  for (prefixMatch in CMD_INJECTION_ASSIGNMENT_PREFIX_RE.finditer(text, Long.MAX_VALUE)) {
    val start = prefixMatch.charStart()
    if (start < lastEnd) continue
    var pos = prefixMatch.charEnd()
    while (true) {
      val tokenMatch =
          CMD_INJECTION_ASSIGNMENT_TOKEN_RE.matchAt(text, pos, text.length, Long.MAX_VALUE)
      if (tokenMatch == null) break
      pos = tokenMatch.charEnd()
    }
    val match = compiled.matchAt(text, start, text.length, Long.MAX_VALUE)
    if (match != null) {
      out.add(match)
      lastEnd = match.charEnd()
    } else {
      lastEnd = pos
    }
  }
  return out
}

/** _ldap_null_byte_attr_name_start. */
public fun ldapNullByteAttrNameStart(text: String, equalsPos: Int): Int? {
  var i = equalsPos
  while (
      i > 0 &&
          LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE.matchAt(
              text,
              i - 1,
              text.length,
              Long.MAX_VALUE,
          ) != null
  ) {
    i--
  }
  if (
      i == equalsPos ||
          LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE.matchAt(text, i, text.length, Long.MAX_VALUE) == null
  ) {
    return null
  }
  return i
}

/** _ldap_null_byte_value_start. */
public fun ldapNullByteValueStart(text: String, starPos: Int): Int {
  var i = starPos
  while (
      i > 0 &&
          LDAP_NULL_BYTE_VALUE_CHAR_RE.matchAt(text, i - 1, text.length, Long.MAX_VALUE) != null
  ) {
    i--
  }
  return i
}

/** _ldap_null_byte_attr_finditer. */
public fun ldapNullByteAttrFinditer(
    text: String,
    compiled: PyRePattern,
    tailRe: PyRePattern,
): List<PyReMatch> {
  if (!text.contains('*') || !text.contains(')')) return emptyList()
  val out = ArrayList<PyReMatch>()
  var lastEnd = 0
  for (tailMatch in tailRe.finditer(text, Long.MAX_VALUE)) {
    val starPos = tailMatch.charStart()
    if (starPos < lastEnd) continue
    val valueStart = ldapNullByteValueStart(text, starPos)
    if (valueStart == 0 || text[valueStart - 1] != '=') continue
    val nameStart = ldapNullByteAttrNameStart(text, valueStart - 1) ?: continue
    val match = compiled.matchAt(text, nameStart, tailMatch.charEnd(), Long.MAX_VALUE)
    if (match != null) {
      out.add(match)
      lastEnd = match.charEnd()
    }
  }
  return out
}

private val QUOTE_SPLICE_WORD_CHAR_RE: PyRePattern = PyRe.compile("\\w", 0)
private val QUOTE_SPLICE_QUOTE_RUN_RE: PyRePattern = PyRe.compile("['\"]+", 0)

/** _quote_splice_word_start. */
public fun quoteSpliceWordStart(text: String, pos: Int): Int? {
  var i = pos
  while (
      i > 0 && QUOTE_SPLICE_WORD_CHAR_RE.matchAt(text, i - 1, text.length, Long.MAX_VALUE) != null
  ) {
    i--
  }
  return if (i < pos) i else null
}

/** _quote_splice_finditer. */
public fun quoteSpliceFinditer(text: String, compiled: PyRePattern): List<PyReMatch> {
  val n = text.length
  val out = ArrayList<PyReMatch>()
  var lastEnd = 0
  for (quoteMatch in QUOTE_SPLICE_QUOTE_RUN_RE.finditer(text, Long.MAX_VALUE)) {
    if (quoteMatch.charStart() < lastEnd) continue
    val quoteEnd = quoteMatch.charEnd()
    if (
        quoteEnd >= n ||
            QUOTE_SPLICE_WORD_CHAR_RE.matchAt(text, quoteEnd, text.length, Long.MAX_VALUE) == null
    ) {
      continue
    }
    val wordStart = quoteSpliceWordStart(text, quoteMatch.charStart()) ?: continue
    val match = compiled.matchAt(text, wordStart, text.length, Long.MAX_VALUE)
    if (match != null) {
      out.add(match)
      lastEnd = match.charEnd()
    } else {
      lastEnd = quoteEnd
    }
  }
  return out
}

public const val SQLI_LOAD_FILE_RE: String = "(?i)(?:LOAD_FILE\\s*\\([^)]+\\))"

public val LOAD_FILE_SCAN_PREFIX_RE: PyRePattern =
    PyRe.compile("LOAD_FILE\\s*\\(", PyReFlags.IGNORECASE)
public val LOAD_FILE_SCAN_TERMINATOR_RE: PyRePattern = PyRe.compile("\\)", 0)

/** _load_file_scan_matches. */
public fun loadFileScanMatches(content: String, compiled: PyRePattern): List<PyReMatch> =
    boundedFinditer(content, compiled, LOAD_FILE_SCAN_PREFIX_RE, LOAD_FILE_SCAN_TERMINATOR_RE)

public const val CMD_INJECTION_DOLLAR_SUBSTITUTION_RE: String =
    "(?:[;&|]\\s*(?:\\$\\([^)]+\\)|\\$\\{[^}]+\\}))"

private val CMD_INJECTION_DOLLAR_PAREN_PREFIX_RE: PyRePattern = PyRe.compile("[;&|]\\s*\\$\\(", 0)
private val CMD_INJECTION_DOLLAR_PAREN_TERMINATOR_RE: PyRePattern = PyRe.compile("\\)", 0)
private val CMD_INJECTION_DOLLAR_BRACE_PREFIX_RE: PyRePattern = PyRe.compile("[;&|]\\s*\\$\\{", 0)
private val CMD_INJECTION_DOLLAR_BRACE_TERMINATOR_RE: PyRePattern = PyRe.compile("\\}", 0)

/** _cmd_injection_dollar_scan_matches. */
public fun cmdInjectionDollarScanMatches(content: String, compiled: PyRePattern): List<PyReMatch> {
  val parenMatches =
      boundedFinditer(
          content,
          compiled,
          CMD_INJECTION_DOLLAR_PAREN_PREFIX_RE,
          CMD_INJECTION_DOLLAR_PAREN_TERMINATOR_RE,
      )
  val braceMatches =
      boundedFinditer(
          content,
          compiled,
          CMD_INJECTION_DOLLAR_BRACE_PREFIX_RE,
          CMD_INJECTION_DOLLAR_BRACE_TERMINATOR_RE,
      )
  return parenMatches + braceMatches
}

public const val TEMPLATE_CURLY_KEYWORD_RE: String =
    "\\{\\{\\s*[^\\}]+(?:system|exec|popen|eval|require|include)\\s*\\}\\}"

private val TEMPLATE_CURLY_PREFIX_RE: PyRePattern = PyRe.compile("\\{\\{\\s*", 0)
private val TEMPLATE_CURLY_TERMINATOR_RE: PyRePattern = PyRe.compile("\\}\\}", 0)

/** _template_curly_keyword_scan_matches. */
public fun templateCurlyKeywordScanMatches(
    content: String,
    compiled: PyRePattern,
): List<PyReMatch> = SusPatternsTemplates.templateKeywordMatches(content, compiled, "{{", "}}")

public const val TEMPLATE_DOLLAR_BRACE_CALL_RE: String =
    "\\$\\{[^}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|\\d+\\s*[*/%+\\-]\\s*\\d+)[^}]*\\}"

private val TEMPLATE_DOLLAR_BRACE_PREFIX_RE: PyRePattern = PyRe.compile("\\$\\{", 0)
private val TEMPLATE_DOLLAR_BRACE_TERMINATOR_RE: PyRePattern = PyRe.compile("\\}", 0)

/** _template_dollar_brace_scan_matches. */
public fun templateDollarBraceScanMatches(content: String, compiled: PyRePattern): List<PyReMatch> =
    SusPatternsTemplates.templateExpressionMatches(content, compiled, "dollar")

public const val TEMPLATE_CURLY_CALL_RE: String =
    "\\{\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\(\\s*\\)|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}\\}"

/** _template_curly_call_scan_matches. */
public fun templateCurlyCallScanMatches(content: String, compiled: PyRePattern): List<PyReMatch> =
    SusPatternsTemplates.templateExpressionMatches(content, compiled, "curly")

public const val TEMPLATE_PERCENT_KEYWORD_RE: String =
    "\\{\\%\\s*[^\\%]+(?:system|exec|popen|eval|require|include)\\s*\\%\\}"

private val TEMPLATE_PERCENT_PREFIX_RE: PyRePattern = PyRe.compile("\\{\\%\\s*", 0)
private val TEMPLATE_PERCENT_TERMINATOR_RE: PyRePattern = PyRe.compile("\\%\\}", 0)

/** _template_percent_keyword_scan_matches. */
public fun templatePercentKeywordScanMatches(
    content: String,
    compiled: PyRePattern,
): List<PyReMatch> = SusPatternsTemplates.templateKeywordMatches(content, compiled, "{%", "%}")

public const val TEMPLATE_ASP_KEYWORD_RE: String =
    "(?i)<%[=#]?[^%]*(?:system|exec|eval|`|Runtime|IO\\.|File\\.|Dir\\." +
        "|\\d+\\s*[-+*/]\\s*\\d+)[^%]*%>"

private val TEMPLATE_ASP_PREFIX_RE: PyRePattern = PyRe.compile("<%[=#]?", 0)
private val TEMPLATE_ASP_TERMINATOR_RE: PyRePattern = PyRe.compile("%>", 0)

/** _template_asp_keyword_scan_matches. */
public fun templateAspKeywordScanMatches(content: String, compiled: PyRePattern): List<PyReMatch> =
    SusPatternsTemplates.templateExpressionMatches(content, compiled, "asp")

/** _template_hash_brace_scan_matches. */
public fun templateHashBraceScanMatches(content: String, compiled: PyRePattern): List<PyReMatch> =
    SusPatternsTemplates.templateExpressionMatches(content, compiled, "hash")

private val BRACE_EXPANSION_WORD_ITEM_RE: PyRePattern = PyRe.compile("\\A[A-Za-z0-9_./~-]+\\Z", 0)
private val BRACE_EXPANSION_LETTER_RE: PyRePattern = PyRe.compile("[A-Za-z]", 0)

/** _brace_expansion_is_dangerous_command. */
public fun braceExpansionIsDangerousCommand(match: PyReMatch): Boolean {
  val text = match.group()
  val start = text.indexOf('{')
  val end = text.lastIndexOf('}')
  if (start == -1 || end == -1 || end <= start) return false
  for (item in text.substring(start + 1, end).split(",")) {
    if (
        BRACE_EXPANSION_WORD_ITEM_RE.matchesFull(item, Long.MAX_VALUE) != null &&
            BRACE_EXPANSION_LETTER_RE.search(item, 0, Long.MAX_VALUE) != null
    ) {
      return true
    }
  }
  return false
}

public val DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE: PyRePattern =
    PyRe.compile(DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE, PyReFlags.IGNORECASE)

private val PICKLE_GLOBAL_NEWLINE_RE: PyRePattern = PyRe.compile("\\n", 0)
private val PICKLE_GLOBAL_IDENT_FULL_RE: PyRePattern =
    PyRe.compile("\\A[A-Za-z_][A-Za-z0-9_]{0,100}\\Z", PyReFlags.IGNORECASE)
private val PICKLE_GLOBAL_NON_MODULE_CHAR_RE: PyRePattern =
    PyRe.compile("[^A-Za-z0-9_.]", PyReFlags.IGNORECASE)
private val PICKLE_GLOBAL_IDENT_START_RE: PyRePattern =
    PyRe.compile("[A-Za-z_]", PyReFlags.IGNORECASE)
public const val PICKLE_GLOBAL_IDENT_MAX_LEN: Int = 101
public const val PICKLE_GLOBAL_DOTTED_SEGMENTS_MAX: Int = 20

/** _pickle_global_first_valid_marker. */
public fun pickleGlobalFirstValidMarker(
    text: String,
    lower: Char,
    upper: Char,
    floor: Int,
    ceiling: Int,
): Int? {
  var start = floor
  while (true) {
    val posLower = text.indexOf(lower, start)
    val posUpper = if (upper != lower) text.indexOf(upper, start) else -1
    val candidates = listOf(posLower, posUpper).filter { it != -1 && it < ceiling }
    if (candidates.isEmpty()) return null
    val pos = candidates.min()
    if (PICKLE_GLOBAL_IDENT_START_RE.matchAt(text, pos + 1, text.length, Long.MAX_VALUE) != null) {
      return pos
    }
    start = pos + 1
  }
}

/** _pickle_global_chain_start. */
public fun pickleGlobalChainStart(text: String, nl1: Int, floor: Int): Int? {
  var segEnd = nl1
  var earliest: Int? = null
  for (i in 0 until PICKLE_GLOBAL_DOTTED_SEGMENTS_MAX + 1) {
    val dotPos = text.lastIndexOf('.', segEnd - 1)
    val segStart = if (dotPos >= floor) dotPos + 1 else floor
    val segFloor = maxOf(segStart, segEnd - PICKLE_GLOBAL_IDENT_MAX_LEN - 1)
    val cPos = pickleGlobalFirstValidMarker(text, 'c', 'C', segFloor, segEnd)
    if (cPos != null) earliest = cPos
    if (
        dotPos < floor ||
            PICKLE_GLOBAL_IDENT_FULL_RE.matchesFull(
                text.substring(segStart, segEnd),
                Long.MAX_VALUE,
            ) == null
    ) {
      break
    }
    segEnd = dotPos
  }
  return earliest
}

/** _pickle_global_run_start. */
public fun pickleGlobalRunStart(
    nonModulePositions: List<Int>,
    nl1: Int,
    floor: Int,
): Int {
  var idx = nonModulePositions.binarySearch(nl1)
  if (idx < 0) idx = -(idx + 1)
  return if (idx > 0) maxOf(floor, nonModulePositions[idx - 1] + 1) else floor
}

/** _pickle_global_generic_finditer. */
public fun pickleGlobalGenericFinditer(text: String, compiled: PyRePattern): List<PyReMatch> {
  val newlinePositions =
      PICKLE_GLOBAL_NEWLINE_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
  if (newlinePositions.size < 2) return emptyList()
  val nonModulePositions =
      PICKLE_GLOBAL_NON_MODULE_CHAR_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }

  val out = ArrayList<PyReMatch>()
  var lastEnd = 0
  for (i in 0 until newlinePositions.size - 1) {
    val nl1 = newlinePositions[i]
    val nl2 = newlinePositions[i + 1]
    if (nl1 < lastEnd) continue
    if (PICKLE_GLOBAL_IDENT_FULL_RE.matchSubstring(text, nl1 + 1, nl2, Long.MAX_VALUE) == null)
        continue
    val runStart = pickleGlobalRunStart(nonModulePositions, nl1, lastEnd)
    val start = pickleGlobalChainStart(text, nl1, runStart) ?: continue
    val match = compiled.matchAt(text, start, text.length, Long.MAX_VALUE)
    if (match != null) {
      out.add(match)
      lastEnd = match.charEnd()
    }
  }
  return out
}
