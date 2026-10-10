package com.guardcore.engine.suspatterns

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyRePattern

/**
 * Shell/backtick/glob source tables and the token validators.
 *
 * Port of guard_core/handlers/_suspatterns_shell_sources.py and _suspatterns_shell_validators.py.
 */
public val PATTERN_SCAN_WINDOW_MATCHERS:
    MutableMap<String, (String, PyRePattern) -> List<PyReMatch>> =
    mutableMapOf(
        SQLI_LOAD_FILE_RE to { content, compiled -> loadFileScanMatches(content, compiled) },
        CMD_INJECTION_DOLLAR_SUBSTITUTION_RE to
            { content, compiled ->
              cmdInjectionDollarScanMatches(content, compiled)
            },
        SusPatternsFileUpload.DANGEROUS_EXTENSION_RE to
            { content, compiled ->
              SusPatternsFileUpload.scanMatches(content, compiled)
            },
        SusPatternsFileUpload.DOUBLE_EXTENSION_RE to
            { content, compiled ->
              SusPatternsFileUpload.scanMatches(content, compiled)
            },
        SusPatternsFileUpload.TRUNCATION_RE to
            { content, compiled ->
              SusPatternsFileUpload.scanMatches(content, compiled)
            },
        SusPatternsFileUpload.DECODED_TRUNCATION_RE to
            { content, compiled ->
              SusPatternsFileUpload.scanMatches(content, compiled)
            },
        TEMPLATE_CURLY_KEYWORD_RE to
            { content, compiled ->
              templateCurlyKeywordScanMatches(content, compiled)
            },
        TEMPLATE_DOLLAR_BRACE_CALL_RE to
            { content, compiled ->
              templateDollarBraceScanMatches(content, compiled)
            },
        TEMPLATE_CURLY_CALL_RE to
            { content, compiled ->
              templateCurlyCallScanMatches(content, compiled)
            },
        TEMPLATE_PERCENT_KEYWORD_RE to
            { content, compiled ->
              templatePercentKeywordScanMatches(content, compiled)
            },
        TEMPLATE_ASP_KEYWORD_RE to
            { content, compiled ->
              templateAspKeywordScanMatches(content, compiled)
            },
        SSTI_HASH_BRACE_SHAPE_RE to
            { content, compiled ->
              templateHashBraceScanMatches(content, compiled)
            },
        GLOB_WILDCARD_ATOM_RE to
            { content, compiled ->
              globWildcardScanMatches(content, compiled)
            },
    )

public val DETECTION_RAW_VIEW_PATTERN_SOURCES: Set<String> =
    setOf(
        LDAP_NULL_BYTE_ATTR_RE,
        LDAP_NULL_BYTE_BARE_RE,
        HTTP_SPLIT_CRLF_RE,
        SQLI_ORDER_BY_TERMINATOR_RE,
        SQLI_COMMENT_TERMINATOR_RE,
        PATH_TRAVERSAL_ENCODED_DOT_RE,
        SSTI_HASH_BRACE_SHAPE_RE,
        DESERIALIZATION_JAVA_B64_RE,
        DESERIALIZATION_DOTNET_B64_RE,
        DESERIALIZATION_PICKLE_B64_RE,
        DESERIALIZATION_RUBY_B64_RE,
        DESERIALIZATION_PICKLE_OS_GLOBAL_RE,
        DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
        SusPatternsFileUpload.TRUNCATION_RE,
        SusPatternsFileUpload.DOUBLE_EXTENSION_RE,
        XSS_JS_SCHEME_CTRL_CHAR_RE,
    )

public val DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES: Set<String> =
    setOf(
        CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
        DIR_TRAVERSAL_ETC_SENSITIVE_RE,
        DIR_TRAVERSAL_WINDOWS_INI_RE,
        DIR_TRAVERSAL_PROC_ENVIRON_RE,
        DIR_TRAVERSAL_VAR_LOG_RE,
        SusPatternsFileUpload.DECODED_TRUNCATION_RE,
        LDAP_NULL_BYTE_DECODED_ATTR_RE,
        LDAP_NULL_BYTE_DECODED_BARE_RE,
        SQLI_ORDER_BY_STRONG_RE,
    )

public const val GLUED_BACKTICK_CANDIDATE_RE: String =
    "(?<!`)`(?:[A-Za-z0-9_./~]|\\$[({])(?:[^`\\\\\\n]|\\\\.)*`"

public const val GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE: String =
    "\\$\\((?:[^()\\\\\\n]|\\\\.)*\\)|\\$\\{(?:[^{}\\\\\\n]|\\\\.)*\\}"

private val GLUED_BACKTICK_ASCII_WORD_RE: PyRePattern = PyRe.compile("[A-Za-z0-9_]", 0)

private val STRONG_SQL_KEYWORD_GLUED_PREFIX_RE: PyRePattern =
    PyRe.compile(
        "(?i)\\b(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\\s+BY|" +
            "GROUP\\s+BY)\\Z",
        0,
    )

private val STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE: PyRePattern =
    PyRe.compile(
        "(?i)\\A(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\\s+BY|" +
            "GROUP\\s+BY)\\b",
        0,
    )

public const val BACKTICK_WINDOW_DELIMITER_CHARS: String = "`'\"\n\r"
private val BACKTICK_WINDOW_DELIMITER_RE: PyRePattern = PyRe.compile("[`'\"\\n\\r]", 0)

private val IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE: PyRePattern = PyRe.compile("[\\s/.;|&\$()]", 0)
private val IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE: PyRePattern = PyRe.compile("[/.;|&\$()]", 0)
private val BARE_SHELL_PARAMETER_NAME_RE: PyRePattern =
    PyRe.compile("\\A[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*\\Z", 0)
public val SHELL_SPECIAL_PARAMETER_NAMES: Set<String> = setOf("ifs")
public val AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS: Set<String> = setOf("query_param", "url_path")

public val CTX_CMD_INJECTION_WITH_URL_PATH: Set<String> =
    setOf("query_param", "header", "url_path", "request_body", "unknown")
public val CTX_LOG4SHELL: Set<String> =
    setOf("query_param", "header", "request_body", "url_path", "unknown")

public const val BRACE_EXPANSION_ITEM_RE: String = "[^{}\\s,:'\\\"][^{},:'\\\"]*"

public const val BRACE_EXPANSION_COMMAND_RE: String =
    "(?:\\A|[;&|]\\s*|\\\$\\()\\{[^{}\\s,:'\\\"][^{},:'\\\"]*(?:,(?:[^{}\\s,:'\\\"][^{},:'\\\"]*)?)+\\}"

public const val QUOTE_SPLICE_CANDIDATE_RE: String = "\\w+(?:['\\\"]+\\w+){1,10}"

public val QUOTE_SPLICE_CANDIDATE_COMPILED_RE: PyRePattern =
    PyRe.compile(QUOTE_SPLICE_CANDIDATE_RE, PyReFlags.IGNORECASE)

public const val GLOB_WILDCARD_ATOM_RE: String = "[A-Za-z0-9_./*?-]*[?*][A-Za-z0-9_./*?-]*"

private val GLOB_WILDCARD_PATH_RUN_RE: PyRePattern = PyRe.compile("[\\w./*?-]+", 0)
private val GLOB_WILDCARD_CHAR_RE: PyRePattern = PyRe.compile("[?*]", 0)

/** _glob_wildcard_scan_matches. */
public fun globWildcardScanMatches(content: String, compiled: PyRePattern): List<PyReMatch> {
  val matches = ArrayList<PyReMatch>()
  for (runMatch in GLOB_WILDCARD_PATH_RUN_RE.finditer(content, Long.MAX_VALUE)) {
    val runStart = runMatch.charStart()
    val runEnd = runMatch.charEnd()
    if (GLOB_WILDCARD_CHAR_RE.search(content, runStart, runEnd, Long.MAX_VALUE) == null) continue
    val match = compiled.matchAt(content, runStart, runEnd, Long.MAX_VALUE)
    if (match != null) matches.add(match)
  }
  return matches
}

public const val PY_DANGEROUS_MODULE_RE: String =
    "__import__\\(\\s*['\"](?:os|subprocess|builtins|importlib)['\"]\\s*\\)" +
        "|\\b(?:os|subprocess|builtins|importlib)\\b"

public const val PY_DANGEROUS_METHOD_RE: String =
    "system|popen|exec|eval|call|run|Popen|check_output|check_call"

private const val PY_MODULE_ALTERNATION: String =
    "(?:__import__\\(\\s*['\\\"](?:os|subprocess|builtins|importlib)['\\\"]\\s*\\)|" +
        "\\b(?:os|subprocess|builtins|importlib)\\b)"

private const val PY_METHOD_ALTERNATION: String =
    "(?:system|popen|exec|eval|call|run|Popen|check_output|check_call)"

public const val PY_GETATTR_INDIRECTION_RE: String =
    "(?-i:\\bgetattr\\(\\s*" +
        PY_MODULE_ALTERNATION +
        "\\s*,\\s*['\\\"]" +
        PY_METHOD_ALTERNATION +
        "['\\\"]\\s*\\)\\s*\\()"

public const val PY_VARS_INDIRECTION_RE: String =
    "(?-i:\\bvars\\(\\s*" +
        PY_MODULE_ALTERNATION +
        "\\s*\\)\\s*\\[\\s*['\\\"]" +
        PY_METHOD_ALTERNATION +
        "['\\\"]\\s*\\]\\s*\\()"

private val SHELL_CHAIN_OPERATOR_RE: PyRePattern = PyRe.compile(";|\\|\\||\\||&&", 0)

// ---- shell_validators ----

/** _backtick_token_has_chained_shell_operators. */
public fun backtickTokenHasChainedShellOperators(token: String): Boolean =
    SHELL_CHAIN_OPERATOR_RE.finditer(token, Long.MAX_VALUE).size >= 2

private val SHELL_METACHARACTER_WINDOW_RE: PyRePattern =
    PyRe.compile(
        "(?:;|\\|\\||\\||&&)\\s*(?:`|[A-Za-z_][\\w-]*|[~./][\\w./-]*|-\\w*)|\\$\\(|\\$\\{",
        0,
    )

private fun backtickPairGlued(content: String, start: Int, end: Int): Boolean {
  val prefixGlued =
      start > 0 &&
          GLUED_BACKTICK_ASCII_WORD_RE.matchAt(
              content,
              start - 1,
              content.length,
              Long.MAX_VALUE,
          ) != null
  val suffixGlued =
      end < content.length &&
          GLUED_BACKTICK_ASCII_WORD_RE.matchAt(content, end, content.length, Long.MAX_VALUE) != null
  return prefixGlued || suffixGlued
}

private const val BACKTICK_CLAUSE_BOUNDARY_CHARS = ".!?;&|"

private fun backtickPairTailAnchored(content: String, end: Int): Boolean =
    content.substring(end).isBlank()

private fun backtickPairClauseInitial(content: String, start: Int): Boolean {
  if (start == 0) return false
  if (content[start - 1] !in " \t\r\n") return false
  val prefix = content.substring(0, start).trimEnd { it.isWhitespace() }
  if (prefix.isEmpty()) return false
  return prefix[prefix.length - 1] in BACKTICK_CLAUSE_BOUNDARY_CHARS
}

private fun backtickPairAppendedClause(content: String, start: Int, end: Int): Boolean =
    backtickPairTailAnchored(content, end) && backtickPairClauseInitial(content, start)

private fun backtickWindowStart(content: String, position: Int): Int {
  var index = position
  while (index > 0 && content[index - 1] !in BACKTICK_WINDOW_DELIMITER_CHARS) index--
  return index
}

private fun backtickWindowEnd(content: String, position: Int): Int {
  val delimiter = BACKTICK_WINDOW_DELIMITER_RE.search(content, position, Long.MAX_VALUE)
  return delimiter?.charStart() ?: content.length
}

private fun backtickPairContextWindow(content: String, start: Int, end: Int): String {
  val windowStart = backtickWindowStart(content, start)
  val windowEnd = backtickWindowEnd(content, end)
  return content.substring(windowStart, windowEnd)
}

private val SHELL_TEXT_PRINTABLE_ASCII_RE: PyRePattern = PyRe.compile("\\A[\\t\\x20-\\x7e]*\\Z", 0)

private fun backtickTokenIsImplausibleSqlIdentifier(token: String): Boolean =
    IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE.search(token, 0, Long.MAX_VALUE) != null

private fun strongSqlKeywordGluedToPair(content: String, start: Int, end: Int): Boolean {
  val windowStart = backtickWindowStart(content, start)
  val windowEnd = backtickWindowEnd(content, end)
  val prefix = content.substring(windowStart, start)
  val suffix = content.substring(end, windowEnd)
  if (STRONG_SQL_KEYWORD_GLUED_PREFIX_RE.search(prefix, 0, Long.MAX_VALUE) != null) return true
  return STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE.matchAt(suffix, 0, suffix.length, Long.MAX_VALUE) !=
      null
}

/** _glued_backtick_pair_is_injection. */
public fun gluedBacktickPairIsInjection(match: PyReMatch, context: String): Boolean {
  val content = match.subject()
  val start = match.charStart()
  val end = match.charEnd()
  val token = content.substring(start + 1, end - 1)
  if (SHELL_TEXT_PRINTABLE_ASCII_RE.matchesFull(token, Long.MAX_VALUE) == null) return false
  if (backtickTokenHasChainedShellOperators(token)) return true
  val appendedClause = backtickPairAppendedClause(content, start, end)
  if (!backtickPairGlued(content, start, end) && !appendedClause) return false
  if (backtickTokenIsImplausibleSqlIdentifier(token)) return true
  val window = backtickPairContextWindow(content, start, end)
  if (SHELL_METACHARACTER_WINDOW_RE.search(window, 0, Long.MAX_VALUE) != null) return true
  if (strongSqlKeywordGluedToPair(content, start, end)) return false
  val normalized = context.split(":", limit = 2)[0]
  return normalized in AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS || appendedClause
}

/** _dollar_substitution_token_is_implausible. */
public fun dollarSubstitutionTokenIsImplausible(token: String, delimiter: Char): Boolean {
  val stripped = token.trim().lowercase()
  if (stripped in SHELL_SPECIAL_PARAMETER_NAMES) return true
  if (delimiter == '{') {
    val trimmed = token.trim()
    return BARE_SHELL_PARAMETER_NAME_RE.matchesFull(trimmed, Long.MAX_VALUE) == null
  }
  return IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE.search(token, 0, Long.MAX_VALUE) != null
}

private fun dollarSubstitutionPairBacktickQuoted(
    content: String,
    start: Int,
    end: Int,
): Boolean {
  val prefixQuoted = start > 0 && content[start - 1] == '`'
  val suffixQuoted = end < content.length && content[end] == '`'
  return prefixQuoted || suffixQuoted
}

/** _dollar_substitution_pair_is_injection. */
public fun dollarSubstitutionPairIsInjection(match: PyReMatch, context: String): Boolean {
  val content = match.subject()
  val start = match.charStart()
  val end = match.charEnd()
  if (dollarSubstitutionPairBacktickQuoted(content, start, end)) return false
  val delimiter = content[start + 1]
  val token = content.substring(start + 2, end - 1)
  if (dollarSubstitutionTokenIsImplausible(token, delimiter)) return true
  if (strongSqlKeywordGluedToPair(content, start, end)) return false
  return context.split(":", limit = 2)[0] in AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS
}

private val quoteSplitRe = Regex("['\"]+")

/** _quote_splice_token_is_dangerous_command. */
public fun quoteSpliceTokenIsDangerousCommand(match: PyReMatch): Boolean {
  var run = 0
  for (fragment in quoteSplitRe.split(match.group())) {
    run = if (fragment.length == 1) run + 1 else 0
    if (run >= 3) return true
  }
  return false
}

private val GLOB_WILDCARD_COMMAND_BOUNDARY_PREFIX_RE: PyRePattern =
    PyRe.compile("(?:;|\\|\\||\\||&&|\\$\\(|`)\\s*\\Z", 0)
private val GLOB_WILDCARD_VALUE_START_CONTEXTS: Set<String> = setOf("request_body")
private val GLOB_WILDCARD_LETTER_RE: PyRePattern = PyRe.compile("[A-Za-z]", 0)
private const val GLOB_WILDCARD_COMMAND_SUFFIX_CHARS = " \t\r\n;|&"

private fun globWildcardTokenIsWordShaped(token: String): Boolean {
  for (wildcard in GLOB_WILDCARD_CHAR_RE.finditer(token, Long.MAX_VALUE)) {
    val index = wildcard.charStart()
    var left = 0
    var position = index - 1
    while (
        position >= 0 &&
            GLOB_WILDCARD_LETTER_RE.matchAt(token, position, token.length, Long.MAX_VALUE) != null
    ) {
      left++
      position--
    }
    var right = 0
    position = index + 1
    while (
        position < token.length &&
            GLOB_WILDCARD_LETTER_RE.matchAt(token, position, token.length, Long.MAX_VALUE) != null
    ) {
      right++
      position++
    }
    if (left + right >= 2) return true
  }
  return false
}

/** _glob_wildcard_token_is_dangerous_command. */
public fun globWildcardTokenIsDangerousCommand(
    match: PyReMatch,
    context: String = "unknown",
): Boolean {
  if (!globWildcardTokenIsWordShaped(match.group())) return false
  val text = match.subject()
  val suffix = text.substring(match.charEnd(), minOf(match.charEnd() + 1, text.length))
  if (suffix.isNotEmpty() && suffix[0] !in GLOB_WILDCARD_COMMAND_SUFFIX_CHARS) return false
  val prefix = text.substring(0, match.charStart())
  if (GLOB_WILDCARD_COMMAND_BOUNDARY_PREFIX_RE.search(prefix, 0, Long.MAX_VALUE) != null)
      return true
  if (context in GLOB_WILDCARD_VALUE_START_CONTEXTS) {
    return prefix.isBlank()
  }
  return false
}
