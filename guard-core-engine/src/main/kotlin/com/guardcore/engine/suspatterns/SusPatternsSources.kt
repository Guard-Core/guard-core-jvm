package com.guardcore.engine.suspatterns

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyRePattern

/**
 * Pattern source constants, context maps, and the anomaly/scoring helpers.
 *
 * Port of guard_core/handlers/_suspatterns_sources.py.
 */
public const val DEFAULT_MAX_SCAN_LENGTH: Int = 10000
public const val DEFAULT_COMPILER_TIMEOUT: Double = 2.0
public const val DEFAULT_MAX_BODY_INSPECT_BYTES: Int = 262144

/** _regex_anomaly: sum of threat weights. */
public fun regexAnomaly(regexThreats: List<Threat>): Double = regexThreats.sumOf { it.weight }

public val ENHANCED_CONFIG_REQUIRED_ATTRS: List<String> =
    listOf(
        "detection_compiler_timeout",
        "detection_max_tracked_patterns",
        "detection_max_content_length",
        "detection_preserve_attack_patterns",
        "detection_anomaly_threshold",
        "detection_slow_pattern_threshold",
        "detection_monitor_history_size",
        "detection_anomaly_emission_cooldown",
        "detection_min_samples_for_anomaly",
        "detection_semantic_threshold",
        "detection_threat_score_threshold",
    )

/** Context sets (python frozensets). */
public val CTX_XSS: Set<String> =
    setOf("query_param", "header", "request_body", "url_path", "unknown")
public val CTX_SQLI: Set<String> =
    setOf("query_param", "header", "request_body", "url_path", "unknown")
public val CTX_SQLI_NARROW: Set<String> = setOf("query_param", "request_body", "unknown")
public val CTX_DIR_TRAVERSAL: Set<String> =
    setOf("url_path", "query_param", "header", "request_body", "unknown")
public val CTX_CMD_INJECTION: Set<String> =
    setOf("query_param", "header", "request_body", "unknown")
public val CTX_FILE_INCLUSION: Set<String> =
    setOf("url_path", "query_param", "header", "request_body", "unknown")
public val CTX_LDAP: Set<String> =
    setOf("query_param", "header", "url_path", "request_body", "unknown")
public val CTX_XML: Set<String> =
    setOf("header", "request_body", "unknown", "query_param", "url_path")
public val CTX_SSRF: Set<String> =
    setOf("query_param", "header", "request_body", "url_path", "unknown")
public val CTX_NOSQL: Set<String> =
    setOf("query_param", "header", "url_path", "request_body", "unknown")
public val CTX_FILE_UPLOAD: Set<String> = setOf("header", "query_param", "request_body", "unknown")
public val CTX_PATH_TRAVERSAL: Set<String> =
    setOf("url_path", "query_param", "header", "request_body", "unknown")
public val CTX_TEMPLATE: Set<String> =
    setOf("query_param", "header", "request_body", "url_path", "unknown")
public val CTX_HTTP_SPLIT: Set<String> =
    setOf("header", "query_param", "url_path", "request_body", "unknown")
public val CTX_SENSITIVE_FILE: Set<String> =
    setOf("url_path", "query_param", "request_body", "unknown")
public const val EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX: String = ":embedded_json"

/** _source_extension_path_is_probe. */
public fun sourceExtensionPathIsProbe(context: String): Boolean =
    !context.endsWith(EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX)

public val CTX_CMS_PROBING: Set<String> =
    setOf("url_path", "query_param", "request_body", "unknown")
public val CTX_RECON: Set<String> = setOf("url_path", "query_param", "request_body", "unknown")
private val RECON_BARE_PATH_CONTEXTS: Set<String> = setOf("url_path", "unknown")

/** _recon_path_value_is_probe. */
public fun reconPathValueIsProbe(
    match: com.guardcore.engine.py.PyReMatch,
    context: String,
): Boolean =
    context.split(":", limit = 2)[0] in RECON_BARE_PATH_CONTEXTS ||
        match.group().startsWith("/") ||
        match.group().startsWith("\\")

public val CTX_PROTO_POLLUTION: Set<String> =
    setOf("query_param", "header", "url_path", "request_body", "unknown")
public val CTX_CODE_INJECTION: Set<String> =
    setOf("query_param", "header", "url_path", "request_body", "unknown")
public val CTX_DESERIALIZATION: Set<String> =
    setOf("query_param", "header", "url_path", "request_body", "unknown")
public val CTX_ALL: Set<String> =
    setOf("query_param", "header", "url_path", "request_body", "unknown")

public val ALL_DETECTION_CATEGORIES: Set<String> =
    setOf(
        "xss",
        "sqli",
        "dir_traversal",
        "path_traversal",
        "cmd_injection",
        "file_inclusion",
        "ldap",
        "xml",
        "ssrf",
        "nosql",
        "file_upload",
        "template",
        "http_split",
        "sensitive_file",
        "cms_probing",
        "recon",
        "proto_pollution",
        "code_injection",
        "deserialization",
    )

public val CATEGORY_CONTEXT_MAP: Map<String, Set<String>> =
    mapOf(
        "xss" to CTX_XSS,
        "sqli" to CTX_SQLI,
        "dir_traversal" to CTX_DIR_TRAVERSAL,
        "path_traversal" to CTX_PATH_TRAVERSAL,
        "cmd_injection" to CTX_CMD_INJECTION,
        "file_inclusion" to CTX_FILE_INCLUSION,
        "ldap" to CTX_LDAP,
        "xml" to CTX_XML,
        "ssrf" to CTX_SSRF,
        "nosql" to CTX_NOSQL,
        "file_upload" to CTX_FILE_UPLOAD,
        "template" to CTX_TEMPLATE,
        "http_split" to CTX_HTTP_SPLIT,
        "sensitive_file" to CTX_SENSITIVE_FILE,
        "cms_probing" to CTX_CMS_PROBING,
        "recon" to CTX_RECON,
        "proto_pollution" to CTX_PROTO_POLLUTION,
        "code_injection" to CTX_CODE_INJECTION,
        "deserialization" to CTX_DESERIALIZATION,
    )

public const val SELECT_FROM_RE: String =
    "(?i)\\bSELECT\\b(?:(?!\\bSELECT\\b)[\\w\\s,\\*().])*?\\bFROM\\b"
public const val SELECT_STAR_RE: String = "(?i)SELECT\\s+\\*"
public const val WHERE_CLAUSE_RE: String = "(?i)\\bWHERE\\s+[\\w.\"]+\\s*(?:=|<|>|<=|>=|LIKE|IN)\\b"
public const val SQLI_TAUTOLOGY_RE: String =
    "(?i)\\b(?:OR|AND)\\s*(\\d+|'[^']*'|\\\"[^\\\"]*\\\"|[@:\$][A-Za-z_]\\w*)\\s*=\\s*\\1\\b"

public const val PATH_ONLY_CHAR_RE: String = "[\\w.\\-~%]"
public const val PATH_ONLY_SEP_RE: String = "[/\\\\]"
public const val PATH_ONLY_PREFIX_RE: String =
    "\\A$PATH_ONLY_SEP_RE?(?:$PATH_ONLY_CHAR_RE+$PATH_ONLY_SEP_RE)*"
public const val PATH_ONLY_SUFFIX_RE: String =
    "(?:$PATH_ONLY_SEP_RE$PATH_ONLY_CHAR_RE*)*(?:\\?\\S*)?\\s*\\Z"

/** _path_only_pattern. */
public fun pathOnlyPattern(required: String, trailing: String = ""): String =
    "\\A$PATH_ONLY_SEP_RE?" +
        "(?:(?!$required(?:$PATH_ONLY_SEP_RE|\\Z))" +
        "$PATH_ONLY_CHAR_RE+$PATH_ONLY_SEP_RE)*" +
        "$required$trailing$PATH_ONLY_SUFFIX_RE"

/** _path_only_extension_pattern. */
public fun pathOnlyExtensionPattern(required: String): String =
    "\\A$PATH_ONLY_SEP_RE?" +
        "(?:$PATH_ONLY_CHAR_RE+$PATH_ONLY_SEP_RE)*" +
        "$PATH_ONLY_CHAR_RE*$required$PATH_ONLY_SUFFIX_RE"

public val SENSITIVE_SOURCE_EXTENSION_PATH_RE: String =
    pathOnlyExtensionPattern("\\.(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)")

public val RECON_EXTENSION_PATH_RE: String =
    pathOnlyExtensionPattern(
        "\\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do|action|lua|inc|woa|nsf|esp)",
    )

/** _nested_path_pattern. */
public fun nestedPathPattern(required: String): String =
    "\\A$PATH_ONLY_SEP_RE" +
        "(?:(?!$required(?:$PATH_ONLY_SEP_RE|\\Z))" +
        "$PATH_ONLY_CHAR_RE+$PATH_ONLY_SEP_RE)*" +
        "$required$PATH_ONLY_SUFFIX_RE"

private const val ATTACK_REPORT_LEXICON_RE: String =
    "\\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?" +
        "|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?" +
        "|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing" +
        "|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?" +
        "|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked" +
        "|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\\b"

/** _embedded_prose_pattern. */
public fun embeddedProsePattern(required: String, trailingMax: Int = 3): String {
  val trailing = "(?:$PATH_ONLY_SEP_RE$PATH_ONLY_CHAR_RE{1,64})?".repeat(trailingMax)
  val singleLinePrefix = "\\A(?:(?!\\n).)*"
  return "\\A(?=(?:(?!\\n).)*$ATTACK_REPORT_LEXICON_RE)" +
      "$singleLinePrefix$PATH_ONLY_SEP_RE" +
      "(?:$required)$trailing\\b"
}

public const val TOP_LEVEL_PATH_PREFIX_RE: String = "\\A$PATH_ONLY_SEP_RE?"
public const val TERMINAL_PATH_SUFFIX_RE: String = "(?:[/\\\\])?(?:\\?\\S*)?\\s*\\Z"

public const val LDAP_ATTR_DESC_RE: String =
    "(?::)?(?:[a-zA-Z][\\w.-]*|\\d+(?:\\.\\d+)*)" + "(?:;[\\w.-]+)*(?::[\\w.-]+)*\\s*"

public const val LDAP_ATTR_EXTENSIBLE_MATCH_RE: String = LDAP_ATTR_DESC_RE + ":?="

public const val LDAP_WILDCARD_CHAIN_RE: String =
    "\\*\\)[|&]?\\(+\\s*$LDAP_ATTR_EXTENSIBLE_MATCH_RE"
public val LDAP_BREAKOUT_BACKWARD_BOUNDARY_CHARS: Set<Char> = "\"'\n&".toSet()
public val LDAP_BREAKOUT_FORWARD_BOUNDARY_CHARS: Set<Char> = "\"'\n".toSet()
public const val LDAP_BREAKOUT_LOCAL_SCAN_CHARS: Int = 40

public val LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE: PyRePattern = PyRe.compile("=[^()]+\\*\\s*\\Z", 0)
public val LDAP_BREAKOUT_ATTACK_TOKEN_RE: PyRePattern =
    PyRe.compile("\\*|\\(\\s*[&|!]|\\x00|\\(\\s*\\(|~=|>=|<=", 0)
public val LDAP_FILTER_EXPRESSION_STRUCTURE_RE: PyRePattern = PyRe.compile("[()\"'\\n]", 0)

public const val PROTO_POLLUTION_PROTOTYPE_ASSIGN_RE: String =
    "Object\\.prototype\\.[A-Za-z_\$][\\w\$]*\\s*=(?!=)"
public const val PROTO_POLLUTION_SET_PROTOTYPE_OF_RE: String =
    "\\b(?:Object|Reflect)\\.setPrototypeOf\\s*\\("

public const val XML_XXE_PUBLIC_EXTERNAL_DTD_RE: String =
    "<!DOCTYPE[^>\\[]+PUBLIC[^>\\[]+[\\\"']https?://(?!(?:www\\.)?w3\\.org/)[^\\\"'>]+[\\\"'][^>\\[]*>"

public const val XSS_JS_SCHEME_CTRL_CHAR_RE: String =
    "j[\\t\\r\\n]*a[\\t\\r\\n]*v[\\t\\r\\n]*a[\\t\\r\\n]*s[\\t\\r\\n]*c[\\t\\r\\n]*r[\\t\\r\\n]*i" +
        "[\\t\\r\\n]*p[\\t\\r\\n]*t[\\t\\r\\n]*:\\s*[^\\s]+"

public const val FILE_INCLUSION_JSON_VALUE_RE: String =
    "[\\\"'](?:template|include|tpl|module|layout)[\\\"']\\s*:\\s*[\\\"'](?:https?|ftp)://[^\\s'\\\"<>]+/[^\\s'\\\"<>/]*\\.(?:phtml|php[3-5]?|phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)(?![a-zA-Z0-9])[\\\"']"

public const val SSRF_BARE_METADATA_ALIAS_RE: String =
    "://(?:metadata|instance-data)(?::\\d+)?(?:/|\\s|\$)"

public const val CMD_INJECTION_NODE_CHILD_PROCESS_RE: String =
    "(?:require\\(\\s*[\\\"']child_process[\\\"']\\s*\\)|child_process)\\s*\\.\\s*(?:execSync|spawnSync|spawn|fork)\\s*\\("

public const val CMD_INJECTION_PHP_ASSERT_VARIABLE_RE: String = "\\bassert\\s*\\(\\s*\\\$"
public const val CMD_INJECTION_PYTHON_EXEC_FAMILY_RE: String =
    "\\bos\\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)\\s*\\("

public const val JS_DYNAMIC_EVAL_FUNCTION_CTOR_RE: String =
    "\\b(?:new\\s+)?Function\\s*\\(\\s*[\\\"']"
public const val JS_DYNAMIC_EVAL_BRACKET_RE: String =
    "\\[\\s*[\\\"']eval[\\\"']\\s*\\]\\s*\\(\\s*[\\\"']"
public const val JS_DYNAMIC_EVAL_CTOR_GADGET_RE: String =
    "(?:\\.\\s*constructor|\\[\\s*[\\\"']constructor[\\\"']\\s*\\])\\s*(?:\\.\\s*constructor|\\[\\s*[\\\"']constructor[\\\"']\\s*\\])\\s*\\(\\s*[\\\"']"

public const val JS_DYNAMIC_EVAL_TIMER_STRING_ARG_RE: String =
    "\\b(?:setTimeout|setInterval)\\s*\\(\\s*[\\\"']"

public const val LDAP_PAREN_CONJUNCTION_RE: String = "\\(\\s*[&|]\\s*"

public val LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE: PyRePattern =
    PyRe.compile("\\A\\s*(?:[!(]|\\*)", 0)
public val LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE: PyRePattern =
    PyRe.compile("\\A\\s*$LDAP_ATTR_EXTENSIBLE_MATCH_RE", 0)

public const val LDAP_WILDCARD_EQUALS_RE: String =
    "\\*\\s*\\)+\\s*(?:[|&!]\\s*)?\\(+\\s*(?:[&|!]|$LDAP_ATTR_EXTENSIBLE_MATCH_RE)"

public const val LDAP_PAREN_BREAKOUT_RE: String =
    "\\)\\s*\\(\\s*(?:[&|!]|$LDAP_ATTR_DESC_RE:?[=~<>])"

public const val SINGLE_LINE_PREFIX_RE: String = "\\A(?:(?!\\n).)*"
public const val SINGLE_LINE_SUFFIX_RE: String = "(?:[&#;,\\\"'<>]|\\s*\\Z)"

public const val FILE_INCLUSION_HOST_LABEL_RE: String = "[0-9a-zA-Z](?:[-\\w]*[0-9a-zA-Z])?"
public const val FILE_INCLUSION_BARE_HOST_RE: String =
    "(?:(?<!:)\\/\\/[0-9a-zA-Z](?:[-\\w]*[0-9a-zA-Z])?(?:\\.[0-9a-zA-Z](?:[-\\w]*[0-9a-zA-Z])?)+(:[0-9]+)?(?:\\/?)(?:[a-zA-Z0-9\\-\\.\\?,'/\\\\\\+&amp;%\\\$#_]*)?)"

public const val LDAP_NULL_BYTE_ATTR_RE: String =
    "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)"

public const val LDAP_NULL_BYTE_BARE_RE: String = "\\*\\)\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)"

public const val LDAP_NULL_BYTE_DECODED_ATTR_RE: String =
    "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+\\x00"
public const val LDAP_NULL_BYTE_DECODED_BARE_RE: String = "\\*\\)\\)+\\x00"

public val LDAP_NULL_BYTE_ATTR_COMPILED_RE: PyRePattern =
    PyRe.compile(LDAP_NULL_BYTE_ATTR_RE, PyReFlags.IGNORECASE)
public val LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE: PyRePattern =
    PyRe.compile(LDAP_NULL_BYTE_DECODED_ATTR_RE, PyReFlags.IGNORECASE)
public val LDAP_NULL_BYTE_TAIL_RE: PyRePattern =
    PyRe.compile("\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)", 0)
public val LDAP_NULL_BYTE_DECODED_TAIL_RE: PyRePattern = PyRe.compile("\\*\\)+\\x00", 0)
public val LDAP_NULL_BYTE_VALUE_CHAR_RE: PyRePattern = PyRe.compile("[\\d\\w\\s]", 0)
public val LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE: PyRePattern = PyRe.compile("[\\w-]", 0)
public val LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE: PyRePattern = PyRe.compile("[a-zA-Z]", 0)

public const val HTTP_SPLIT_CRLF_RE: String =
    "[\\r\\n][^\\S\\r\\n]*(?:HTTP\\/[0-9.]+|Location:|Set-Cookie:)"

public const val SQLI_ORDER_BY_TERMINATOR_RE: String =
    "(?i)\\bORDER\\s+BY\\s+\\d+\\s*(?:--|#|;|\\)|,|/\\*|\\Z)" +
        "|(?<=[=?&])ORDER\\s+BY\\s+\\d+\\s*\\n"

public const val SQLI_ORDER_BY_STRONG_RE: String =
    "(?i)(?:['\\\")\\d]|/\\*)\\s{0,3}\\bORDER\\s+BY\\s+\\d+|\\bORDER\\s+BY\\s+\\d+\\s*(?:--|#|/\\*)"

public const val SQLI_EXEC_STRONG_RE: String =
    "(?i)(?:\\A|[;'\\\"])\\s*EXEC(?:UTE)?\\s+(?:xp_\\w+|sp_\\w+)"

public const val SQLI_COMMENT_TERMINATOR_RE: String = "'\\s*(?:[\\);]+\\s*)?--|'[\\);]*#(?:\\n|\\Z)"

public const val SQLI_WAITFOR_RE: String =
    "(?i)\\bWAITFOR\\s+(?:DELAY|TIME)\\s+'\\d{1,2}:\\d{1,2}:\\d{1,2}(?:\\.\\d+)?'"

public const val PATH_TRAVERSAL_ENCODED_DOT_RE: String =
    "(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae" + "%e0%80%ae|%25c0%25ae)/"

public const val PATH_TRAVERSAL_SEMICOLON_SEP_RE: String = "\\.\\.;[^/\\\\]*[/\\\\]"
public val PATH_TRAVERSAL_DECODED_SHAPE_RE: PyRePattern = PyRe.compile("\\.\\.[\\\\/]", 0)

public const val CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE: String =
    "\\n[^\\S\\r\\n]*(?:[^=\\s;|&]+=[^\\s;|&]+\\s+)*(?:/?(?:[\\w.-]+/)*env\\s+)?/?(?:[\\w.-]+/)*" +
        "(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-c\\b"

public const val CMD_INJECTION_SHELL_DASH_FLAG_RE: String =
    "(?:\\A|[;|&])\\s*/?(?:[\\w.-]+/)*(?:env\\s+/?(?:[\\w.-]+/)*)?(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-[a-zA-Z]+(?:\\s+(?:'[^']*'|\\\"[^\\\"]*\\\"|[^\\s;|&]+))?(?=\\s*(?:[;|&]|\\Z))"

public const val DIR_TRAVERSAL_ETC_SENSITIVE_RE: String =
    SINGLE_LINE_PREFIX_RE +
        "etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\\.cnf|ssh/ssh_config)" +
        SINGLE_LINE_SUFFIX_RE

public const val DIR_TRAVERSAL_WINDOWS_INI_RE: String =
    SINGLE_LINE_PREFIX_RE +
        "(?:boot\\.ini|win\\.ini|system\\.ini|config\\.sys)" +
        SINGLE_LINE_SUFFIX_RE

public const val DIR_TRAVERSAL_PROC_ENVIRON_RE: String =
    SINGLE_LINE_PREFIX_RE + "proc/self/environ" + SINGLE_LINE_SUFFIX_RE

public const val DIR_TRAVERSAL_VAR_LOG_RE: String =
    SINGLE_LINE_PREFIX_RE + "var/log/[^\\s/]+" + SINGLE_LINE_SUFFIX_RE

public const val SSTI_HASH_BRACE_SHAPE_RE: String =
    "#\\{(?![^\\}]*\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))(?=[^\\}]*(?:@[\\w.]+@|\\b\\w+\\s*\\(|['\\\"]?\\d+['\\\"]?\\s*[*/%+\\-]\\s*['\\\"]?\\d+['\\\"]?))[^\\}]*\\}"

public const val DESERIALIZATION_JAVA_B64_RE: String = "(?<![A-Za-z0-9+/])(?-i:rO0AB)"
public const val DESERIALIZATION_DOTNET_B64_RE: String = "(?<![A-Za-z0-9+/])(?-i:AAEAAAD)"
public const val DESERIALIZATION_PICKLE_B64_RE: String = "(?<![A-Za-z0-9+/])(?-i:gA[SW]V)"
public const val DESERIALIZATION_RUBY_B64_RE: String = "(?<![A-Za-z0-9+/])(?-i:BAh[Jv7bV])"
public const val DESERIALIZATION_PICKLE_OS_GLOBAL_RE: String = "cos\\n"

public const val PICKLE_IDENT_RE: String = "[A-Za-z_][A-Za-z0-9_]{0,100}"
public const val PICKLE_DOTTED_MODULE_RE: String = "$PICKLE_IDENT_RE(?:\\.$PICKLE_IDENT_RE){0,20}"
public const val DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE: String =
    "(c$PICKLE_DOTTED_MODULE_RE\\n$PICKLE_IDENT_RE\\n)[^ \\t]{0,100}?[Rb]"

public const val PICKLE_OPCODE_WORK_BUDGET_BYTES: Int = 4096
