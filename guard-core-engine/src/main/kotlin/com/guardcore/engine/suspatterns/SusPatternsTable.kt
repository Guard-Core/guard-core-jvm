package com.guardcore.engine.suspatterns

/**
 * _PATTERN_DEFINITIONS: the detection pattern table (source, contexts, category), plus the
 * noise-prone and view-membership source sets.
 *
 * Port of guard_core/handlers/_suspatterns_pattern_table.py. Rows are (source, contexts, category)
 * triples; the compiled table attaches at manager construction.
 */
public const val SHELL_KEYWORD_COMMAND_RE: String =
    "[;|&]\\s*(?:ls|cat|rm|id|whoami|uname|wget|curl|nc|netcat|socat|bash|sh|" + "python|perl)\\b"

public val NOISE_PRONE_PATTERN_SOURCES: Set<String> =
    setOf(
        GLUED_BACKTICK_CANDIDATE_RE,
        GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
        CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
        SHELL_KEYWORD_COMMAND_RE,
        QUOTE_SPLICE_CANDIDATE_RE,
        GLOB_WILDCARD_ATOM_RE,
        TEMPLATE_DOLLAR_BRACE_CALL_RE,
        SSTI_HASH_BRACE_SHAPE_RE,
        LDAP_PAREN_CONJUNCTION_RE,
        SQLI_COMMENT_TERMINATOR_RE,
    )

/** The event-handler XSS row (assembled from the tag-open + alternation fragments). */
public const val HTML_EVENT_HANDLER_PATTERN_RE: String =
    "(?:<[A-Za-z/](?:[^<>]*[^<>\\s/])?(?<!=)(?<!=\\\")(" +
        "?<!=')[\\s/]+(?:onwebkitplaybacktargetavailability" +
        "changed|oncontentvisibilityautostatechange|onwebki" +
        "tpresentationmodechanged|onwebkitmouseforcewillbeg" +
        "in|onwebkitanimationiteration|onsecuritypolicyviol" +
        "ation|onwebkitmouseforcechanged|onvalidationstatus" +
        "change|onwebkitfullscreenchange|onwebkitwillreveal" +
        "bottom|onwebkitanimationstart|onwebkitmouseforcedo" +
        "wn|onbeforescriptexecute|onmozfullscreenchange|onw" +
        "ebkittransitionend|onafterscriptexecute|onanimatio" +
        "niteration|onlostpointercapture|onscrollsnapchangi" +
        "ng|onunhandledrejection|onwebkitanimationend|onweb" +
        "kitmouseforceup|ondeviceorientation|ongotpointerca" +
        "pture|onbeforedeactivate|onfullscreenchange|onpoin" +
        "terrawupdate|onreadystatechange|onrejectionhandled" +
        "|onscrollsnapchange|ontransitioncancel|onanimation" +
        "cancel|onbeforeeditfocus|oncontextrestored|ondatas" +
        "etcomplete|onselectionchange|ontransitionstart|ona" +
        "nimationstart|onbeforeactivate|oncanplaythrough|on" +
        "datasetchanged|ondurationchange|onlanguagechange|o" +
        "nlayoutcomplete|onloadedmetadata|onpropertychange|" +
        "oncontrolselect|ondataavailable|ongesturechange|on" +
        "mediacomplete|onpointercancel|onpromptdismiss|ontr" +
        "ansitionend|ontransitionrun|onwebkitneedkey|onanim" +
        "ationend|onbeforetoggle|onbeforeunload|onbeforeupd" +
        "ate|ondevicemotion|onfilterchange|ongesturestart|o" +
        "nmessageerror|onpointerenter|onpointerleave|onprom" +
        "ptaction|onsyncrestored|onvolumechange|onafterupda" +
        "te|onbeforeinput|onbeforematch|onbeforepaste|onbef" +
        "oreprint|oncontextlost|oncontextmenu|onerrorupdate" +
        "|onlosecapture|onpointerdown|onpointermove|onpoint" +
        "erover|onresizestart|onrowinserted|onselectstart|o" +
        "ntouchcancel|ontrackchange|onafterprint|onbeforeco" +
        "py|oncellchange|ondeactivate|ongestureend|onhashch" +
        "ange|onloadeddata|onmediaerror|onmouseenter|onmous" +
        "eleave|onmousewheel|onpagereveal|onpointerout|onra" +
        "techange|onslotchange|ontimeupdate|ontouchstart|on" +
        "beforecut|oncuechange|ondragenter|ondragleave|ondr" +
        "agstart|onloadstart|onmousedown|onmousemove|onmous" +
        "eover|onmovestart|onoutofsync|onpointerup|onresize" +
        "end|onrowdelete|onrowsenter|onscrollend|ontimeerro" +
        "r|ontouchmove|onactivate|onauxclick|ondblclick|ond" +
        "ragdrop|ondragexit|ondragover|onfocusout|onformdat" +
        "a|onkeypress|onlocation|onmouseout|onpagehide|onpa" +
        "geshow|onpageswap|onpopstate|onprogress|ontouchend" +
        "|oncanplay|oncommand|ondragend|onemptied|onfocusin" +
        "|oninvalid|onkeydown|onmessage|onmouseup|onmoveend" +
        "|onoffline|onplaying|onreverse|onrowexit|onseeking" +
        "|onstalled|onstorage|onsuspend|onurlflip|onwaiting" +
        "|onbounce|oncancel|onchange|onfinish|ononline|onre" +
        "peat|onresize|onresume|onscroll|onsearch|onseeked|" +
        "onselect|onsubmit|ontoggle|onunload|onabort|onbegi" +
        "n|onclick|onclose|onended|onerror|onfocus|oninput|" +
        "onkeyup|onpaste|onpause|onreset|onstart|onwheel|on" +
        "blur|oncopy|ondrag|ondrop|onhelp|onload|onmove|onp" +
        "lay|onredo|onseek|onstop|onundo|oncut|onend)\\s*=" +
        "\\s{0,20}(?:[\\\"'][^\\\"']*[\\\"']|[^\\s>]+))"

public const val HTML_SCHEME_PATTERN_RE: String =
    "(?:<[A-Za-z/](?:[^<>]*[^<>\\s])?\\s+(?:href|src|da" +
        "ta|action)\\s*=[\\s\\\"\\']*(?:javascript|vbscript" +
        "|data):)"

public const val HTML_STYLE_PATTERN_RE: String =
    "(?:<[A-Za-z/][^<>]*style\\s*=\\s{0,20}[\\\"']?[^<>\\\"']*(?:expression|behavior|url)\\s*\\([^)]*\\))"

public val PATTERN_DEFINITIONS: List<Triple<String, Set<String>, String>> =
    listOf(
        Triple("<script[^>]*>[^<]*<\\/script\\s*>", CTX_XSS, "xss"),
        Triple("javascript:\\s*[^\\s]+", CTX_XSS, "xss"),
        Triple(XSS_JS_SCHEME_CTRL_CHAR_RE, CTX_XSS, "xss"),
        Triple(HTML_EVENT_HANDLER_PATTERN_RE, CTX_XSS, "xss"),
        Triple(HTML_SCHEME_PATTERN_RE, CTX_XSS, "xss"),
        Triple(HTML_STYLE_PATTERN_RE, CTX_XSS, "xss"),
        Triple("(?:<object[^>]*>[\\s\\S]*<\\/object\\s*>)", CTX_XSS, "xss"),
        Triple("(?:<embed[^>]*>[\\s\\S]*<\\/embed\\s*>)", CTX_XSS, "xss"),
        Triple("(?:<applet[^>]*>[\\s\\S]*<\\/applet\\s*>)", CTX_XSS, "xss"),
        Triple(SELECT_FROM_RE, CTX_SQLI, "sqli"),
        Triple(SELECT_STAR_RE, CTX_SQLI, "sqli"),
        Triple(WHERE_CLAUSE_RE, CTX_SQLI, "sqli"),
        Triple(SQLI_TAUTOLOGY_RE, CTX_SQLI, "sqli"),
        Triple("(?i)UNION\\s+(?:ALL\\s+)?SELECT", CTX_SQLI, "sqli"),
        Triple(
            "(?i)('\\s*(?:OR|AND)[\\s(]*'?(?:[@:\$][A-Za-z_]\\w*|[\\d\\w]+)\\s*" +
                "(?:LIKE|[<>]=?|=)[\\s(]*'?(?:[@:\$][A-Za-z_]\\w*|[\\d\\w]+))",
            CTX_SQLI,
            "sqli",
        ),
        Triple(
            "(?i)(UNION\\s+(?:ALL\\s+)?SELECT\\s+NULL(?:[,\\s]*NULL)*[,\\s]*|" +
                "\\(\\s*SELECT\\s+(?:@@|VERSION))",
            CTX_SQLI,
            "sqli",
        ),
        Triple("(?i)(?:INTO\\s+(?:OUTFILE|DUMPFILE)\\s+'[^']+')", CTX_SQLI, "sqli"),
        Triple(SQLI_LOAD_FILE_RE, CTX_SQLI, "sqli"),
        Triple("(?i)(?:BENCHMARK\\s*\\(\\s*\\d+\\s*,)", CTX_SQLI, "sqli"),
        Triple("(?i)(?:SLEEP\\s*\\(\\s*\\d+\\s*\\))", CTX_SQLI, "sqli"),
        Triple(
            "(?i)(?:\\/\\*![0-9]*\\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|" +
                "CONCAT|CHAR|UPDATE)\\b)",
            CTX_SQLI,
            "sqli",
        ),
        Triple("\\w/\\*(?!!)[^*]*\\*/\\w", CTX_SQLI_NARROW, "sqli"),
        Triple(
            "(?i)(?:OR|AND)\\s+(?:'[\\w\\d]*'='[\\w\\d]*'?|" +
                "[@:\$][A-Za-z_]\\w*\\s*=\\s*[@:\$][A-Za-z_]\\w*)",
            CTX_SQLI,
            "sqli",
        ),
        Triple(
            "(?i);\\s*(?:DROP|TRUNCATE|ALTER|CREATE)\\s+(?:TABLE|DATABASE|SCHEMA)\\b",
            CTX_SQLI,
            "sqli",
        ),
        Triple(
            "(?i);\\s*(?:INSERT\\s+INTO|UPDATE\\s+\\w+\\s+SET|DELETE\\s+FROM|" +
                "SELECT\\b[^;]*?\\bFROM\\b|REPLACE\\s+INTO)\\b",
            CTX_SQLI,
            "sqli",
        ),
        Triple("(?i)\\bEXEC(?:UTE)?\\s+(?:xp_\\w+|sp_\\w+)", CTX_SQLI_NARROW, "sqli"),
        Triple(SQLI_EXEC_STRONG_RE, CTX_SQLI, "sqli"),
        Triple(SQLI_ORDER_BY_TERMINATOR_RE, CTX_SQLI_NARROW, "sqli"),
        Triple(SQLI_ORDER_BY_STRONG_RE, CTX_SQLI, "sqli"),
        Triple(SQLI_COMMENT_TERMINATOR_RE, CTX_SQLI, "sqli"),
        Triple(SQLI_WAITFOR_RE, CTX_SQLI, "sqli"),
        Triple(
            "(?:\\.\\.\\/|\\.\\.\\\\)(?:\\.\\.\\/|\\.\\.\\\\)+",
            CTX_DIR_TRAVERSAL,
            "dir_traversal",
        ),
        Triple(DIR_TRAVERSAL_ETC_SENSITIVE_RE, CTX_DIR_TRAVERSAL, "dir_traversal"),
        Triple(
            embeddedProsePattern(
                "etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\\.cnf" + "|ssh/ssh_config)",
            ),
            CTX_DIR_TRAVERSAL,
            "dir_traversal",
        ),
        Triple(DIR_TRAVERSAL_WINDOWS_INI_RE, CTX_DIR_TRAVERSAL, "dir_traversal"),
        Triple(DIR_TRAVERSAL_PROC_ENVIRON_RE, CTX_DIR_TRAVERSAL, "dir_traversal"),
        Triple(DIR_TRAVERSAL_VAR_LOG_RE, CTX_DIR_TRAVERSAL, "dir_traversal"),
        Triple(PATH_TRAVERSAL_SEMICOLON_SEP_RE, CTX_DIR_TRAVERSAL, "dir_traversal"),
        Triple(
            ";\\s*(?:ls|cat|rm|chmod|chown|wget|curl|nc|netcat|ping|telnet)\\s+" + "-[a-zA-Z]+\\s+",
            CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        Triple(
            "\\|\\s*(?:wget|curl|fetch|lwp-download|lynx|links|GET)\\s+",
            CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        Triple(CMD_INJECTION_DOLLAR_SUBSTITUTION_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(
            "\\A\\s*(?:[;&|]\\s*)*`\\s*(?:[A-Za-z0-9_./~]|\\$[({])" +
                "(?:[^`\\\\\\n]|\\\\.)*(?:\\n\\s*)?`" +
                "(?:\\s*[;&|]\\s*`\\s*(?:[A-Za-z0-9_./~]|\\$[({])" +
                "(?:[^`\\\\\\n]|\\\\.)*(?:\\n\\s*)?`)*" +
                "\\s*(?:[;&|]\\s*)*\\Z",
            CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        Triple(GLUED_BACKTICK_CANDIDATE_RE, CTX_CMD_INJECTION_WITH_URL_PATH, "cmd_injection"),
        Triple(
            GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
            CTX_CMD_INJECTION_WITH_URL_PATH,
            "cmd_injection",
        ),
        Triple(LOG4SHELL_JNDI_LOOKUP_RE, CTX_LOG4SHELL, "cmd_injection"),
        Triple(CMD_INJECTION_SHELL_DASH_FLAG_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(
            "(?:\\A|[;|&])\\s*[^=\\s;|&]+=[^\\s;|&]+\\s+(?:/?(?:[\\w.-]+/)*env\\s+)?/?(?:[\\w.-]+/)*" +
                "(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-[a-zA-Z]+",
            CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        Triple(CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(
            "\\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open|create_function)\\s*\\(",
            CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        Triple(CMD_INJECTION_NODE_CHILD_PROCESS_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(CMD_INJECTION_PHP_ASSERT_VARIABLE_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(CMD_INJECTION_PYTHON_EXEC_FAMILY_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(JS_DYNAMIC_EVAL_FUNCTION_CTOR_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(JS_DYNAMIC_EVAL_BRACKET_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(JS_DYNAMIC_EVAL_CTOR_GADGET_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(JS_DYNAMIC_EVAL_TIMER_STRING_ARG_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(SHELL_KEYWORD_COMMAND_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(
            "(?i)\\b(?:nc|netcat|ncat)\\s+-[a-z]*e\\b|/dev/tcp/\\d",
            CTX_CMD_INJECTION,
            "cmd_injection",
        ),
        Triple(BRACE_EXPANSION_COMMAND_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(QUOTE_SPLICE_CANDIDATE_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(GLOB_WILDCARD_ATOM_RE, CTX_CMD_INJECTION, "cmd_injection"),
        Triple(
            "(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|" +
                "rar|ogg|expect)://[^\\s]+",
            CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        Triple(FILE_INCLUSION_BARE_HOST_RE, CTX_FILE_INCLUSION, "file_inclusion"),
        Triple(
            "=(?:https?|ftp):\\/\\/[^\\s'\\\"<>]+\\/[^\\s'\\\"<" +
                ">\\/]*\\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|t" +
                "xt|inc)(?![a-zA-Z0-9])",
            CTX_FILE_INCLUSION,
            "file_inclusion",
        ),
        Triple(FILE_INCLUSION_JSON_VALUE_RE, CTX_FILE_INCLUSION, "file_inclusion"),
        Triple("\\([\\s]*[|&][\\s]*\\([^)(]+=[*]", CTX_LDAP, "ldap"),
        Triple(LDAP_WILDCARD_EQUALS_RE, CTX_LDAP, "ldap"),
        Triple(LDAP_PAREN_BREAKOUT_RE, CTX_LDAP, "ldap"),
        Triple(LDAP_PAREN_CONJUNCTION_RE, CTX_LDAP, "ldap"),
        Triple(LDAP_WILDCARD_CHAIN_RE, CTX_LDAP, "ldap"),
        Triple(LDAP_NULL_BYTE_ATTR_RE, CTX_LDAP, "ldap"),
        Triple(LDAP_NULL_BYTE_BARE_RE, CTX_LDAP, "ldap"),
        Triple(LDAP_NULL_BYTE_DECODED_ATTR_RE, CTX_LDAP, "ldap"),
        Triple(LDAP_NULL_BYTE_DECODED_BARE_RE, CTX_LDAP, "ldap"),
        Triple("<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", CTX_XML, "xml"),
        Triple(XML_XXE_PUBLIC_EXTERNAL_DTD_RE, CTX_XML, "xml"),
        Triple("(?:<!\\[CDATA\\[.*?\\]\\]>)", CTX_XML, "xml"),
        Triple("<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY", CTX_XML, "xml"),
        Triple(
            "(?:^|\\s|/)(?:(?<=://)[^\\s/@]*@)?(?:localhost\\.?|127\\.0\\.0\\.1|0\\.0\\.0\\.0|" +
                "\\[::(?:\\d*)\\]|\\[::ffff:127\\.0\\.0\\.1\\]|169\\.254(?:\\.\\d{1,3}){2}|" +
                "192\\.168(?:\\.\\d{1,3}){2}|" +
                "10(?:\\.\\d{1,3}){3}|172\\.(?:1[6-9]|2[0-9]|3[01])(?:\\.\\d{1,3}){2}|" +
                "metadata\\.google\\.internal|metadata\\.goog|100\\.100\\.100\\.200)" +
                "(?::\\d+)?(?:\\s|\$|/)",
            CTX_SSRF,
            "ssrf",
        ),
        Triple(LEGACY_IPV4_HOST_RE, CTX_SSRF, "ssrf"),
        Triple("(?:file|dict|gopher|jar|tftp)://[^\\s]+", CTX_SSRF, "ssrf"),
        Triple("://[^/\\s@]*@[^/\\s@]*@", CTX_SSRF, "ssrf"),
        Triple(SSRF_BARE_METADATA_ALIAS_RE, CTX_SSRF, "ssrf"),
        Triple(
            "\\{\\s*\\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|" + "options):",
            CTX_NOSQL,
            "nosql",
        ),
        Triple("(?:\\{\\s*\\$[a-zA-Z]+\\s*:\\s*(?:\\{|\\[))", CTX_NOSQL, "nosql"),
        Triple(
            "\"\\$(?:where|regex|expr|jsonSchema|function|accumulator|type|exists|size)\"\\s*:",
            CTX_NOSQL,
            "nosql",
        ),
        Triple(
            "\"\\$(?:gt|gte|lt|lte|ne|eq|in|nin|all|mod)\"\\s*:\\s*(?:\"\"|null|\\{|\\[)",
            CTX_NOSQL,
            "nosql",
        ),
        Triple(
            "\"[^\"]+\"\\s*:\\s*\\{\\s*\"\\$(?:ne|eq)\"\\s*:\\s*(?:true|false)",
            CTX_NOSQL,
            "nosql",
        ),
        Triple(
            "\\[\\$(?:where|gt|gte|lt|lte|ne|eq|regex|in|nin|nor|and|or|not|all|" +
                "size|exists|type|mod|options|expr|function|elemMatch)\\]",
            CTX_NOSQL,
            "nosql",
        ),
        Triple(SusPatternsFileUpload.DANGEROUS_EXTENSION_RE, CTX_FILE_UPLOAD, "file_upload"),
        Triple(SusPatternsFileUpload.DOUBLE_EXTENSION_RE, CTX_FILE_UPLOAD, "file_upload"),
        Triple(SusPatternsFileUpload.TRUNCATION_RE, CTX_FILE_UPLOAD, "file_upload"),
        Triple(SusPatternsFileUpload.DECODED_TRUNCATION_RE, CTX_FILE_UPLOAD, "file_upload"),
        Triple(PATH_TRAVERSAL_ENCODED_DOT_RE, CTX_PATH_TRAVERSAL, "path_traversal"),
        Triple(TEMPLATE_CURLY_KEYWORD_RE, CTX_TEMPLATE, "template"),
        Triple(TEMPLATE_PERCENT_KEYWORD_RE, CTX_TEMPLATE, "template"),
        Triple(TEMPLATE_ASP_KEYWORD_RE, CTX_TEMPLATE, "template"),
        Triple(TEMPLATE_DOLLAR_BRACE_CALL_RE, CTX_TEMPLATE, "template"),
        Triple(TEMPLATE_CURLY_CALL_RE, CTX_TEMPLATE, "template"),
        Triple(SSTI_HASH_BRACE_SHAPE_RE, CTX_TEMPLATE, "template"),
        Triple(HTTP_SPLIT_CRLF_RE, CTX_HTTP_SPLIT, "http_split"),
        Triple(pathOnlyPattern("\\.env(?:\\.\\w+)?"), CTX_SENSITIVE_FILE, "sensitive_file"),
        Triple(embeddedProsePattern("\\.env(?:\\.\\w+)?"), CTX_SENSITIVE_FILE, "sensitive_file"),
        Triple(
            pathOnlyPattern(
                "(?:(?!config)[\\w-])*config[\\w-]*\\.(?:env|yml|yaml|json|toml|ini|xml|conf)",
            ),
            CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        Triple(pathOnlyPattern("$PATH_ONLY_CHAR_RE*\\.map"), CTX_SENSITIVE_FILE, "sensitive_file"),
        Triple(SENSITIVE_SOURCE_EXTENSION_PATH_RE, CTX_SENSITIVE_FILE, "sensitive_file"),
        Triple(pathOnlyPattern("\\.(?:git|svn|hg|bzr)"), CTX_SENSITIVE_FILE, "sensitive_file"),
        Triple(embeddedProsePattern("\\.(?:git|svn|hg|bzr)"), CTX_SENSITIVE_FILE, "sensitive_file"),
        Triple(
            PATH_ONLY_PREFIX_RE + "$PATH_ONLY_CHAR_RE*\\.\\w+~(?:\\?\\S*)?\\s*\\Z",
            CTX_SENSITIVE_FILE,
            "sensitive_file",
        ),
        Triple(
            pathOnlyPattern(
                "(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)" +
                    "\\.?(?:php)?",
            ),
            CTX_CMS_PROBING,
            "cms_probing",
        ),
        Triple(
            embeddedProsePattern(
                "(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)" +
                    "\\.?(?:php)?",
            ),
            CTX_CMS_PROBING,
            "cms_probing",
        ),
        Triple(
            pathOnlyPattern("(?:phpinfo|info|test|php_info)\\.php"),
            CTX_CMS_PROBING,
            "cms_probing",
        ),
        Triple(
            embeddedProsePattern("(?:phpinfo|info|test|php_info)\\.php"),
            CTX_CMS_PROBING,
            "cms_probing",
        ),
        Triple(
            pathOnlyPattern("$PATH_ONLY_CHAR_RE*\\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)"),
            CTX_CMS_PROBING,
            "cms_probing",
        ),
        Triple(
            pathOnlyPattern(
                "(?:\\.htaccess|\\.htpasswd|\\.DS_Store|Thumbs\\.db" +
                    "|\\.npmrc|\\.dockerenv|web\\.config)",
            ),
            CTX_CMS_PROBING,
            "cms_probing",
        ),
        Triple(
            embeddedProsePattern(
                "(?:\\.htaccess|\\.htpasswd|\\.DS_Store|Thumbs\\.db" +
                    "|\\.npmrc|\\.dockerenv|web\\.config)",
            ),
            CTX_CMS_PROBING,
            "cms_probing",
        ),
        Triple(RECON_EXTENSION_PATH_RE, CTX_RECON, "recon"),
        Triple(
            nestedPathPattern(
                "(?:management|config_dump|credentials|system${PATH_ONLY_SEP_RE}version" +
                    "|version${PATH_ONLY_SEP_RE}system)",
            ),
            CTX_RECON,
            "recon",
        ),
        Triple(
            "\\A$PATH_ONLY_SEP_RE(?:system|version)" + PATH_ONLY_SUFFIX_RE,
            CTX_RECON,
            "recon",
        ),
        Triple(pathOnlyPattern("(?:actuator|server-status|telescope)"), CTX_RECON, "recon"),
        Triple(
            "(?:CSCOE|dana-(?:na|cached)|sslvpn|RDWeb|/owa/|/ecp/" +
                "|global-protect|ssl-vpn/|svpn/|sonicui|/remote/login" +
                "|myvpn|vpntunnel|versa/login)",
            CTX_RECON,
            "recon",
        ),
        Triple(
            pathOnlyPattern(
                "(?:geoserver|confluence|nifi|ScadaBR|pandora_console" +
                    "|centreon|kylin|decisioncenter|evox|MagicInfo|metasys" +
                    "|officescan|helpdesk|ignite)",
                trailing = "(?:[.\\-]$PATH_ONLY_CHAR_RE*)?",
            ),
            CTX_RECON,
            "recon",
        ),
        Triple(pathOnlyPattern("cgi-(?:bin|mod)"), CTX_RECON, "recon"),
        Triple(pathOnlyPattern("(?:HNAP1|IPCamDesc\\.xml|SDK/webLanguage)"), CTX_RECON, "recon"),
        Triple(pathOnlyPattern("(?:language|languages)"), CTX_RECON, "recon"),
        Triple(
            pathOnlyPattern(
                "(?:readme\\.txt|README\\.md|CHANGELOG|pom\\.xml" +
                    "|build\\.gradle|appsettings\\.json|crossdomain\\.xml)",
                trailing = "(?:\\.$PATH_ONLY_CHAR_RE*)?",
            ),
            CTX_RECON,
            "recon",
        ),
        Triple(
            pathOnlyPattern(
                "(?:sap|ise|nidp|cslu|rustfs|developmentserver" +
                    "|fog/management|lms/db|json/login_session|sms_mp" +
                    "|plugin/webs_model|wsman|am_bin)",
            ),
            CTX_RECON,
            "recon",
        ),
        Triple("(?:nmaplowercheck|nice\\s+ports|Trinity\\.txt)", CTX_RECON, "recon"),
        Triple(pathOnlyPattern("\\.(?:openclaw|clawdbot)"), CTX_RECON, "recon"),
        Triple(
            TOP_LEVEL_PATH_PREFIX_RE +
                "(?:default|inicio|indice|localstart)" +
                "(?:\\.$PATH_ONLY_CHAR_RE*)?" +
                TERMINAL_PATH_SUFFIX_RE,
            CTX_RECON,
            "recon",
        ),
        Triple(pathOnlyPattern("inicio\\.html?"), CTX_RECON, "recon"),
        Triple(
            pathOnlyPattern(
                "(?:\\.streamlit|\\.gpt-pilot|\\.aider|\\.cursor" +
                    "|\\.windsurf|\\.copilot|\\.devcontainer)",
            ),
            CTX_RECON,
            "recon",
        ),
        Triple(
            pathOnlyPattern(
                "(?:docker-compose|Dockerfile|Makefile|Vagrantfile" +
                    "|Jenkinsfile|Procfile)(?:\\.ya?ml)?",
            ),
            CTX_RECON,
            "recon",
        ),
        Triple(
            pathOnlyPattern(
                "$PATH_ONLY_CHAR_RE*(?:secrets?|credentials?)" +
                    "\\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)",
            ),
            CTX_RECON,
            "recon",
        ),
        Triple(pathOnlyPattern("autodiscover"), CTX_RECON, "recon"),
        Triple(pathOnlyPattern("dns-query"), CTX_RECON, "recon"),
        Triple(pathOnlyPattern("\\.git/(?:refs|index|HEAD|objects|logs)"), CTX_RECON, "recon"),
        Triple(
            "(?:__proto__|constructor)\\s*(?:\\[\\s*[\\\"']prot" +
                "otype[\\\"']\\s*\\]|\\.\\s*prototype)|[\\\"']__pro" +
                "to__[\\\"']\\s*:",
            CTX_PROTO_POLLUTION,
            "proto_pollution",
        ),
        Triple(
            "__proto__\\s*(?:\\[|\\.)|\\[\\s*[\\\"']?__proto__[" +
                "\\\"']?\\s*\\]|constructor\\s*\\[\\s*[\\\"']?proto" +
                "type[\\\"']?\\s*\\]|\\[\\s*[\\\"']?constructor[" +
                "\\\"']?\\s*\\]\\s*\\[\\s*[\\\"']?prototype[\\\"']?" +
                "\\s*\\]",
            CTX_PROTO_POLLUTION,
            "proto_pollution",
        ),
        Triple(PROTO_POLLUTION_PROTOTYPE_ASSIGN_RE, CTX_PROTO_POLLUTION, "proto_pollution"),
        Triple(PROTO_POLLUTION_SET_PROTOTYPE_OF_RE, CTX_PROTO_POLLUTION, "proto_pollution"),
        Triple(
            "System\\.Diagnostics\\.Process\\.Start\\s*\\(|System\\.Reflection\\.|Assembly\\.Load\\s*\\(",
            CTX_CODE_INJECTION,
            "code_injection",
        ),
        Triple(PY_GETATTR_INDIRECTION_RE, CTX_CODE_INJECTION, "code_injection"),
        Triple(PY_VARS_INDIRECTION_RE, CTX_CODE_INJECTION, "code_injection"),
        Triple(DESERIALIZATION_JAVA_B64_RE, CTX_DESERIALIZATION, "deserialization"),
        Triple(DESERIALIZATION_DOTNET_B64_RE, CTX_DESERIALIZATION, "deserialization"),
        Triple(DESERIALIZATION_PICKLE_B64_RE, CTX_DESERIALIZATION, "deserialization"),
        Triple(DESERIALIZATION_RUBY_B64_RE, CTX_DESERIALIZATION, "deserialization"),
        Triple(DESERIALIZATION_PICKLE_OS_GLOBAL_RE, CTX_DESERIALIZATION, "deserialization"),
        Triple("c__builtin__", CTX_DESERIALIZATION, "deserialization"),
        Triple("csubprocess", CTX_DESERIALIZATION, "deserialization"),
        Triple("cposix", CTX_DESERIALIZATION, "deserialization"),
        Triple(DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE, CTX_DESERIALIZATION, "deserialization"),
        Triple("O:\\d+:\"", CTX_DESERIALIZATION, "deserialization"),
        Triple("C:\\d+:\"", CTX_DESERIALIZATION, "deserialization"),
        Triple("E:\\d+:\"", CTX_DESERIALIZATION, "deserialization"),
        Triple("<ObjectDataProvider\\b", CTX_DESERIALIZATION, "deserialization"),
    )

/** RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES. */
public val RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES: Set<String> =
    PATTERN_DEFINITIONS.filter { (_, _, category) -> category == "recon" }
        .map { (source, _, _) -> source }
        .filter { it.startsWith(TOP_LEVEL_PATH_PREFIX_RE) }
        .toSet()

/** DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES. */
public val DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES: Set<String> =
    PATTERN_DEFINITIONS.filter { (_, _, category) -> category == "recon" }
        .map { (source, _, _) -> source }
        .toSet()
