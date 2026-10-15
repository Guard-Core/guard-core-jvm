package com.guardcore.engine.suspatterns

import com.guardcore.engine.detection.BinaryPrefix
import com.guardcore.engine.detection.ContentPreprocessor
import com.guardcore.engine.detection.PatternCompiler
import com.guardcore.engine.detection.PatternValidationTimeout
import com.guardcore.engine.detection.PyUrllib
import com.guardcore.engine.detection.boundedFinditer
import com.guardcore.engine.detection.looksLikeBinaryContent
import com.guardcore.engine.detection.reportScanSuccess
import com.guardcore.engine.detection.reportScanTimeout
import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyRePattern

private typealias PyReDeadlines = com.guardcore.engine.py.PyRe.DeadlineExceededException

/**
 * SusPatternsManager: the compiled pattern table scan and the detect() verdict pipeline.
 *
 * Port of guard_core/handlers/_suspatterns_regex.py, _suspatterns_views.py,
 * _suspatterns_enhanced.py, _suspatterns_registry.py, and suspatterns_handler.py. The reference
 * runs regex work on a shared thread pool with future timeouts; this port runs inline under the
 * hard match deadline (the Go posture).
 */
public class CompiledPatternRow(
    public val compiled: PyRePattern,
    public val contexts: Set<String>,
    public val category: String,
)

public object SusPatternsWeights {
  public val CATEGORY_WEIGHTS: Map<String, Double> = ALL_DETECTION_CATEGORIES.associateWith { 1.0 }

  public val PATTERN_WEIGHT_OVERRIDES: Map<String, Double> =
      mapOf(
          SELECT_FROM_RE to 0.5,
          SELECT_STAR_RE to 0.5,
          WHERE_CLAUSE_RE to 0.5,
      )

  public fun resolvePatternWeight(pattern: String, category: String): Double {
    PATTERN_WEIGHT_OVERRIDES[pattern]?.let {
      return it
    }
    return CATEGORY_WEIGHTS[category] ?: 1.0
  }
}

public const val DECODE_BUDGET_EXHAUSTED_PATTERN: String = "decode_budget_exhausted"

public fun decodeBudgetExhaustedThreat(): Threat =
    Threat(
        type = "regex",
        pattern = DECODE_BUDGET_EXHAUSTED_PATTERN,
        match = DECODE_BUDGET_EXHAUSTED_PATTERN,
        position = 0,
        executionTime = 0.0,
        category = "custom",
        weight = SusPatternsWeights.resolvePatternWeight(DECODE_BUDGET_EXHAUSTED_PATTERN, "custom"),
    )

/** SEMANTIC_ATTACK_TYPE_TO_CATEGORY. */
public val SEMANTIC_ATTACK_TYPE_TO_CATEGORY: Map<String, String> =
    mapOf(
        "xss" to "xss",
        "sql" to "sqli",
        "command" to "cmd_injection",
        "path" to "path_traversal",
        "template" to "template",
        "suspicious" to "custom",
    )

/** _collect_threat_categories. */
public fun collectThreatCategories(threats: List<Threat>): List<String> {
  val categories = ArrayList<String>()
  for (threat in threats) {
    var category = threat.category
    if (category.isEmpty()) continue
    if (threat.type == "semantic") {
      category = SEMANTIC_ATTACK_TYPE_TO_CATEGORY[category] ?: category
    }
    if (category !in categories) categories.add(category)
  }
  return categories
}

public val CANDIDATE_REJECTION_VALIDATORS: List<Pair<String, (PyReMatch, String) -> Boolean>> =
    listOf(
        Pair(LEGACY_IPV4_HOST_RE) { m, _ -> legacyIpv4MatchIsBlocked(m) },
        Pair(LDAP_WILDCARD_CHAIN_RE) { m, _ -> ldapWildcardChainIsInjection(m) },
        Pair(LDAP_WILDCARD_EQUALS_RE) { m, _ -> ldapWildcardChainIsInjection(m) },
        Pair(LDAP_PAREN_BREAKOUT_RE) { m, _ -> ldapWildcardChainIsInjection(m) },
        Pair(LDAP_PAREN_CONJUNCTION_RE) { m, _ -> ldapParenConjunctionIsInjection(m) },
        Pair(GLUED_BACKTICK_CANDIDATE_RE) { m, ctx -> gluedBacktickPairIsInjection(m, ctx) },
        Pair(SENSITIVE_SOURCE_EXTENSION_PATH_RE) { _, ctx ->
          sourceExtensionPathIsProbe(ctx)
        },
        Pair(GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE) { m, ctx ->
          dollarSubstitutionPairIsInjection(m, ctx)
        },
        Pair(BRACE_EXPANSION_COMMAND_RE) { m, _ -> braceExpansionIsDangerousCommand(m) },
        Pair(QUOTE_SPLICE_CANDIDATE_RE) { m, _ -> quoteSpliceTokenIsDangerousCommand(m) },
        Pair(GLOB_WILDCARD_ATOM_RE) { m, ctx -> globWildcardTokenIsDangerousCommand(m, ctx) },
        Pair(DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE) { m, ctx ->
          pickleGlobalCandidateIsInjection(m, ctx)
        },
    )

public val WINDOWED_PATTERN_FINDERS: Map<String, (String) -> List<PyReMatch>> =
    mapOf(
        CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE to
            { text ->
              cmdInjectionShellDashCFinditer(text, CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE)
            },
        LDAP_NULL_BYTE_ATTR_RE to
            { text ->
              ldapNullByteAttrFinditer(
                  text,
                  LDAP_NULL_BYTE_ATTR_COMPILED_RE,
                  LDAP_NULL_BYTE_TAIL_RE,
              )
            },
        LDAP_NULL_BYTE_DECODED_ATTR_RE to
            { text ->
              ldapNullByteAttrFinditer(
                  text,
                  LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE,
                  LDAP_NULL_BYTE_DECODED_TAIL_RE,
              )
            },
        QUOTE_SPLICE_CANDIDATE_RE to
            { text ->
              quoteSpliceFinditer(text, QUOTE_SPLICE_CANDIDATE_COMPILED_RE)
            },
        DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE to
            { text ->
              pickleGlobalGenericFinditer(text, DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE)
            },
        XML_XXE_PUBLIC_EXTERNAL_DTD_RE to
            { text ->
              SusPatternsXmlXxe.publicExternalDtdFinditer(text)
            },
    )

public val SCAN_WINDOW_BOUND_SOURCES: Map<String, List<Pair<String, String>>> =
    mapOf(
        "<script[^>]*>[^<]*<\\/script\\s*>" to listOf(Pair("<script", "<\\/script\\s*>")),
        "(?:<[A-Za-z/][^<>]*style\\s*=\\s{0,20}[\"']?[^<>\"']*" +
            "(?:expression|behavior|url)\\s*\\([^)]*\\))" to
            listOf(Pair("<[A-Za-z/][^<>]*style\\s*=", "\\)")),
        "(?:<object[^>]*>[\\s\\S]*<\\/object\\s*>)" to listOf(Pair("<object", "<\\/object\\s*>")),
        "(?:<embed[^>]*>[\\s\\S]*<\\/embed\\s*>)" to listOf(Pair("<embed", "<\\/embed\\s*>")),
        "(?:<applet[^>]*>[\\s\\S]*<\\/applet\\s*>)" to listOf(Pair("<applet", "<\\/applet\\s*>")),
        "\\.\\.;[^/\\\\]*[/\\\\]" to listOf(Pair("\\.\\.;", "[/\\\\]")),
        "=(?:https?|ftp):\\/\\/[^\\s'\"<>]+\\/[^\\s'\"<>/]*" +
            "\\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)(?![a-zA-Z0-9])" to
            listOf(
                Pair(
                    "=(?:https?|ftp):\\/\\/",
                    "\\.(?:phtml|php\\d*|phar|jsp|aspx?|pl|py|txt|inc)[a-zA-Z0-9]*",
                ),
            ),
        "<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>" to listOf(Pair("<!(?:ENTITY|DOCTYPE)", ">")),
        "(?:<!\\[CDATA\\[.*?\\]\\]>)" to listOf(Pair("<!\\[CDATA\\[", "\\]\\]>")),
        "<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY" to listOf(Pair("<!DOCTYPE", "<!ENTITY")),
    )

public val SCAN_WINDOW_PATTERNS: Map<String, List<Pair<PyRePattern, PyRePattern>>> =
    SCAN_WINDOW_BOUND_SOURCES.mapValues { (_, pairs) ->
      pairs.map { (prefix, terminator) ->
        Pair(
            PyRe.compile(prefix, PyReFlags.IGNORECASE),
            PyRe.compile(terminator, PyReFlags.IGNORECASE),
        )
      }
    }

/** _iter_scan_window_matches. */
public fun iterScanWindowMatches(
    content: String,
    pattern: PyRePattern,
    bounds: List<Pair<PyRePattern, PyRePattern>>,
): List<PyReMatch> {
  if (pattern.source == "<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>") {
    return SusPatternsXmlXxe.xmlSystemFinditer(content)
  }
  if (pattern.source == "<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY") {
    return SusPatternsXmlXxe.xmlInternalEntityFinditer(content)
  }
  val out = ArrayList<PyReMatch>()
  for ((prefix, terminator) in bounds) {
    out.addAll(boundedFinditer(content, pattern, prefix, terminator))
  }
  return out
}

/** _build_regex_threat, with the rejection validators and binary-density gate. */
public fun buildRegexThreat(
    pattern: PyRePattern,
    match: PyReMatch,
    category: String,
    patternStartNanos: Long,
    context: String = "unknown",
    binaryPrefix: IntArray? = null,
): Threat? {
  for ((candidate, isValidThreat) in CANDIDATE_REJECTION_VALIDATORS) {
    if (pattern.source == candidate && !isValidThreat(match, context)) return null
  }
  if (
      pattern.source in RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES &&
          !reconPathValueIsProbe(match, context)
  ) {
    return null
  }
  if (
      pattern.source in NOISE_PRONE_PATTERN_SOURCES &&
          BinaryPrefix.matchIsBinaryDense(binaryPrefix, match)
  ) {
    return null
  }
  return Threat(
      type = "regex",
      pattern = pattern.source,
      match = sanitizeForReporting(match.group()),
      position = match.start(),
      executionTime = (System.nanoTime() - patternStartNanos) / 1e9,
      category = category,
      weight = SusPatternsWeights.resolvePatternWeight(pattern.source, category),
  )
}

/** _build_timeout_threat. */
public fun buildTimeoutThreat(
    pattern: PyRePattern,
    category: String,
    patternStartNanos: Long,
): Threat =
    Threat(
        type = "pattern_timeout",
        pattern = pattern.source,
        match = "",
        position = 0,
        executionTime = (System.nanoTime() - patternStartNanos) / 1e9,
        category = category,
        weight = SusPatternsWeights.resolvePatternWeight(pattern.source, category),
    )

/** _first_accepted_regex_threat. */
public fun firstAcceptedRegexThreat(
    matches: List<PyReMatch>,
    pattern: PyRePattern,
    category: String,
    patternStartNanos: Long,
    context: String = "unknown",
    binaryPrefix: IntArray? = null,
): Threat? {
  for (match in matches) {
    val threat =
        buildRegexThreat(pattern, match, category, patternStartNanos, context, binaryPrefix)
    if (threat != null) return threat
  }
  return null
}

private val KNOWN_CONTEXTS: Set<String> =
    setOf("query_param", "header", "url_path", "request_body", "unknown")

public fun normalizeContext(context: String?): String {
  if (context == null) return "unknown"
  val normalized = context.split(":", limit = 2)[0]
  return if (normalized !in KNOWN_CONTEXTS) "unknown" else normalized
}

public class SusPatternsManager private constructor() {
  public var config: DetectionConfigView? = null
  public val patterns: MutableList<String> = PATTERN_DEFINITIONS.map { it.first }.toMutableList()
  public val customPatterns: MutableSet<String> = LinkedHashSet()
  public val compiledPatterns: MutableList<CompiledPatternRow> =
      PATTERN_DEFINITIONS.map { (source, contexts, category) ->
            CompiledPatternRow(
                PyRe.compile(source, BUILTIN_PATTERN_COMPILE_FLAGS),
                contexts,
                category,
            )
          }
          .toMutableList()
  public val compiledCustomPatterns: MutableSet<CompiledPatternRow> = LinkedHashSet()
  public var detectionState: DetectionState = LEGACY_DETECTION_STATE

  public companion object {
    public const val BUILTIN_PATTERN_COMPILE_FLAGS: Int = PyReFlags.IGNORECASE

    private val instance: SusPatternsManager by lazy { SusPatternsManager() }

    /** python SusPatternsManager() singleton-call analog. */
    public fun shared(): SusPatternsManager = instance
  }

  private val compiler: PatternCompiler?
    get() = detectionState.compiler

  /** configure: swap in the enhanced state for a supported config. */
  public fun configure(config: DetectionConfigView?) {
    if (!supportsEnhancedConfig(config)) return
    this.config = config
    if (config != null) {
      detectionState = buildEnhancedDetectionState(config)
    }
  }

  /** add_pattern: validate then compile into the table (python add_pattern). */
  public fun addPattern(pattern: String, custom: Boolean = false): Boolean {
    val compiler = this.compiler ?: PatternCompiler()
    val maxContentLength = config?.detectionMaxBodyInspectBytes ?: DEFAULT_MAX_BODY_INSPECT_BYTES
    val (isSafe, reason) =
        compiler.validatePatternSafety(pattern, maxContentLength = maxContentLength)
    if (!isSafe) {
      return false
    }
    val row =
        CompiledPatternRow(
            PyRe.compile(pattern, PyReFlags.IGNORECASE or PyReFlags.MULTILINE),
            CTX_ALL,
            "custom",
        )
    if (custom) {
      compiledCustomPatterns.add(row)
      customPatterns.add(pattern)
    } else {
      compiledPatterns.add(row)
      patterns.add(pattern)
    }
    this.compiler?.clearCache()
    return true
  }

  public fun removePattern(pattern: String, custom: Boolean = false): Boolean {
    val removed =
        if (custom) {
          if (pattern !in customPatterns) return false
          customPatterns.remove(pattern)
          compiledCustomPatterns.removeAll { it.compiled.source == pattern }
          true
        } else {
          val index = patterns.indexOf(pattern)
          if (index == -1) return false
          patterns.removeAt(index)
          // Python dels both lists unconditionally (remove_pattern keeps them in
          // lockstep: both are seeded from PATTERN_DEFINITIONS and appended/removed
          // together), so removeAt mirrors python's IndexError-on-skew exactly.
          compiledPatterns.removeAt(index)
          true
        }
    if (removed) {
      compiler?.clearCache()
      detectionState.performanceMonitor?.removePatternStats(pattern)
    }
    return removed
  }

  public fun getAllCompiledPatterns(): List<CompiledPatternRow> =
      compiledPatterns + compiledCustomPatterns

  /** _preprocess_content: (processed, decode_budget_exhausted, decoded). */
  private fun preprocessContent(
      content: String,
      state: DetectionState,
  ): Triple<String, Boolean, String> {
    val preprocessor =
        state.preprocessor
            ?: run {
              val maxLength = config?.detectionMaxContentLength ?: DEFAULT_MAX_SCAN_LENGTH
              return Triple(
                  com.guardcore.engine.py.PyUnicode.cpSlice(content, 0, maxLength),
                  false,
                  "",
              )
            }
    val budget = booleanArrayOf(false)
    val (processed, decoded) = preprocessor.preprocessWithDecoded(content, budget)
    return Triple(processed, budget[0], decoded)
  }

  /** _check_regex_pattern: one pattern over one view. */
  private fun checkRegexPattern(
      pattern: PyRePattern,
      content: String,
      patternStartNanos: Long,
      category: String,
      state: DetectionState,
      context: String,
      binaryPrefix: IntArray?,
  ): Pair<Threat?, Boolean> {
    val windowedFinder = WINDOWED_PATTERN_FINDERS[pattern.source]
    if (windowedFinder != null) {
      return checkWindowedPattern(
          pattern,
          windowedFinder,
          content,
          patternStartNanos,
          category,
          context,
          binaryPrefix,
      )
    }

    var timeoutOccurred = false

    val scanWindowMatcher = PATTERN_SCAN_WINDOW_MATCHERS[pattern.source]
    if (scanWindowMatcher != null) {
      val matches =
          try {
            scanWindowMatcher(content, pattern)
          } catch (e: PyReDeadlines) {
            reportScanTimeout()
            emptyList()
          }
      val threat =
          firstAcceptedRegexThreat(
              matches,
              pattern,
              category,
              patternStartNanos,
              context,
              binaryPrefix,
          )
      return Pair(threat, timeoutOccurred)
    }

    val scanWindowBounds = SCAN_WINDOW_PATTERNS[pattern.source]
    if (scanWindowBounds != null) {
      val matches =
          try {
            iterScanWindowMatches(content, pattern, scanWindowBounds)
          } catch (e: PyReDeadlines) {
            reportScanTimeout()
            emptyList()
          }
      val threat =
          firstAcceptedRegexThreat(
              matches,
              pattern,
              category,
              patternStartNanos,
              context,
              binaryPrefix,
          )
      return Pair(threat, timeoutOccurred)
    }

    val compiler = state.compiler
    if (compiler != null) {
      // Inline table patterns cannot exceed the wall clock short of a host stall; the
      // reference's inline path has the same property (no executor timeout).
      val matches = pattern.finditer(content, Long.MAX_VALUE)
      val timeoutThreshold = 0.9 * compiler.defaultTimeout
      if (matches.isEmpty() && (System.nanoTime() - patternStartNanos) / 1e9 >= timeoutThreshold) {
        timeoutOccurred = true
      }
      val threat =
          firstAcceptedRegexThreat(
              matches,
              pattern,
              category,
              patternStartNanos,
              context,
              binaryPrefix,
          )
      if (threat != null) return Pair(threat, timeoutOccurred)
    } else {
      val (threat, occurred) =
          checkRegexPatternWithRetry(
              pattern,
              content,
              patternStartNanos,
              category,
              context,
              binaryPrefix,
          )
      if (threat != null) return Pair(threat, occurred)
      timeoutOccurred = timeoutOccurred || occurred
    }

    return Pair(null, timeoutOccurred)
  }

  /** _check_windowed_pattern with the hard deadline. */
  private fun checkWindowedPattern(
      pattern: PyRePattern,
      finder: (String) -> List<PyReMatch>,
      content: String,
      patternStartNanos: Long,
      category: String,
      context: String,
      binaryPrefix: IntArray?,
  ): Pair<Threat?, Boolean> {
    val timeout = config?.detectionCompilerTimeout ?: DEFAULT_COMPILER_TIMEOUT
    val deadlineNanos = System.nanoTime() + (timeout * 1e9).toLong()
    val matches: List<PyReMatch> =
        try {
          runWithDeadlineGuard(deadlineNanos) { finder(content) }
        } catch (e: PyRe.DeadlineExceededException) {
          reportScanTimeout()
          return Pair(null, true)
        } catch (e: Exception) {
          return Pair(null, false)
        }
    reportScanSuccess()
    val threat =
        firstAcceptedRegexThreat(
            matches,
            pattern,
            category,
            patternStartNanos,
            context,
            binaryPrefix,
        )
    return Pair(threat, false)
  }

  private inline fun <T> runWithDeadlineGuard(deadlineNanos: Long, block: () -> T): T {
    // The finder itself enforces per-match deadlines via DeadlineCharSequence; the wall
    // clock guard catches construction cost between matches.
    val result = block()
    if (System.nanoTime() > deadlineNanos) throw PyRe.DeadlineExceededException()
    return result
  }

  /** _check_regex_pattern_with_retry (legacy path). */
  private fun checkRegexPatternWithRetry(
      pattern: PyRePattern,
      content: String,
      patternStartNanos: Long,
      category: String,
      context: String,
      binaryPrefix: IntArray?,
  ): Pair<Threat?, Boolean> {
    var searchFrom = 0
    var timeoutOccurred = false

    while (true) {
      val (match, occurred) =
          checkPatternWithTimeout(pattern, content, patternStartNanos, searchFrom)
      timeoutOccurred = timeoutOccurred || occurred
      if (match == null || occurred) break

      val threat =
          buildRegexThreat(pattern, match, category, patternStartNanos, context, binaryPrefix)
      if (threat != null) return Pair(threat, timeoutOccurred)

      searchFrom =
          if (match.charEnd() == match.charStart()) match.charEnd() + 1 else match.charEnd()
    }

    return Pair(null, timeoutOccurred)
  }

  private fun checkPatternWithTimeout(
      pattern: PyRePattern,
      content: String,
      patternStartNanos: Long,
      searchFrom: Int,
  ): Pair<PyReMatch?, Boolean> {
    val timeout = config?.detectionCompilerTimeout ?: DEFAULT_COMPILER_TIMEOUT
    val deadlineNanos = System.nanoTime() + (timeout * 1e9).toLong()
    return try {
      val match = pattern.search(content, searchFrom, deadlineNanos)
      reportScanSuccess()
      Pair(match, false)
    } catch (e: PyRe.DeadlineExceededException) {
      reportScanTimeout()
      Pair(null, true)
    } catch (e: Exception) {
      Pair(null, false)
    }
  }

  /** _pattern_excluded_from_view. */
  private fun patternExcludedFromView(
      source: String,
      rawViewOnly: Boolean?,
      urlDecodedViewOnly: Boolean?,
  ): Boolean {
    val isRawViewPattern = source in DETECTION_RAW_VIEW_PATTERN_SOURCES
    val isUrlDecodedViewPattern = source in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    val isReconRawViewPattern = source in DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES
    if (rawViewOnly == true) {
      return isUrlDecodedViewPattern || !(isRawViewPattern || isReconRawViewPattern)
    }
    if (urlDecodedViewOnly == true) {
      return isRawViewPattern || !isUrlDecodedViewPattern
    }
    if (rawViewOnly == false) {
      return isRawViewPattern || isUrlDecodedViewPattern
    }
    return false
  }

  private fun patternShouldBeSkipped(
      source: String,
      contexts: Set<String>,
      category: String,
      rawViewOnly: Boolean?,
      skipFilter: Boolean,
      normalizedContext: String,
      enabledCategories: Set<String>?,
      urlDecodedViewOnly: Boolean?,
  ): Boolean {
    if (patternExcludedFromView(source, rawViewOnly, urlDecodedViewOnly)) return true
    if (!skipFilter && normalizedContext !in contexts) return true
    return enabledCategories != null && category != "custom" && category !in enabledCategories
  }

  /** _check_regex_patterns over one view. */
  private fun checkRegexPatterns(
      content: String,
      context: String,
      enabledCategories: Set<String>?,
      state: DetectionState,
      rawViewOnly: Boolean? = null,
      urlDecodedViewOnly: Boolean? = null,
  ): Triple<MutableList<Threat>, MutableList<String>, MutableList<String>> {
    val threats = ArrayList<Threat>()
    val matchedPatterns = ArrayList<String>()
    val timeouts = ArrayList<String>()

    val allPatterns = getAllCompiledPatterns()
    val normalized = normalizeContext(context)
    val validatorContext =
        if (context.endsWith(EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX)) {
          normalized + EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX
        } else {
          normalized
        }
    val skipFilter = normalized == "unknown" || normalized == "request_body"
    val performanceMonitor = state.performanceMonitor
    val binaryPrefix = BinaryPrefix.buildBinaryPrefix(content)

    for (row in allPatterns) {
      if (
          patternShouldBeSkipped(
              row.compiled.source,
              row.contexts,
              row.category,
              rawViewOnly,
              skipFilter,
              normalized,
              enabledCategories,
              urlDecodedViewOnly,
          )
      ) {
        continue
      }

      val patternStart = System.nanoTime()

      var threat: Threat?
      var timeoutOccurred: Boolean
      try {
        val (t, occurred) =
            checkRegexPattern(
                row.compiled,
                content,
                patternStart,
                row.category,
                state,
                validatorContext,
                binaryPrefix,
            )
        threat = t
        timeoutOccurred = occurred
      } catch (e: PatternValidationTimeout) {
        threat = null
        timeoutOccurred = true
      }

      if (timeoutOccurred) {
        timeouts.add(row.compiled.source)
        if (threat == null) {
          threat = buildTimeoutThreat(row.compiled, row.category, patternStart)
        }
      }

      if (threat != null) {
        threats.add(threat)
        matchedPatterns.add(row.compiled.source)
        if (System.getProperty("guardcore.debug.views") != null) {
          System.err.println(
              "[view=" +
                  (if (rawViewOnly == true) "raw"
                  else if (urlDecodedViewOnly == true) "url" else "main") +
                  "] matched: " +
                  row.compiled.source.take(70) +
                  " threat=" +
                  threat.type,
          )
        }
      }

      if (performanceMonitor != null) {
        performanceMonitor.recordMetric(
            row.compiled.source,
            (System.nanoTime() - patternStart) / 1e9,
            content.length,
            matched = threat != null,
            timeout = timeoutOccurred,
        )
      }
    }

    return Triple(threats, matchedPatterns, timeouts)
  }

  /** _check_raw_view_patterns. */
  private fun checkRawViewPatterns(
      content: String,
      context: String,
      enabledCategories: Set<String>?,
      state: DetectionState,
  ): Triple<MutableList<Threat>, MutableList<String>, MutableList<String>> {
    val preprocessor = state.preprocessor ?: return Triple(ArrayList(), ArrayList(), ArrayList())
    val rawViewContent = preprocessor.preprocessSignalPreserving(content)
    return checkRegexPatterns(rawViewContent, context, enabledCategories, state, rawViewOnly = true)
  }

  /** _check_decoded_view_path_traversal. */
  private fun checkDecodedViewPathTraversal(
      processedContent: String,
      content: String,
      context: String,
      enabledCategories: Set<String>?,
      state: DetectionState,
  ): Threat? {
    if (enabledCategories != null && "path_traversal" !in enabledCategories) return null

    val patternStart = System.nanoTime()
    val preprocessor = state.preprocessor
    val rawViewContent: String
    val decodedViewContent: String
    if (preprocessor != null) {
      rawViewContent = preprocessor.preprocessSignalPreserving(content)
      decodedViewContent = processedContent
    } else {
      val maxLength = config?.detectionMaxContentLength ?: DEFAULT_MAX_SCAN_LENGTH
      val legacy = ContentPreprocessor()
      val raw =
          legacy.normalizeUnicode(
              com.guardcore.engine.py.PyUnicode.cpSlice(content, 0, maxLength),
          )
      rawViewContent = raw
      decodedViewContent = legacyDecodePathTraversalView(raw, legacy)
    }

    val decodedMatches =
        PATH_TRAVERSAL_DECODED_SHAPE_RE.finditer(decodedViewContent, Long.MAX_VALUE)
    val rawCount = PATH_TRAVERSAL_DECODED_SHAPE_RE.finditer(rawViewContent, Long.MAX_VALUE).size
    if (decodedMatches.size <= rawCount) return null

    val match = decodedMatches[0]
    return Threat(
        type = "regex",
        pattern = PATH_TRAVERSAL_DECODED_SHAPE_RE.source,
        match = sanitizeForReporting(match.group()),
        position = match.start(),
        executionTime = (System.nanoTime() - patternStart) / 1e9,
        category = "path_traversal",
        weight =
            SusPatternsWeights.resolvePatternWeight(
                PATH_TRAVERSAL_DECODED_SHAPE_RE.source,
                "path_traversal",
            ),
    )
  }

  private val legacyPathTraversalDecodeMaxIterations = 8

  private fun legacyDecodePathTraversalView(
      normalizedContent: String,
      legacy: ContentPreprocessor,
  ): String {
    var decoded = normalizedContent
    for (i in 0 until legacyPathTraversalDecodeMaxIterations) {
      val previous = decoded
      decoded = EncodingDecodersAccess.decodeOverlongUtf8PercentRuns(decoded)
      decoded = PyUrllib.unquoteIgnore(decoded)
      decoded = EncodingDecodersAccess.decodePercentUEscapes(decoded)
      decoded = legacy.normalizeUnicode(decoded)
      if (decoded == previous) break
    }
    return legacy.removeNullBytes(decoded)
  }

  /** _check_url_decoded_view_patterns. */
  private fun checkUrlDecodedViewPatterns(
      content: String,
      context: String,
      enabledCategories: Set<String>?,
      state: DetectionState,
      precomputedDecoded: String,
      precomputedDecodeBudgetExhausted: Boolean,
  ): Quad<MutableList<Threat>, MutableList<String>, MutableList<String>, Boolean> {
    val preprocessor =
        state.preprocessor ?: return Quad(ArrayList(), ArrayList(), ArrayList(), false)

    // preprocessContent always computes the decoded view alongside the processed
    // content (a single preprocessWithDecoded pass), so the decoded view re-derives
    // from the precomputed value; a null precompute cannot occur (the python
    // _check_url_decoded_view_patterns recompute branch guarded a lazily-computed
    // value this port always has).
    val urlDecodedViewContent = preprocessor.truncateSafely(precomputedDecoded)
    val decodeBudgetExhaustedFlag = precomputedDecodeBudgetExhausted

    val (threats, matched, timeouts) =
        checkRegexPatterns(
            urlDecodedViewContent,
            context,
            enabledCategories,
            state,
            urlDecodedViewOnly = true,
        )
    return Quad(threats, matched, timeouts, decodeBudgetExhaustedFlag)
  }

  /** _check_short_base64_additive_view_patterns. */
  private fun checkShortBase64AdditiveViewPatterns(
      content: String,
      context: String,
      enabledCategories: Set<String>?,
      state: DetectionState,
  ): Triple<MutableList<Threat>, MutableList<String>, MutableList<String>> {
    val preprocessor = state.preprocessor ?: return Triple(ArrayList(), ArrayList(), ArrayList())
    val additiveViewContent = preprocessor.preprocessShortBase64AdditiveView(content)
    if (additiveViewContent.isEmpty()) return Triple(ArrayList(), ArrayList(), ArrayList())
    return checkRegexPatterns(additiveViewContent, context, enabledCategories, state)
  }

  /** _check_semantic_threats. */
  private fun checkSemanticThreats(
      content: String,
      state: DetectionState,
      rawContent: String,
  ): Pair<List<Threat>, Double> {
    val semanticAnalyzer = state.semanticAnalyzer ?: return Pair(emptyList(), 0.0)

    if (looksLikeBinaryContent(rawContent)) return Pair(emptyList(), 0.0)

    val semanticThreshold = state.semanticThreshold
    val semanticBudget = state.preprocessor?.maxContentLength ?: content.length
    val semanticAnalysis =
        semanticAnalyzer.analyze(
            com.guardcore.engine.py.PyUnicode.cpSlice(content, 0, semanticBudget),
        )
    val semanticScore = semanticAnalyzer.getThreatScore(semanticAnalysis)
    val threats = ArrayList<Threat>()

    if (semanticScore > semanticThreshold) {
      @Suppress("UNCHECKED_CAST")
      val attackProbs = semanticAnalysis["attack_probabilities"] as Map<String, Double>
      for ((attackType, probability) in attackProbs) {
        if (probability >= semanticThreshold) {
          threats.add(
              Threat(
                  type = "semantic",
                  pattern = "",
                  match = "",
                  position = 0,
                  executionTime = 0.0,
                  category = attackType,
                  weight = 0.0,
                  attackType = attackType,
                  probability = probability,
                  analysis = semanticAnalysis,
              ),
          )
        }
      }

      if (threats.isEmpty() && semanticScore >= semanticThreshold) {
        threats.add(
            Threat(
                type = "semantic",
                pattern = "",
                match = "",
                position = 0,
                executionTime = 0.0,
                category = "suspicious",
                weight = 0.0,
                attackType = "suspicious",
                threatScore = semanticScore,
                analysis = semanticAnalysis,
            ),
        )
      }
    }

    return Pair(threats, semanticScore)
  }

  /** _calculate_threat_score. */
  private fun calculateThreatScore(
      regexThreats: List<Threat>,
      semanticThreats: List<Threat>,
  ): Double {
    if (regexThreats.isEmpty() && semanticThreats.isEmpty()) return 0.0

    val anomaly = regexAnomaly(regexThreats)
    val semanticScores = semanticThreats.map { it.probability ?: it.threatScore ?: 0.0 }
    val semanticMax = if (semanticScores.isNotEmpty()) semanticScores.max() else 0.0
    return minOf(maxOf(anomaly, semanticMax), 1.0)
  }

  /** _drop_view_duplicate_threats + _merge_raw_view_results. */
  private fun mergeRawViewResults(
      seenThreats: List<Threat>,
      rawResults: Triple<MutableList<Threat>, MutableList<String>, MutableList<String>>,
  ): Triple<MutableList<Threat>, MutableList<String>, MutableList<String>> {
    val (rawThreats, rawMatched, rawTimeouts) = rawResults
    val seen = seenThreats.map { Pair(it.pattern, it.match) }.toHashSet()
    val keptThreats = ArrayList<Threat>()
    val keptMatched = ArrayList<String>()
    for (i in rawThreats.indices) {
      val threat = rawThreats[i]
      val pattern = rawMatched[i]
      val key = Pair(threat.pattern, threat.match)
      if (key in seen) continue
      seen.add(key)
      keptThreats.add(threat)
      keptMatched.add(pattern)
    }
    return Triple(keptThreats, keptMatched, rawTimeouts)
  }

  /** detect(): the full verdict pipeline (synchronous engine surface). */
  public fun detect(
      content: String,
      ipAddress: String,
      context: String = "unknown",
      correlationId: String? = null,
      enabledCategories: Set<String>? = null,
      skipSemantic: Boolean = false,
  ): DetectResult =
      // The whole pipeline runs on one big-stack scan-pool worker: java.util.regex recurses
      // per group-repetition iteration, so the table's long-input scans need the 512 MiB
      // worker stack (the JVM analog of the reference's shared regex executor).
      com.guardcore.engine.py.RegexWorkers.submit {
        detectInternal(
            content,
            ipAddress,
            context,
            correlationId,
            enabledCategories,
            skipSemantic,
        )
      }

  private fun detectInternal(
      content: String,
      ipAddress: String,
      context: String,
      correlationId: String?,
      enabledCategories: Set<String>?,
      skipSemantic: Boolean,
  ): DetectResult {
    val originalContent = content
    val executionStart = System.nanoTime()
    val state = detectionState

    val (processedContent, decodeBudgetExhausted, precomputedDecoded) =
        preprocessContent(content, state)

    val (regexThreats0, matchedPatterns0, timeouts0) =
        checkRegexPatterns(
            processedContent,
            context,
            enabledCategories,
            state,
            rawViewOnly = if (state.preprocessor != null) false else null,
        )

    val rawViewResults = checkRawViewPatterns(content, context, enabledCategories, state)
    val (rawThreats, rawMatched, rawTimeouts) = mergeRawViewResults(regexThreats0, rawViewResults)
    val regexThreats = ArrayList(regexThreats0)
    regexThreats.addAll(rawThreats)
    val matchedPatterns = ArrayList(matchedPatterns0)
    matchedPatterns.addAll(rawMatched)
    val timeouts = ArrayList(timeouts0)
    for (t in rawTimeouts) if (t !in timeouts) timeouts.add(t)

    val decodedViewThreat =
        checkDecodedViewPathTraversal(processedContent, content, context, enabledCategories, state)
    if (decodedViewThreat != null) {
      regexThreats.add(decodedViewThreat)
      matchedPatterns.add(decodedViewThreat.pattern)
    }

    val urlDecoded =
        checkUrlDecodedViewPatterns(
            content,
            context,
            enabledCategories,
            state,
            precomputedDecoded,
            decodeBudgetExhausted,
        )
    val urlDecodedThreats = urlDecoded.first
    val urlDecodedMatched = urlDecoded.second
    val urlDecodedTimeouts = urlDecoded.third
    val urlDecodedBudgetExhausted = urlDecoded.fourth
    regexThreats.addAll(urlDecodedThreats)
    matchedPatterns.addAll(urlDecodedMatched)
    timeouts.addAll(urlDecodedTimeouts)

    if (decodeBudgetExhausted || urlDecodedBudgetExhausted) {
      val exhaustionThreat = decodeBudgetExhaustedThreat()
      regexThreats.add(exhaustionThreat)
      matchedPatterns.add(exhaustionThreat.pattern)
    }

    val (shortBase64Threats, shortBase64Matched, shortBase64Timeouts) =
        checkShortBase64AdditiveViewPatterns(content, context, enabledCategories, state)
    regexThreats.addAll(shortBase64Threats)
    matchedPatterns.addAll(shortBase64Matched)
    timeouts.addAll(shortBase64Timeouts)

    val semanticThreats =
        if (skipSemantic) emptyList()
        else checkSemanticThreats(processedContent, state, originalContent).first

    val threats = ArrayList(regexThreats)
    threats.addAll(semanticThreats)
    val isThreat =
        regexAnomaly(regexThreats) >= state.threatScoreThreshold || semanticThreats.isNotEmpty()

    val threatScore = calculateThreatScore(regexThreats, semanticThreats)

    val totalExecutionTime = (System.nanoTime() - executionStart) / 1e9

    if (state.performanceMonitor != null) {
      state.performanceMonitor.recordMetric(
          "overall_detection",
          totalExecutionTime,
          content.length,
          matched = isThreat,
          timeout = false,
      )
    }

    val detectionMethod = if (state.compiler != null) "enhanced" else "legacy"

    return DetectResult(
        isThreat = isThreat,
        threatScore = threatScore,
        threats = threats,
        context = context,
        originalLength = com.guardcore.engine.py.PyUnicode.cpLength(originalContent),
        processedLength = com.guardcore.engine.py.PyUnicode.cpLength(processedContent),
        executionTime = totalExecutionTime,
        detectionMethod = detectionMethod,
        timeouts = timeouts,
        correlationId = correlationId,
    )
  }
}

/** Access alias for the encoding decoders used by the legacy view path. */
internal object EncodingDecodersAccess {
  fun decodeOverlongUtf8PercentRuns(content: String): String =
      com.guardcore.engine.detection.EncodingDecoders.decodeOverlongUtf8PercentRuns(content)

  fun decodePercentUEscapes(content: String): String =
      com.guardcore.engine.detection.EncodingDecoders.decodePercentUEscapes(content)
}

/** 4-tuple for the multi-value view results (python tuple unpacking analog). */
public class Quad<A, B, C, D>(
    public val first: A,
    public val second: B,
    public val third: C,
    public val fourth: D,
) {
  public operator fun component1(): A = first

  public operator fun component2(): B = second

  public operator fun component3(): C = third

  public operator fun component4(): D = fourth
}
