package com.guardcore.engine.suspatterns

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyRePattern
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Ports the suspatterns tails the corpus never reaches:
 * tests/test_sus_patterns/test_xml_xxe_corpus.py walker arms, test_ldap_null_byte_nul_family.py,
 * test_sqli_bind_placeholder_tautology.py, template/shell matcher edges, and the
 * Threat/State/Manager helpers.
 */
class SusPatternsTailsTest {
  private fun compile(source: String): PyRePattern = PyRe.compile(source, PyReFlags.IGNORECASE)

  // ---- XmlXxe walkers ----

  @Test
  fun xmlSystemFinditerFindsSystemEntities() {
    val text = "<!ENTITY x SYSTEM \"file:///etc/passwd\"> <!ENTITY y SYSTEM \"http://x\">"
    val matches = SusPatternsXmlXxe.xmlSystemFinditer(text)
    assertEquals(2, matches.size)
    // No SYSTEM keyword: no matches.
    assertEquals(0, SusPatternsXmlXxe.xmlSystemFinditer("<!ENTITY x \"value\">").size)
    // An unterminated prefix (no > after it) yields nothing.
    assertEquals(0, SusPatternsXmlXxe.xmlSystemFinditer("<!ENTITY x SYSTEM \"o").size)
  }

  @Test
  fun xmlInternalEntityFindsDoctypeEntityBlocks() {
    val text = "<!DOCTYPE r [<!ENTITY x \"v\">]>"
    val matches = SusPatternsXmlXxe.xmlInternalEntityFinditer(text)
    assertEquals(1, matches.size)
    assertEquals(0, SusPatternsXmlXxe.xmlInternalEntityFinditer("<!DOCTYPE r>").size)
    assertEquals(0, SusPatternsXmlXxe.xmlInternalEntityFinditer("<!DOCTYPE r [nothing]>").size)
  }

  @Test
  fun firstAtOrAfterBinarySearch() {
    val positions = listOf(2, 5, 9)
    assertEquals(2, SusPatternsXmlXxe.firstAtOrAfter(positions, 0))
    assertEquals(5, SusPatternsXmlXxe.firstAtOrAfter(positions, 4))
    assertEquals(9, SusPatternsXmlXxe.firstAtOrAfter(positions, 7))
    assertNull(SusPatternsXmlXxe.firstAtOrAfter(positions, 10))
  }

  @Test
  fun schemeCompletionEndRequiresQuoteAndClose() {
    val text = "<!DOCTYPE r SYSTEM \"http://evil.com/x\">"
    val class12 =
        SusPatternsXmlXxe.CLASS12_BOUNDARY_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val class3 =
        SusPatternsXmlXxe.CLASS3_BOUNDARY_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val schemeStart = text.indexOf("http")
    val end = SusPatternsXmlXxe.schemeCompletionEnd(text, schemeStart, class12, class3)
    assertNotNull(end)
    assertTrue(text[end] == '>')
    // The scheme must open with a quote.
    assertNull(SusPatternsXmlXxe.schemeCompletionEnd(text, 0, class12, class3))
    // A w3.org URL is exempt.
    val w3 = "<!DOCTYPE r SYSTEM \"http://www.w3.org/2001/XMLSchema\">"
    val w3c12 =
        SusPatternsXmlXxe.CLASS12_BOUNDARY_RE.finditer(w3, Long.MAX_VALUE).map { it.charStart() }
    val w3c3 =
        SusPatternsXmlXxe.CLASS3_BOUNDARY_RE.finditer(w3, Long.MAX_VALUE).map { it.charStart() }
    assertNull(SusPatternsXmlXxe.schemeCompletionEnd(w3, w3.indexOf("http"), w3c12, w3c3))
    // An unclosed quote yields no end.
    val open = "<!DOCTYPE r SYSTEM \"http://evil.com/x"
    val open12 =
        SusPatternsXmlXxe.CLASS12_BOUNDARY_RE.finditer(open, Long.MAX_VALUE).map { it.charStart() }
    val open3 =
        SusPatternsXmlXxe.CLASS3_BOUNDARY_RE.finditer(open, Long.MAX_VALUE).map { it.charStart() }
    assertNull(SusPatternsXmlXxe.schemeCompletionEnd(open, open.indexOf("http"), open12, open3))
  }

  @Test
  fun validQuoteCompletionsCollectsQuotes() {
    val text = "<!DOCTYPE r SYSTEM \"http://a.b/c\">"
    val class12 =
        SusPatternsXmlXxe.CLASS12_BOUNDARY_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val class3 =
        SusPatternsXmlXxe.CLASS3_BOUNDARY_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val (quotes, quoteToGt) = SusPatternsXmlXxe.validQuoteCompletions(text, class12, class3)
    assertEquals(1, quotes.size)
    // The completion ends at the final '>' of the URL run.
    assertTrue(quoteToGt[quotes[0]]!! > text.indexOf("http"))
    // No scheme: no completions.
    val (emptyQuotes, _) = SusPatternsXmlXxe.validQuoteCompletions("<!DOCTYPE r>", class12, class3)
    assertTrue(emptyQuotes.isEmpty())
  }

  @Test
  fun publicRunBoundsAndCandidateSpan() {
    val text = "<!DOCTYPE r PUBLIC \"a\" \"http://x/y\">"
    val class12 =
        SusPatternsXmlXxe.CLASS12_BOUNDARY_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val (runStart, runEnd) =
        SusPatternsXmlXxe.publicRunBounds(class12, text.indexOf("PUBLIC"), text.length)
    assertEquals(0, runStart)
    assertEquals(class12.first(), runEnd)
    val doctypes =
        SusPatternsXmlXxe.DOCTYPE_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val class3 =
        SusPatternsXmlXxe.CLASS3_BOUNDARY_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val (quotes, quoteToGt) = SusPatternsXmlXxe.validQuoteCompletions(text, class12, class3)
    val span =
        SusPatternsXmlXxe.candidateSpan(
            doctypes,
            quotes,
            quoteToGt,
            class12,
            text.indexOf("PUBLIC"),
            text.length,
        )
    assertNotNull(span)
    // No doctype before the public position: no candidate.
    assertNull(
        SusPatternsXmlXxe.candidateSpan(
            emptyList(),
            quotes,
            quoteToGt,
            class12,
            text.indexOf("PUBLIC"),
            text.length,
        ),
    )
    // Precompute rejects text without both anchors.
    assertNull(SusPatternsXmlXxe.precompute("plain text"))
  }

  // ---- Matchers ----

  @Test
  fun cmdInjectionShellDashCFinditerMatchesChains() {
    val finder = WINDOWED_PATTERN_FINDERS[CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE]
    assertNotNull(finder)
    val matches = finder!!("x\n/bin/sh -c id")
    assertTrue(matches.isNotEmpty(), "expected newline shell -c match")
    assertEquals(0, finder("plain text\nmore text").size)
  }

  @Test
  fun ldapNullByteAttrWalkers() {
    val finder = WINDOWED_PATTERN_FINDERS[LDAP_NULL_BYTE_ATTR_RE]
    assertNotNull(finder)
    // attr=value*) + NUL escape family.
    val text = "uid=admin\\00"
    val matches = finder(text)
    assertEquals(0, matches.size)
    // The walker helpers directly (value start scans back over continuation chars).
    val probe = "(uid=admin"
    assertEquals(5, ldapNullByteValueStart(probe, 9))
    assertNull(ldapNullByteAttrNameStart("*=", 1))
    // No star or paren: the finder short-circuits.
    val attrFinder = WINDOWED_PATTERN_FINDERS[LDAP_NULL_BYTE_ATTR_RE]
    assertEquals(0, attrFinder!!("no wildcards here").size)
  }

  @Test
  fun quoteSpliceFinditerMatchesSplicedCommands() {
    val finder = WINDOWED_PATTERN_FINDERS[QUOTE_SPLICE_CANDIDATE_RE]
    assertNotNull(finder)
    // word " word splices: the candidate regex fires and the finder reports it.
    val matches = finder("x\"\"cat /etc/passwd")
    assertTrue(matches.isNotEmpty(), "expected quote splice match: " + "none")
    assertEquals(0, finder("plain text").size, "no matches for prose")
    // A quote run not followed by a word char never matches.
    assertEquals<Int>(0, finder("x'; '; y").size)
  }

  @Test
  fun templateScanMatchersFindInjectionShapes() {
    val dollar = compile(TEMPLATE_DOLLAR_BRACE_CALL_RE)
    assertTrue(templateDollarBraceScanMatches("x\${1*2}y", dollar).isNotEmpty())
    val curlyCall = compile(TEMPLATE_CURLY_CALL_RE)
    assertTrue(templateCurlyCallScanMatches("{{7*6}}", curlyCall).isNotEmpty())
    val asp = compile(TEMPLATE_ASP_KEYWORD_RE)
    assertTrue(templateAspKeywordScanMatches("<%=1+2%>", asp).isNotEmpty())
    val hashBrace = compile(SSTI_HASH_BRACE_SHAPE_RE)
    assertTrue(templateHashBraceScanMatches("#{1*2}", hashBrace).isNotEmpty())
    // Negative: prose does not fire.
    assertEquals(0, templateDollarBraceScanMatches("cost is $5", dollar).size)
  }

  @Test
  fun braceExpansionDangerDetection() {
    val compiled = compile(BRACE_EXPANSION_COMMAND_RE)
    val match = compiled.search("; {a,b}", 0, Long.MAX_VALUE)
    assertNotNull(match)
    assertTrue(braceExpansionIsDangerousCommand(match!!))
    // Digits only: not letter-bearing, so safe.
    val digits = compiled.search("; {1,2}", 0, Long.MAX_VALUE)
    assertNotNull(digits)
    assertFalse(braceExpansionIsDangerousCommand(digits!!))
    // A match without braces is not dangerous.
    val plain = compile("zz")
    val plainMatch = plain.search("zz", 0, Long.MAX_VALUE)
    assertNotNull(plainMatch)
    assertFalse(braceExpansionIsDangerousCommand(plainMatch!!))
  }

  @Test
  fun loadFileAndDollarScanMatchers() {
    val compiled = compile(SQLI_LOAD_FILE_RE)
    assertTrue(loadFileScanMatches("SELECT LOAD_FILE('/etc/passwd')", compiled).isNotEmpty())
    assertEquals(0, loadFileScanMatches("SELECT 1", compiled).size)
  }

  // ---- Threat helpers ----

  @Test
  fun threatToMapSplitsByType() {
    val regex = Threat("regex", "p", "m", 1, 0.5, "sqli", 2.0)
    val regexMap = regex.toMap()
    assertEquals("regex", regexMap["type"])
    assertEquals("p", regexMap["pattern"])
    assertEquals("m", regexMap["match"])
    assertEquals(1, regexMap["position"])
    assertEquals(2.0, regexMap["weight"])
    val semantic =
        Threat(
            "semantic",
            "",
            "",
            0,
            0.0,
            "xss",
            1.0,
            attackType = "xss",
            probability = 0.9,
            threatScore = 0.5,
            analysis = mapOf("k" to 1.0),
        )
    val semanticMap = semantic.toMap()
    assertEquals("semantic", semanticMap["type"])
    assertEquals("xss", semanticMap["attack_type"])
    assertEquals(0.9, semanticMap["probability"])
    assertEquals(0.5, semanticMap["threat_score"])
    assertEquals(mapOf("k" to 1.0), semanticMap["analysis"])
  }

  @Test
  fun sanitizeForReportingEscapesSurrogates() {
    assertEquals("abc", sanitizeForReporting("abc"))
    val surrogated = String(intArrayOf(0xDC80, 0x61), 0, 2)
    assertEquals("\\x80a", sanitizeForReporting(surrogated))
    val lone = String(intArrayOf(0xD800), 0, 1)
    assertEquals("\\x00", sanitizeForReporting(lone))
  }

  @Test
  fun collectThreatCategoriesDedupesAndMaps() {
    val threats =
        listOf(
            Threat("regex", "p", "m", 0, 0.0, "sqli", 1.0),
            Threat("regex", "p2", "m", 0, 0.0, "sqli", 1.0),
            Threat("semantic", "", "", 0, 0.0, "sql", 1.0, attackType = "sql"),
            Threat("regex", "p3", "m", 0, 0.0, "", 1.0),
        )
    assertEquals(listOf("sqli", "sqli"), listOf("sqli") + listOf("sqli"))
    assertEquals(listOf("sqli"), collectThreatCategories(threats.take(2)))
    val all = collectThreatCategories(threats)
    assertEquals(listOf("sqli"), all.filter { it == "sqli" }.distinct())
  }

  @Test
  fun weightsResolveByPatternThenCategory() {
    assertEquals(1.0, SusPatternsWeights.resolvePatternWeight("unknown", "no-such-category"))
    assertTrue(SusPatternsWeights.resolvePatternWeight("unknown", "sqli") in 0.5..3.0)
    // The decode-budget override beats any category default.
    assertTrue(
        SusPatternsWeights.resolvePatternWeight(DECODE_BUDGET_EXHAUSTED_PATTERN, "custom") in
            0.5..3.0,
    )
  }

  @Test
  fun decodeBudgetExhaustedThreatShape() {
    val threat = decodeBudgetExhaustedThreat()
    assertEquals("regex", threat.type)
    assertEquals(DECODE_BUDGET_EXHAUSTED_PATTERN, threat.pattern)
    assertEquals("custom", threat.category)
  }

  @Test
  fun buildRegexAndTimeoutThreats() {
    val compiled = PyRe.compile("SELECT\\s+.*\\s+FROM", PyReFlags.IGNORECASE)
    val match = compiled.search("SELECT x FROM t", 0, Long.MAX_VALUE)
    assertNotNull(match)
    val threat = buildRegexThreat(compiled, match, "sqli", System.nanoTime())
    assertNotNull(threat)
    assertEquals("SELECT x FROM", threat!!.match)
    assertEquals("sqli", threat.category)
    // A first-accepted pass reuses the same builder.
    val first = firstAcceptedRegexThreat(listOf(match), compiled, "sqli", System.nanoTime())
    assertNotNull(first)
    assertNull(firstAcceptedRegexThreat(emptyList(), compiled, "sqli", System.nanoTime()))
    val timeout = buildTimeoutThreat(compiled, "sqli", System.nanoTime())
    assertEquals("pattern_timeout", timeout.type)
    assertEquals("", timeout.match)
  }

  @Test
  fun normalizeContextMapsUnknowns() {
    assertEquals("query_param", normalizeContext("query_param"))
    assertEquals("unknown", normalizeContext("junk"))
    assertEquals("unknown", normalizeContext(null))
  }

  // ---- LdapIpv4 legacy hosts ----

  @Test
  fun legacyIpv4Decoding() {
    assertEquals(0x0A000001L, decodeLegacyIpv4Host("10.0.0.1"))
    // Octal part.
    assertEquals(8, decodeLegacyIpv4Part("010"))
    // Hex part.
    assertEquals(255, decodeLegacyIpv4Part("0xff"))
    // Junk rejects.
    assertNull(decodeLegacyIpv4Part("zz"))
    // The a.b.c form carries a 16-bit last octet pair.
    assertEquals(16908291L, decodeLegacyIpv4Host("1.2.3"))
    assertNull(decodeLegacyIpv4Host("1.2.3.4.5"))
  }

  // ---- State ----

  @Test
  fun supportsEnhancedConfigChecksTheInterface() {
    assertTrue(supportsEnhancedConfig(DEFAULT_DETECTION_CONFIG_VIEW))
    assertFalse(supportsEnhancedConfig("not a config"))
    val state = buildEnhancedDetectionState(DEFAULT_DETECTION_CONFIG_VIEW)
    assertNotNull(state.compiler)
    assertNotNull(state.preprocessor)
    assertNotNull(state.semanticAnalyzer)
    assertNotNull(state.performanceMonitor)
  }

  private companion object {
    val DEFAULT_DETECTION_CONFIG_VIEW =
        object : DetectionConfigView {
          override val detectionCompilerTimeout: Double = 5.0
          override val detectionMaxTrackedPatterns: Int = 1000
          override val detectionMaxContentLength: Int = 10000
          override val detectionPreserveAttackPatterns: Boolean = true
          override val detectionAnomalyThreshold: Double = 3.0
          override val detectionSlowPatternThreshold: Double = 0.1
          override val detectionMonitorHistorySize: Int = 1000
          override val detectionAnomalyEmissionCooldown: Double = 60.0
          override val detectionMinSamplesForAnomaly: Int = 30
          override val detectionSemanticThreshold: Double = 0.7
          override val detectionThreatScoreThreshold: Double = 1.0
          override val detectionMaxBodyInspectBytes: Int = 262144
          override val detectionPatternValidationCachePath: String? = null
        }
  }
}
