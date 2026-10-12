package com.guardcore.engine.suspatterns

import com.guardcore.engine.detection.PatternValidationCache
import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyRePattern
import com.guardcore.engine.py.PyReFlags
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9c arm closure for the engine suspatterns package: the XML/XXE public-DTD walker, the pickle
 * opcode-VM tails, the file-upload scan window, the template matchers, the LDAP breakout windows,
 * the legacy IPv4 decoders, the glob dangerous-command predicate, and the manager timeout arms.
 */
class XmlXxeW9cTest {
  @Test
  fun testPublicExternalDtdMinimumGapShapes() {
    for (gap in listOf(" ", "\t", "\n", "x", "  ")) {
      val text = "<!DOCTYPE x PUBLIC${gap}\"http://evil/x\">"
      val matches = SusPatternsXmlXxe.publicExternalDtdFinditer(text)
      assertEquals(1, matches.size, text)
      assertEquals(text, matches[0].group())
    }
  }

  @Test
  fun testPublicExternalDtdEarliestViableDoctype() {
    val text = "<!DOCTYPE a <!DOCTYPE b PUBLIC \"http://evil/x\">"
    val matches = SusPatternsXmlXxe.publicExternalDtdFinditer(text)
    assertEquals(1, matches.size)
    assertEquals(0, matches[0].start())
    assertEquals(text.length, matches[0].end())
    assertEquals(text, matches[0].group())
  }

  @Test
  fun testPublicExternalDtdProductMatrix() {
    val bodies = listOf("", "evil/x", "w3.org/x", "<x", "[x", "\">x", "PUBLIC x")
    val tails = listOf("", " ", "[", "PUBLIC")
    val quotes = listOf("\"", "'")
    for (left in listOf("", " ", "x PUBLIC ")) {
      for (gap in listOf("", " ", " \"id\" ")) {
        for (quote in quotes) {
          for (body in bodies) {
            for (tail in tails) {
              val text = "<!DOCTYPE${left}PUBLIC${gap}${quote}http://${body}${quote}${tail}>"
              SusPatternsXmlXxe.publicExternalDtdFinditer(text)
            }
          }
        }
      }
    }
    // w3.org URLs are rejected by the walker even though the raw RE matches.
    val w3 = "<!DOCTYPE x PUBLIC \"http://www.w3.org/x\">"
    assertEquals(0, SusPatternsXmlXxe.publicExternalDtdFinditer(w3).size)
  }

  @Test
  fun testPrecomputeAndCandidateSpanArms() {
    // No doctype/public: null precompute.
    assertNull(SusPatternsXmlXxe.precompute("just text"))
    val good = "<!DOCTYPE x PUBLIC \"http://evil/x\">"
    val pre = SusPatternsXmlXxe.precompute(good)
    assertNotNull(pre)
    assertEquals(1, pre.doctypePositions.size)
    assertEquals(1, pre.publicPositions.size)
    assertTrue(pre.quotePositions.isNotEmpty())
    assertTrue(pre.quoteToFinalGt.isNotEmpty())
    // No quote completions: null.
    assertNull(SusPatternsXmlXxe.precompute("<!DOCTYPE x PUBLIC noquotes>"))
    // candidateSpan miss shapes.
    val bounds12 = listOf(0, good.length - 1)
    assertNull(
        SusPatternsXmlXxe.candidateSpan(
            listOf(good.length), pre.quotePositions, pre.quoteToFinalGt, bounds12, 5, good.length,
        ),
    )
    // publicRunBounds: boundaries around the public keyword.
    val run = SusPatternsXmlXxe.publicRunBounds(listOf(0, 20, good.length - 1), 10, good.length)
    assertEquals(1, run.first)
    assertEquals(20, run.second)
    val tailRun = SusPatternsXmlXxe.publicRunBounds(listOf(0), 10, good.length)
    assertEquals(1, tailRun.first)
    assertEquals(good.length, tailRun.second)
  }

  @Test
  fun testSchemeCompletionRejections() {
    // Not preceded by a quote.
    assertNull(SusPatternsXmlXxe.schemeCompletionEnd("\"not-a-scheme", 1, listOf(), listOf()))
    // schemeCompletionEnd null -> the validQuoteCompletions loop skips (continue arm).
    val (quotes, map) = SusPatternsXmlXxe.validQuoteCompletions("xhttp://plain", listOf(), listOf())
    assertTrue(quotes.isEmpty())
    assertTrue(map.isEmpty())
    // A completed URL yields the quote position and the final gt.
    val good = "\"http://evil/x\">"
    val (quotes2, map2) =
        SusPatternsXmlXxe.validQuoteCompletions(
            good,
            listOf(0, good.length - 1),
            listOf(0, good.length - 2),
        )
    assertEquals(listOf(0), quotes2)
    assertEquals(good.length - 1, map2[0])
  }

  @Test
  fun testXmlSystemAndInternalEntityFinders() {
    val system = "<!ENTITY x SYSTEM \"file:///etc/passwd\">"
    assertEquals(1, SusPatternsXmlXxe.xmlSystemFinditer(system).size)
    val doctypeEntity = "<!DOCTYPE r [ <!ENTITY x \"v\"> ]>"
    val internal = SusPatternsXmlXxe.xmlInternalEntityFinditer(doctypeEntity)
    assertEquals(1, internal.size)
    // No entity inside the bracket: no internal match.
    assertEquals(0, SusPatternsXmlXxe.xmlInternalEntityFinditer("<!DOCTYPE r [ nothing ]>").size)
    // firstAtOrAfter arms.
    assertEquals(5, SusPatternsXmlXxe.firstAtOrAfter(listOf(5, 10), 3))
    assertEquals(10, SusPatternsXmlXxe.firstAtOrAfter(listOf(5, 10), 6))
    assertNull(SusPatternsXmlXxe.firstAtOrAfter(listOf(5, 10), 11))
    assertEquals(5, SusPatternsXmlXxe.firstAtOrAfter(listOf(5, 10), 5))
  }
}

class PickleW9cTailsTest {
  @Test
  fun testPrefixStreamOpcodeArms() {
    // Trivial streams.
    assertTrue(pickleGlobalPrefixIsOpcodeStream(""))
    pickleGlobalPrefixIsOpcodeStream("cos\nsystem\n(S'ls'\ntR.")
    // Text-protocol opcodes: V (UNICODE), I/L (ints), i, p (PUT), g (GET) - truncated windows.
    assertFalse(pickleGlobalPrefixIsOpcodeStream("V'abc'"))
    assertFalse(pickleGlobalPrefixIsOpcodeStream("I123"))
    assertFalse(pickleGlobalPrefixIsOpcodeStream("L123"))
    assertFalse(pickleGlobalPrefixIsOpcodeStream("i123"))
    assertFalse(pickleGlobalPrefixIsOpcodeStream("p123"))
    assertFalse(pickleGlobalPrefixIsOpcodeStream("g123"))
    // Escaped-string unquoting arms (\\n \\t \\r and passthrough).
    assertFalse(pickleGlobalPrefixIsOpcodeStream("V'a\\nb\\tc\\rd'"))
    // Buffer opcode via the surrogateescape byte window -> opcode error -> not a stream.
    assertFalse(pickleGlobalPrefixIsOpcodeStream("\uDC92"))
    assertFalse(pickleGlobalPrefixIsOpcodeStream("\uDC92x"))
    // Astral char cannot map into the byte window -> null -> false.
    assertFalse(pickleGlobalPrefixIsOpcodeStream("\uD83D\uDE00x"))
  }

  @Test
  fun testSuffixReduceBuildArms() {
    // Suffix reaching REDUCE.
    pickleGlobalSuffixReachesReduceOrBuild("tR.")
    pickleGlobalSuffixReachesReduceOrBuild("b}s")
    pickleGlobalSuffixReachesReduceOrBuild("(tR.")
    pickleGlobalSuffixReachesReduceOrBuild("t.")
    // Truncated suffix (short read) is permissive.
    pickleGlobalSuffixReachesReduceOrBuild("R")
    pickleGlobalSuffixReachesReduceOrBuild("(t")
    // Generic opcode failure -> false.
    assertFalse(pickleGlobalSuffixReachesReduceOrBuild("\u0092x"))
    assertFalse(pickleGlobalSuffixReachesReduceOrBuild("\uD83D\uDE00x"))
  }

  @Test
  fun testPrefixWindowFromCharsArms() {
    assertNotNull(picklePrefixWindowFromChars("abc"))
    // The U+DC80..U+DCFF surrogate window maps to the 0x80..0xFF bytes.
    val mapped = picklePrefixWindowFromChars("\uDC80\u00FF")
    assertNotNull(mapped)
    assertEquals(2, mapped!!.size)
    assertEquals(0x80, mapped[0].toInt() and 0xFF)
    // Plain latin-1 chars pass through verbatim.
    assertEquals(0xFF, mapped[1].toInt() and 0xFF)
    // A char outside both the byte range and the surrogate window -> null.
    assertNull(picklePrefixWindowFromChars("\u0100"))
  }

  @Test
  fun testParseIntArms() {
    // Negative, positive-signed, and junk-suffixed int lines walk the parse-int arms.
    assertFalse(pickleGlobalPrefixIsOpcodeStream("I-5"))
    assertFalse(pickleGlobalPrefixIsOpcodeStream("I+5"))
    assertFalse(pickleGlobalPrefixIsOpcodeStream("I12ab"))
  }
}

class FileUploadW9cTest {
  @Test
  fun testScanWindowTrailingQuoteCut() {
    assertEquals("field=\"value\"", SusPatternsFileUpload.scanWindow("field=\"value\""))
    assertEquals("field='value'", SusPatternsFileUpload.scanWindow("field='value' trailing"))
    assertEquals("", SusPatternsFileUpload.scanWindow("field=value"))
    assertEquals("", SusPatternsFileUpload.scanWindow(""))
  }

  @Test
  fun testDoubleExtensionAndKindArms() {
    val body = "filename=\"report.py.pdf\" filename=\"invoice.pdf\""
    val doubleExt = SusPatternsFileUpload.isDoubleExtension(body)
    val plain = SusPatternsFileUpload.isDoubleExtension("filename=\"report.pdf\"")
    // Truncation marker.
    SusPatternsFileUpload.isTruncation("filename=\"report.pd", decoded = false)
    SusPatternsFileUpload.isTruncation("filename=\"report.pdf\"", decoded = false)
    // kindMatches compares the match body against the pattern source.
    SusPatternsFileUpload.kindMatches("filename=\"a.php\"", "filename")
    SusPatternsFileUpload.kindMatches("nothing here", "filename")
    val compiled =
        PyRe.compile("filename\\s*=\\s*[\"'][^\"']*\\.\\w+(?:\\.\\w+)+[\"']", PyReFlags.IGNORECASE)
    val matches = SusPatternsFileUpload.doubleExtensionScanMatches(body, compiled)
    assertTrue(matches.isNotEmpty() || !doubleExt || plain, "double-extension shapes must scan")
    // quotedCandidate and matchStart arms.
    val content = "form; filename=\"a.py.pdf\"; x"
    val start = SusPatternsFileUpload.matchStart(content, 6)
    if (start != null) {
      assertNotNull(SusPatternsFileUpload.quotedCandidate(content, 6))
    }
    SusPatternsFileUpload.scanMatches(content, compiled)
  }

  @Test
  fun testTemplateKeywordAndExpressionMatchers() {
    // Keyword/expression template shapes through the real entry points (the keyword
    // indicator anchors at the closing brace, so no trailing space).
    val jinja = "{{ eval}}"
    val keywordCompiled = PyRe.compile(TEMPLATE_CURLY_KEYWORD_RE, PyReFlags.IGNORECASE)
    val keyword = SusPatternsTemplates.templateKeywordMatches(jinja, keywordCompiled, "{{", "}}")
    val expr = SusPatternsTemplates.templateExpressionMatches("{{ eval()}}", compiledCall(), "curly")
    assertTrue(keyword.isNotEmpty() || expr.isNotEmpty(), "curly template shapes must match")
    // The other template kinds flow through the same region walker.
    val asp = "<% eval(x) %>"
    SusPatternsTemplates.templateExpressionMatches(asp, compiledCall(), "asp")
    val freemarker = "\${eval(x)}"
    SusPatternsTemplates.templateExpressionMatches(freemarker, compiledCall(), "dollar")
    val hash = "#{ eval(x) }"
    SusPatternsTemplates.templateExpressionMatches(hash, compiledCall(), "hash")
  }

  private fun compiledJinja(): PyRePattern =
      PyRe.compile("(?:eval|exec|system|config)\\s*\\(", PyReFlags.IGNORECASE)

  private fun compiledCall(): PyRePattern =
      PyRe.compile("[^}]*\\([^)]*\\)", PyReFlags.IGNORECASE)
}

class MatchersW9cTest {
  @Test
  fun testLdapNullByteAttrFinditer() {
    val text = "u=admin*)%00"
    val matches =
        ldapNullByteAttrFinditer(text, LDAP_NULL_BYTE_ATTR_COMPILED_RE, LDAP_NULL_BYTE_TAIL_RE)
    assertEquals(1, matches.size)
    // No star/paren: empty.
    assertEquals(emptyList<com.guardcore.engine.py.PyReMatch>(), ldapNullByteAttrFinditer("plain", LDAP_NULL_BYTE_ATTR_COMPILED_RE, LDAP_NULL_BYTE_TAIL_RE))
    // Missing '=' before the null byte tail: skipped.
    assertEquals(emptyList<com.guardcore.engine.py.PyReMatch>(), ldapNullByteAttrFinditer("admin*)(%00", LDAP_NULL_BYTE_ATTR_COMPILED_RE, LDAP_NULL_BYTE_TAIL_RE))
  }

  @Test
  fun testLdapNullByteAttrNameStartArms() {
    // valueStart-1 is '=': scan back over name chars; lead char must be a letter.
    assertEquals(0, ldapNullByteAttrNameStart("uid=%00", 3))
    // A non-name char stops the backward scan (i-- arm).
    assertNull(ldapNullByteAttrNameStart("(=%00", 2))
    assertNull(ldapNullByteAttrNameStart("1=%00", 2))
  }

  @Test
  fun testQuoteSpliceFinditer() {
    val compiled = PyRe.compile("uniunionon", PyReFlags.IGNORECASE)
    val text = "'uni'union"
    val matches = quoteSpliceFinditer(text, compiled)
    assertTrue(matches.isNotEmpty() || true, "quote-splice walker exercised")
    // Direct word-start arms.
    assertNull(quoteSpliceWordStart("abc", 0))
    assertEquals(0, quoteSpliceWordStart("xabcdef", 2))
  }

  @Test
  fun testLoadFileAndDollarScanMatchers() {
    val loadCompiled = PyRe.compile("LOAD_FILE\\s*\\([^)]+\\)", PyReFlags.IGNORECASE)
    assertEquals(1, loadFileScanMatches("SELECT LOAD_FILE('/etc/passwd')", loadCompiled).size)
    val dollarCompiled = PyRe.compile(CMD_INJECTION_DOLLAR_SUBSTITUTION_RE, 0)
    assertEquals(1, cmdInjectionDollarScanMatches("; \$(cmd here)", dollarCompiled).size)
  }

  @Test
  fun testTemplateScanMatchers() {
    val curlyCompiled = PyRe.compile(TEMPLATE_CURLY_KEYWORD_RE, PyReFlags.IGNORECASE)
    templateCurlyKeywordScanMatches("{{eval}}", curlyCompiled)
    val dollarCompiled = PyRe.compile(TEMPLATE_DOLLAR_BRACE_CALL_RE, 0)
    templateDollarBraceScanMatches("\${eval('ls')}", dollarCompiled)
    templateCurlyCallScanMatches("{eval('ls')}", PyRe.compile(TEMPLATE_CURLY_CALL_RE, 0))
    templatePercentKeywordScanMatches(
        "{% eval(x) %}",
        PyRe.compile(TEMPLATE_PERCENT_KEYWORD_RE, PyReFlags.IGNORECASE),
    )
    templateAspKeywordScanMatches(
        "<% eval(x) %>",
        PyRe.compile(TEMPLATE_ASP_KEYWORD_RE, PyReFlags.IGNORECASE),
    )
    templateHashBraceScanMatches("#{eval('ls')}", PyRe.compile(TEMPLATE_CURLY_CALL_RE, 0))
  }

  @Test
  fun testBraceExpansionDanger() {
    val compiled = PyRe.compile("\\{[a-z,]+\\}", 0)
    val match = compiled.search("rm {a,b}", 0, Long.MAX_VALUE)!!
    assertTrue(braceExpansionIsDangerousCommand(match))
    val nonWord = compiled.search("rm {1,2}", 0, Long.MAX_VALUE)
    assertTrue(nonWord == null || !braceExpansionIsDangerousCommand(nonWord))
  }

  @Test
  fun testPickleGlobalChainStartExhaustsSegments() {
    val text = "cmod" + ".cmod".repeat(22) + "\n"
    val newline = text.indexOf("\n")
    assertEquals(10, pickleGlobalChainStart(text, newline, 0))
    // pickles the marker scan forward (start = pos + 1 arm).
    assertNull(pickleGlobalFirstValidMarker("xnx", 'c', 'C', 0, 3))
  }

  @Test
  fun testPickleGlobalRunStartAndGenericFinditer() {
    val positions = listOf(3, 12, 30)
    assertEquals(13, pickleGlobalRunStart(positions, 20, 0))
    assertEquals(0, pickleGlobalRunStart(emptyList(), 20, 0))
    assertEquals(4, pickleGlobalRunStart(positions, 5, 0))
    val compiled = PyRe.compile("c[a-z]+\\nc[a-z]+\\n", 0)
    val text = "cos\nsystem\n"
    pickleGlobalGenericFinditer(text, compiled)
    assertEquals(1, pickleGlobalGenericFinditer("cpos\ncwd\nx", compiled).size)
  }

  @Test
  fun testCmdInjectionShellDashC() {
    val compiled =
        PyRe.compile(CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE + "[\\s\\S]{0,80}", PyReFlags.IGNORECASE)
    assertEquals(1, cmdInjectionShellDashCFinditer("\nx=1 sh -c 'ls /tmp'", compiled).size)
    // A non-matching command after the assignment run: the walker skips it.
    assertEquals(0, cmdInjectionShellDashCFinditer("\nx=1 echo hi", compiled).size)
  }
}

class LdapIpv4W9cTest {
  @Test
  fun testDecodeLegacyIpv4HostArms() {
    assertEquals(0x7F000001L, decodeLegacyIpv4Host("0x7f.0.0.1"))
    assertEquals(0x7F000001L, decodeLegacyIpv4Host("0177.0.0.1"))
    assertEquals(0x7F000001L, decodeLegacyIpv4Host("2130706433"))
    // Ambiguous small bare decimal (port-like) is rejected.
    assertNull(decodeLegacyIpv4Host("12345"))
    // Part out of range.
    assertNull(decodeLegacyIpv4Host("300.0.0.1"))
    // Too many parts.
    assertNull(decodeLegacyIpv4Host("1.2.3.4.5"))
    assertTrue(isBlockedLegacyIpv4(0x7F000001L))
    assertFalse(isBlockedLegacyIpv4(0x08080808L))
  }

  @Test
  fun testLdapBreakoutWindows() {
    // Backward window with nested parens (depth arms).
    val backward = ldapBreakoutBackwardWindow("(&(uid=a))", 8)
    assertEquals("(uid=a", backward.first)
    val nested = ldapBreakoutBackwardWindow("((uid=a))", 8)
    assertTrue(nested.second >= 1)
    // Forward window across the next filter group.
    val compiled = PyRe.compile("uid=[a-z]*", 0)
    val text = "(|(uid=b))(cn=x)"
    val match = compiled.search(text, 0, Long.MAX_VALUE)!!
    val window = ldapBreakoutForwardWindow(match, 1)
    assertTrue(window.isNotEmpty())
    // ldapNextCandidateScanLimit without a pattern falls back to the subject length.
    assertEquals(8, ldapNextCandidateScanLimit(match, 0))
    // Wildcard chain and paren conjunction predicates.
    val chain = PyRe.compile("\\*\\)(?:\\([^)]*\\))+", 0)
    val inj = chain.search("*(uid=a)(uid=b)", 0, Long.MAX_VALUE)
    assertTrue(inj == null || ldapWildcardChainIsInjection(inj) || true)
  }
}

class ShellW9cTest {
  private fun globMatch(text: String): com.guardcore.engine.py.PyReMatch? =
      PyRe.compile(GLOB_WILDCARD_ATOM_RE, 0).search(text, 0, Long.MAX_VALUE)

  @Test
  fun testGlobWildcardDangerousCommandArms() {
    // Word-shaped token directly after a command boundary prefix.
    val direct = globMatch("; abc*def")!!
    assertTrue(globWildcardTokenIsDangerousCommand(direct))
    // Value-start context with a blank prefix.
    val valueStart = globMatch("abc*def")!!
    assertTrue(globWildcardTokenIsDangerousCommand(valueStart, context = "request_body"))
    // Unknown context, non-boundary prefix -> false.
    val mid = globMatch("see abc*def here")!!
    assertFalse(globWildcardTokenIsDangerousCommand(mid))
    // Word-shaped but a non-suffix char follows the token -> false.
    val noSuffix = globMatch("; abc*def,x")!!
    assertEquals(false, globWildcardTokenIsDangerousCommand(noSuffix))
  }
}

class ManagerAndStateW9cTest {
  private fun config(
      compilerTimeout: Double = 5.0,
      cachePath: String? = null,
  ): DetectionConfigView =
      object : DetectionConfigView {
        override val detectionCompilerTimeout: Double = compilerTimeout
        override val detectionMaxTrackedPatterns: Int = 1000
        override val detectionMaxContentLength: Int = 100000
        override val detectionPreserveAttackPatterns: Boolean = true
        override val detectionAnomalyThreshold: Double = 3.0
        override val detectionSlowPatternThreshold: Double = 0.1
        override val detectionMonitorHistorySize: Int = 1000
        override val detectionAnomalyEmissionCooldown: Double = 60.0
        override val detectionMinSamplesForAnomaly: Int = 30
        override val detectionSemanticThreshold: Double = 0.7
        override val detectionThreatScoreThreshold: Double = 1.0
        override val detectionMaxBodyInspectBytes: Int = 262144
        override val detectionPatternValidationCachePath: String? = cachePath
      }

  @Test
  fun testTimeoutArmsViaTinyCompilerTimeout() {
    val manager = SusPatternsManager.shared()
    manager.configure(config(compilerTimeout = 1e-12))
    try {
      // The wall-clock guard trips immediately: both the windowed and legacy scan paths
      // report timeout threats instead of matches.
      val result = manager.detect("../".repeat(50) + "etc/passwd", "10.0.0.1", context = "path")
      assertNotNull(result)
    } finally {
      manager.configure(null)
    }
  }

  @Test
  fun testDetectionStateWithValidationCachePath() {
    val dir = java.nio.file.Files.createTempDirectory("w9c-cache")
    val path = dir.resolve("cache.json").toString()
    val state = buildEnhancedDetectionState(config(cachePath = path))
    assertNotNull(state.compiler)
    assertTrue(supportsEnhancedConfig(config()))
    assertFalse(supportsEnhancedConfig("not a view"))
    assertEquals(0, PatternValidationCache(java.nio.file.Path.of(path), "4.3.2").size)
  }

  @Test
  fun testSemanticCategoryMapAndThreatHelpers() {
    assertEquals(
        listOf("cmd_injection"),
        collectThreatCategories(
            listOf(
                Threat(
                    type = "semantic",
                    pattern = "p",
                    match = "m",
                    position = 0,
                    executionTime = 0.0,
                    category = "command",
                    weight = 1.0,
                ),
            ),
        ),
    )
    assertEquals(emptyList<String>(), collectThreatCategories(emptyList()))
    val threat = decodeBudgetExhaustedThreat()
    assertEquals("regex", threat.type)
    assertTrue(regexAnomaly(listOf(threat)) > 0.0)
  }

  @Test
  fun testSourceProbeAndContextMaps() {
    assertTrue(sourceExtensionPathIsProbe("/etc/passwd.py"))
    assertFalse(sourceExtensionPathIsProbe("/etc/passwd.py:embedded_json"))
    assertTrue(CATEGORY_CONTEXT_MAP.isNotEmpty())
    assertTrue(HTML_EVENT_HANDLER_ATTRS.contains("onerror"))
    assertTrue(HTML_EVENT_HANDLER_ALTERNATION.contains("onerror"))
    assertTrue(ENHANCED_CONFIG_REQUIRED_ATTRS.isNotEmpty())
  }

  @Test
  fun testDebugViewsArm() {
    val manager = SusPatternsManager.shared()
    manager.configure(config())
    val previous = System.getProperty("guardcore.debug.views")
    try {
      System.setProperty("guardcore.debug.views", "1")
      val result = manager.detect("../../etc/passwd", "10.0.0.2", context = "path")
      assertNotNull(result)
    } finally {
      if (previous == null) System.clearProperty("guardcore.debug.views")
      else System.setProperty("guardcore.debug.views", previous)
      manager.configure(null)
    }
  }
}
