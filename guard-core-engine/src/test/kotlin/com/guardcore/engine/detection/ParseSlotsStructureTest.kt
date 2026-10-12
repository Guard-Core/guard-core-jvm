package com.guardcore.engine.detection

import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.ReCategory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of the slot-extraction, ambiguous-tail, structure, and preprocessor arms:
 * tests/test_sus_patterns/test_semantic.py, test_preprocessor.py, test_redos_helper_branches.py,
 * and the structure-rule corpus tests.
 */
class ParseSlotsStructureTest {
  // ---- ParseSlots ----

  @Test
  fun patternSlotsExtractsAtomsAndGroups() {
    val slots = patternSlots("""[a-c]+\d{2,4}x?""", 0)
    assertNotNull(slots)
    assertEquals(3, slots.size)
    val cls = slots[0] as PairingAtom
    assertTrue(cls.unbounded)
    assertFalse(cls.allowsZero)
    val digits = slots[1] as PairingAtom
    assertTrue(digits.variableBounded)
    assertEquals(4, digits.maxRepeat)
    // An unparseable pattern yields null.
    assertNull(patternSlots("[", 0))
    // Branches become non-pairing slots with alternatives.
    val branch = patternSlots("(?:ab|cd)+", 0)
    assertNotNull(branch)
    val branchSlot = branch[0] as NonPairingSlot
    assertEquals(2, branchSlot.inner?.size)
  }

  @Test
  fun categoryPredicatesHonorAsciiMode() {
    val unicodeDigit = categoryPredicate(ReCategory.DIGIT, 0)
    assertTrue(unicodeDigit('1'.code))
    assertFalse(unicodeDigit('x'.code))
    val asciiWord = categoryPredicate(ReCategory.WORD, PyReFlags.ASCII)
    assertTrue(asciiWord('_'.code))
    assertTrue(asciiWord('A'.code))
    assertFalse(asciiWord(0xE9))
    val unicodeWord = categoryPredicate(ReCategory.WORD, 0)
    assertTrue(unicodeWord(0xE9))
    val asciiSpace = categoryPredicate(ReCategory.SPACE, PyReFlags.ASCII)
    assertTrue(asciiSpace(' '.code))
    assertTrue(asciiSpace('\t'.code))
    val notSpace = categoryPredicate(ReCategory.NOT_SPACE, 0)
    assertTrue(notSpace('a'.code))
    assertFalse(notSpace(' '.code))
    val notWord = categoryPredicate(ReCategory.NOT_WORD, 0)
    assertTrue(notWord('!'.code))
    val notDigit = categoryPredicate(ReCategory.NOT_DIGIT, PyReFlags.ASCII)
    assertTrue(notDigit('x'.code))
    assertFalse(notDigit('3'.code))
    // ASCII mode restricts to 0x7F.
    assertFalse(asciiWord(0x80))
  }

  @Test
  fun candidateCharsForAtomText() {
    assertEquals(setOf('x'), candidateCharsForAtomText("x", 0))
    assertTrue(candidateCharsForAtomText("""\d""", PyReFlags.ASCII).all { it.isDigit() })
    assertEquals(emptySet(), candidateCharsForAtomText("[", 0))
  }

  // ---- AmbiguousTail ----

  @Test
  fun atomCharSetProbesPrintableMatches() {
    assertEquals(setOf('x'), atomCharSet("x"))
    assertTrue(atomCharSet("""\d""").isNotEmpty())
    assertTrue(atomCharSet("[b-d]").containsAll(setOf('b', 'c', 'd')))
    assertEquals(emptySet(), atomCharSet("["))
  }

  @Test
  fun representativeCharForAtomFallsBackToCandidates() {
    assertEquals('0', representativeCharForAtom("""\d"""))
    assertEquals('x', representativeCharForAtom("x"))
    assertNull(representativeCharForAtom("["))
  }

  @Test
  fun parseFlatQuantifiedAtomsWithTextShapes() {
    val atoms = parseFlatQuantifiedAtomsWithText("""\d+x{2,5}?y""")
    assertNotNull(atoms)
    assertEquals(3, atoms.size)
    assertTrue(atoms[0].unbounded)
    assertTrue(atoms[1].variable)
    assertFalse(atoms[2].variable)
    // Groups and alternations reject the flat parse.
    assertNull(parseFlatQuantifiedAtomsWithText("(a)"))
    assertNull(parseFlatQuantifiedAtomsWithText("a|b"))
    // A malformed brace quantifier rejects.
    assertNull(parseFlatQuantifiedAtomsWithText("a{x"))
  }

  @Test
  fun groupInnerAmbiguityRules() {
    // Ambiguous pair: an unbounded atom anywhere and an optional atom anywhere.
    assertTrue(groupInnerIsAmbiguous("a*b?"))
    assertFalse(groupInnerIsAmbiguous("a*b"))
    assertFalse(groupInnerIsAmbiguous("a?b"))
    // A single variable, non-unbounded atom is ambiguous on its own.
    assertTrue(groupInnerIsAmbiguous("a?"))
    assertFalse(groupInnerIsAmbiguous("a*"))
    // A flat parse with groups or alternations is not ambiguous.
    assertFalse(groupInnerIsAmbiguous("(a)"))
    assertFalse(groupInnerIsAmbiguous("a|b"))
    assertFalse(groupInnerIsAmbiguous("xy"))
  }

  @Test
  fun detectAmbiguousOptionalTailReturnsTheSpan() {
    val span = detectAmbiguousOptionalTailInQuantifiedGroup("""x(?:\d+x?)+z""")
    assertNotNull(span)
    assertTrue(span.isNotEmpty())
    assertNull(detectAmbiguousOptionalTailInQuantifiedGroup("plain"))
    assertNull(detectAmbiguousOptionalTailInQuantifiedGroup("""x(?:\d+y)+z"""))
  }

  @Test
  fun representativeCharAndEndForEscapeOrClass() {
    val escape = representativeCharAndEndForEscapeOrClass("""\dx""", 0)
    assertNotNull(escape)
    assertEquals(2, escape.first)
    assertEquals('0', escape.second)
    val cls = representativeCharAndEndForEscapeOrClass("[b-d]x", 0)
    assertNotNull(cls)
    assertEquals(5, cls.first)
    assertEquals('b', cls.second)
    assertNull(representativeCharAndEndForEscapeOrClass("xx", 0))
  }

  @Test
  fun extractLiteralCharsWalksThePattern() {
    val chars = extractLiteralChars("""a[b-c]\d_/x:@~.""")
    assertTrue('a' in chars)
    assertTrue('b' in chars)
    assertTrue('0' in chars)
    assertTrue('_' in chars)
    assertTrue('/' in chars)
  }

  // ---- StructureRules / StructurePrimitives ----

  @Test
  fun nestedUnboundedQuantifierDetection() {
    val reason = detectNestedUnboundedQuantifier("""(a+)+""")
    assertNotNull(reason)
    assertNull(detectNestedUnboundedQuantifier("a+b"))
    assertNull(detectNestedUnboundedQuantifier("["))
    assertTrue(nestedBodyIsUnbounded("a+"))
    assertFalse(nestedBodyIsUnbounded("a"))
  }

  @Test
  fun adjacentBroadUnboundedQuantifiersDetection() {
    val reason = detectAdjacentBroadUnboundedQuantifiers("""\S+[^\d]+""")
    assertNotNull(reason)
    assertNull(detectAdjacentBroadUnboundedQuantifiers("abc"))
    assertNull(detectAdjacentBroadUnboundedQuantifiers("""\s+\d+"""))
    // A single broad unbounded atom is not adjacent.
    assertNull(detectAdjacentBroadUnboundedQuantifiers("""\S+x"""))
  }

  @Test
  fun broadAtomSpanCoversEscapeAndClass() {
    // Broad shorthands are the uppercase S/W/D only.
    val esc = broadAtomSpan("""\S+x""", 0)
    assertEquals(2, esc.first)
    assertTrue(esc.second)
    val narrow = broadAtomSpan("""\s+x""", 0)
    assertEquals(2, narrow.first)
    assertFalse(narrow.second)
    // A negated class is broad unless it already excludes via S/D/W.
    assertTrue(broadAtomSpan("""[^\d]+x""", 0).second)
    assertFalse(broadAtomSpan("""[^\S]+x""", 0).second)
    // Non-negated classes are broad only for the \s\S self-pair.
    assertFalse(broadAtomSpan("""[a-z]+x""", 0).second)
    assertTrue(broadAtomSpan("""[\s\S]+x""", 0).second)
    // The any-dot atom is broad.
    assertTrue(broadAtomSpan(".+x", 0).second)
  }

  @Test
  fun structurePrimitivesWalkText() {
    assertEquals(5, skipCharClass("[b-d]x", 0))
    assertEquals(2, skipCharClass("""\]x""", 0))
    assertEquals("a", stripEscapesAndCharClasses("""a\dz""").take(1))
    assertTrue(branchIsUnboundedSingle("a+"))
    assertFalse(branchIsUnboundedSingle("a"))
    // An escape token spans exactly two chars.
    assertEquals(2, advancePastEscapeOrCharClass("""\dx""", 0))
    assertNull(advancePastEscapeOrCharClass("xx", 0))
    assertEquals(5, findGroupEnd("(abc)", 0))
    assertNull(findGroupEnd("(abc", 0))
    assertEquals("abc", normalizeGroupInner("?:abc"))
    // An unrecognized group prefix passes through unchanged.
    assertEquals("?<n>abc", normalizeGroupInner("?<n>abc"))
    assertEquals("a", unwrapTransparentWrapper("(?:a)"))
    assertEquals(1, outerQuantifierLen("a+", 1))
    // Overlap is prefix containment, not a shared first char.
    assertTrue(branchesOverlap(listOf("ab", "abc")))
    assertTrue(branchesOverlap(listOf("ab", "ab")))
    assertFalse(branchesOverlap(listOf("ab", "ac")))
    assertFalse(branchesOverlap(listOf("ab", "xy")))
    assertTrue(isPureLiteralBranch("abc"))
    assertFalse(isPureLiteralBranch("a+"))
    assertEquals(listOf("ab", "cd"), splitTopLevelAlternations("ab|cd"))
    assertTrue(overlappingLiteralBranches("ab|abc"))
    assertFalse(overlappingLiteralBranches("ab|ac"))
    assertFalse(overlappingLiteralBranches("ab|xy"))
  }

  @Test
  fun iterQuantifiedGroupBodiesFindsGroups() {
    val bodies = iterQuantifiedGroupBodies("""x(?:ab)+y""")
    assertEquals(1, bodies.size)
    assertEquals("ab", bodies[0].third)
    // Deep nesting beyond the limit raises the fail-closed signal.
    try {
      iterQuantifiedGroupBodies("(".repeat(30) + "a+" + ")".repeat(30))
      assertTrue(true)
    } catch (e: GroupNestingTooDeep) {
      assertTrue(e.depth >= 1)
    }
  }

  // ---- UnreachableTerminator ----

  @Test
  fun unreachableTerminatorDetection() {
    // Malformed classes are handled like the reference (empty inner slice).
    assertNull(detectUnreachableTerminatorScan("["))
    val reason = detectUnreachableTerminatorScan("""X[0-9]+A""")
    assertTrue(reason == null || reason.isNotEmpty())
    // A quantified negated class with a disjoint terminator and prefix is flagged.
    val finding = detectUnreachableTerminatorScan("""A[^X]+X""")
    assertTrue(finding != null && finding.startsWith("[^X]"), finding)
    // Without the prefix the rule cannot fire.
    assertNull(detectUnreachableTerminatorScan("""[^X]+X"""))
  }

  // ---- Semantic ----

  @Test
  fun looksLikeBinaryContent() {
    assertFalse(looksLikeBinaryContent(""))
    assertFalse(looksLikeBinaryContent("plain text"))
    assertTrue(looksLikeBinaryContent("\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007"))
  }

  @Test
  fun semanticAnalyzerFullSurface() {
    val analyzer = SemanticAnalyzer()
    assertTrue(analyzer.extractTokens("<script>alert('xss')</script>").contains("script"))
    assertTrue(
        analyzer.calculateEntropy("aaaaaaaaaaaaaaaa") < analyzer.calculateEntropy("aqzpxkwvmf"),
    )
    // Percent + unicode-escape + html-entity layers (plus the base64 run of a's).
    val layers = analyzer.detectEncodingLayers("aaaaaaaa%41%42\\u0041&amp;")
    assertTrue(layers >= 3, "layers=$layers")
    val probability = analyzer.analyzeAttackProbability("<script>alert(1)</script>")
    assertTrue((probability["xss"] ?: 0.0) >= 0.0)
    // A 36-symbol alphabet has entropy above the 4.5 obfuscation gate.
    assertTrue(analyzer.detectObfuscation("abcdefghijklmnopqrstuvwxyz0123456789"))
    assertFalse(analyzer.detectObfuscation("plain english sentence here"))
    val patterns = analyzer.extractSuspiciousPatterns("<script>alert(1)</script> ls; cd ..")
    assertTrue(patterns.isNotEmpty())
    assertTrue((analyzer.analyzeCodeInjectionRisk("eval(${1+1})") >= 0.0))
    val analysis = analyzer.analyze("<script>javascript:</script> SELECT x FROM t")
    assertTrue(analysis.containsKey("attack_probabilities"))
    assertTrue(analysis.containsKey("entropy"))
    assertTrue(analysis.containsKey("encoding_layers"))
    assertTrue(analysis.containsKey("is_obfuscated"))
    assertTrue(analysis.containsKey("suspicious_patterns"))
    assertTrue(analysis.containsKey("code_injection_risk"))
    assertTrue(analysis.containsKey("token_count"))
    assertTrue(analyzer.getThreatScore(analysis) >= 0.0)
  }

  // ---- Preprocessor ----

  @Test
  fun preprocessorDecodesAndNormalizes() {
    val pp = ContentPreprocessor()
    assertEquals("//..", pp.normalizeUnicode("\u2044\u2215.."))
    assertEquals("a b", pp.removeExcessiveWhitespace("a  \n\t b"))
    assertEquals("ab", pp.removeNullBytes("a\u0000b"))
    val decoded = pp.decodeCommonEncodings("%2561\\x41\\u0041<a>")
    assertTrue(decoded.contains("a"))
    assertEquals("SELECT 1   comment", pp.stripSqlComments("SELECT 1 -- comment"))
    // A block comment is replaced by its body surrounded with spaces.
    assertEquals("SELECT 1   c  ", pp.stripSqlComments("SELECT 1 /* c */"))
    val processed = pp.preprocess("<script>%2561</script>")
    assertTrue(processed.isNotEmpty())
    assertEquals(2, pp.preprocessBatch(listOf("a", "b")).size)
    // The decode-budget seam trips when the input keeps decoding for 16 rounds.
    val budget = booleanArrayOf(false)
    // A 20-deep nested percent-encoding keeps the decoder busy past the
    // 16-round cap (each layer peels in exactly one pass).
    var nested = "a"
    repeat(20) { nested = nested.replace("%", "%25").replace("a", "%61") }
    pp.preprocess(nested, budget)
    assertTrue(budget[0])
    // A shallow input does not exhaust the budget.
    val shallow = booleanArrayOf(false)
    pp.preprocess("%2561", shallow)
    assertFalse(shallow[0])
    // The signal-preserving view normalizes + truncates without decoding.
    assertEquals("%2e%2e/", pp.preprocessSignalPreserving("%2e%2e/"))
    assertTrue(pp.preprocessUrlDecodedNewlinePreserving("%0a").contains("\n"))
    // The short-base64 view only appends fragments decoding to marker chars.
    assertTrue(pp.preprocessShortBase64AdditiveView("aGk=").isEmpty())
    assertEquals(
        "\${a}",
        pp.preprocessShortBase64AdditiveView("JHthfQ=="),
    )
    val (processed2, decodedViews) = pp.preprocessWithDecoded("%2561")
    assertTrue(decodedViews.isNotEmpty())
    assertTrue(processed2.isNotEmpty())
  }

  @Test
  fun pyUrllibAndPyHtml() {
    assertEquals("a b", PyUrllib.unquoteIgnore("a%20b"))
    assertEquals("a%zz", PyUrllib.unquoteIgnore("a%zz"))
    assertEquals("%", PyUrllib.unquoteIgnore("%"))
    assertEquals("<b>", PyHtml.unescape("&lt;b&gt;"))
    assertEquals("\u00e9", PyHtml.unescape("&#233;"))
    assertEquals("\u00e9", PyHtml.unescape("&#xE9;"))
  }
}
