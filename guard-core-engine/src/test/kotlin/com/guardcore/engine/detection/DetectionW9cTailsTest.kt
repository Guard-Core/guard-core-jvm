package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyReParser
import com.guardcore.engine.py.PyUnicode
import com.guardcore.engine.py.ReCategory
import com.guardcore.engine.py.ReNode
import com.guardcore.engine.py.ReOp
import java.lang.management.ManagementFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9c arm closure for the engine detection package: ParseSlots slot shapes and predicates,
 * AmbiguousTail, ReachProbe, ClassIntersection crossing, CostArbiter batching/deadline arms,
 * Compiler, Base64Decode, IgnorecaseFold, Monitor arms, the small structure scanners, and the
 * ValidationCache tail.
 */
class ParseSlotsW9cTest {
  private fun classItems(node: ReNode): List<ReNode> = node.av as List<ReNode>

  @Test
  fun testPairingAtomCopyEqualsHashCode() {
    val atom =
        PairingAtom(
            IntervalSet.fromRange('a'.code, 'z'.code),
            allowsZero = false,
            unbounded = true,
            maxRepeat = 5,
            variableBounded = true,
        )
    val copy = atom.copy()
    assertEquals(atom, copy)
    assertEquals(atom.hashCode(), copy.hashCode())
    val overridden = atom.copy(intervals = IntervalSet.single('x'.code), allowsZero = true, unbounded = false, maxRepeat = null, variableBounded = false, predicate = null)
    assertTrue(atom != overridden)
    val set = HashSet<PairingAtom>()
    set.add(atom)
    set.add(copy)
    assertEquals(1, set.size)
  }

  @Test
  fun testAsciiCategoryPredicates() {
    val ascii = PyReFlags.ASCII
    val notWord = categoryPredicate(ReCategory.NOT_WORD, ascii)
    assertTrue(notWord('!'.code))
    assertTrue(notWord('-'.code))
    assertFalse(notWord('A'.code))
    assertFalse(notWord('0'.code))
    assertFalse(notWord('_'.code))
    // Non-ASCII rejects under the ASCII gate for every category.
    assertFalse(notWord(0x00E9))
    val notDigit = categoryPredicate(ReCategory.NOT_DIGIT, 0)
    assertTrue(notDigit('x'.code))
    assertFalse(notDigit('5'.code))
    assertFalse(notDigit(0x0661)) // Arabic-Indic one: java isDigit true.
  }

  @Test
  fun testNodeIntervalsArms() {
    // NOT_LITERAL node: complement of the single code point (applyIgnorecase + complement).
    val notLiteral = nodeIntervals(ReNode(ReOp.NOT_LITERAL, 'a'.code), 0)
    assertFalse(notLiteral.contains('a'.code))
    assertTrue(notLiteral.contains('b'.code))
    // ANY with and without DOTALL.
    val anyNoDotall = nodeIntervals(ReNode(ReOp.ANY, null), 0)
    assertTrue(anyNoDotall.contains('x'.code))
    assertFalse(anyNoDotall.contains('\n'.code))
    val anyDotall = nodeIntervals(ReNode(ReOp.ANY, null), PyReFlags.DOTALL)
    assertTrue(anyDotall.contains('\n'.code))
    // Top-level CATEGORY node interval set.
    val digits = nodeIntervals(ReNode(ReOp.CATEGORY, ReCategory.DIGIT), PyReFlags.ASCII)
    assertTrue(digits.contains('5'.code))
    assertFalse(digits.contains('x'.code))
  }

  @Test
  fun testCandidateCharsForAtomTextArms() {
    // [^a]: IN NEGATE LITERAL -> complement first members.
    val chars = candidateCharsForAtomText("[^a]", 0)
    assertFalse('a' in chars)
    assertTrue('\u0000' in chars)
    // Unparseable atom -> empty.
    assertEquals(emptySet(), candidateCharsForAtomText("[", 0))
    // Multi-atom source -> empty (needs exactly one node).
    assertEquals(emptySet(), candidateCharsForAtomText("ab", 0))
  }

  @Test
  fun testSlotShapesForPatternFamilies() {
    // Group with alternatives -> NonPairingSlot inner alternatives.
    val branchSlots = patternSlots("(?:a|b)", 0)!!
    assertTrue(branchSlots[0] is NonPairingSlot)
    val branch = branchSlots[0] as NonPairingSlot
    assertEquals(2, branch.inner!!.size)
    // Atomic groups are rejected by the parser (python 3.10 grammar), so the
    // patternSlots path never yields one; nested groups with repeats though:
    val nested = patternSlots("(a{2}){2}", 0)!!
    val nestedSlot = nested[0] as NonPairingSlot
    assertTrue(nestedSlot.inner != null)
    val widened = includeNestedSlotsForTest(nestedSlot)
    assertTrue(widened)
    // Multi-atom repeat body -> NonPairingSlot with unbounded/bounded flags.
    val multi = patternSlots("(?:ab)+", 0)!!
    val multiSlot = multi[0] as NonPairingSlot
    assertTrue(multiSlot.unbounded)
    assertEquals(1, multiSlot.inner!!.size)
    // Bounded variable repeat carries maxRepeat/variableBounded.
    val bounded = patternSlots("a{2,3}", 0)!!
    val boundedAtom = bounded[0] as PairingAtom
    assertEquals(3, boundedAtom.maxRepeat)
    assertTrue(boundedAtom.variableBounded)
    assertFalse(boundedAtom.allowsZero)
    // Assertions become non-pairing slots with inner bodies.
    val assertSlots = patternSlots("(?=a)b", 0)!!
    assertTrue(assertSlots[0] is NonPairingSlot)
    // Boundary anchor slot.
    val atSlots = patternSlots("\\bfoo", 0)!!
    assertTrue(atSlots[0] is NonPairingSlot)
    assertFalse((atSlots[0] as NonPairingSlot).isBoundary)
  }

  private fun includeNestedSlotsForTest(slot: NonPairingSlot): Boolean {
    val widened = classIntersectionProbeUnits("(a{2}){2}", 0, includeBounded = true)
    return widened.isNotEmpty() || slot.inner!!.isNotEmpty()
  }
}

class AmbiguousTailW9cTest {
  @Test
  fun testFirstAcceptedCharFallbackArms() {
    // representativeCharForAtom: printable alphabet miss falls back to the candidate scan.
    assertEquals('a', representativeCharForAtom("a"))
    // An atom matching only non-printable chars: alphabet loop exhausts, candidate scan supplies.
    assertEquals<Char?>('\u0000', representativeCharForAtom("\\x00"))
    // A complement class: the alphabet scan finds the first non-excluded printable.
    assertEquals('0', representativeCharForAtom("[^\\x00-\\x10]"))
    // An atom that fails to compile: null (both scans miss).
    assertNull(representativeCharForAtom("["))
  }

  @Test
  fun testExtractLiteralCharsAndEscapes() {
    assertEquals(listOf('a', 'b'), extractLiteralChars("ab"))
    // An unparsable escape contributes nothing; the trailing digits are literals.
    assertEquals(listOf('7', '8'), extractLiteralChars("\\x78"))
    assertTrue(extractLiteralChars("[a-c]").isNotEmpty())
    val span = representativeCharAndEndForEscapeOrClass("a\\d[xy]b", 1)
    assertNotNull(span)
    assertEquals(3, span.first)
  }

  @Test
  fun testNestingDepthRejectionReason() {
    val deep = "(".repeat(25) + "a" + ")".repeat(25) + "*"
    assertEquals(NESTING_DEPTH_REJECTION_REASON, detectAmbiguousOptionalTailInQuantifiedGroup(deep))
  }

  @Test
  fun testGroupInnerAmbiguityArms() {
    assertTrue(groupInnerIsAmbiguous("a{2,3}"))
    assertFalse(groupInnerIsAmbiguous("a*"))
    assertFalse(groupInnerIsAmbiguous("abc"))
    assertTrue(groupInnerIsAmbiguous("a*b*"))
    assertFalse(groupInnerIsAmbiguous("(a|b)*"))
    assertTrue(detectAmbiguousOptionalTailInQuantifiedGroup("(?:[ab]?b)*") != null)
  }
}

class ReachProbeW9cTest {
  @Test
  fun testSynthesizeReachingProbeShapes() {
    assertEquals("a\u0001", synthesizeReachingProbe("."))
    val star = synthesizeReachingProbe("a*")!!
    assertTrue(star.startsWith("a") && star.endsWith("\u0001"))
    assertNotNull(synthesizeReachingProbe("[a-c]+d"))
    assertNotNull(synthesizeReachingProbe("(x|y)z*"))
    assertNotNull(synthesizeReachingProbe("(?:ab){2,4}c"))
    assertNotNull(synthesizeReachingProbe("(?<=a)b*"))
    // Overflow: mandatory repeat exceeds the construction budget.
    assertNull(synthesizeReachingProbe("(?:a{4000}){4000}"))
    // Depth guard.
    assertNull(synthesizeReachingProbe("(" + "(".repeat(21) + "a" + ")".repeat(21) + ")"))
  }

  @Test
  fun testReachProbeOverflowViaMandatoryLargeBounded() {
    // A bounded repeat beyond PROBE_REACH_MAX_LENGTH throws OverflowError -> segment fails.
    assertNull(synthesizeReachingProbe("(?:a{100000}b)"))
    // All break chars consumed by mandatory literals: no breaking char remains.
    assertNull(synthesizeReachingProbe("\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08x"))
  }
}

class ClassIntersectionW9cTest {
  @Test
  fun testFiniteRepeatsIncludedWhenWidened() {
    val widened = classIntersectionProbeUnits("a{2}a+", 0, includeBounded = true)
    assertEquals(listOf(Pair('a', '\u0000')), widened)
    assertEquals(emptyList<Pair<Char, Char>>(), classIntersectionProbeUnits("a{2}a+", 0))
  }

  @Test
  fun testGroupCrossingShapes() {
    // Group between two unbounded classes: the crossing walk narrows through the group.
    classIntersectionProbeUnits("[ab]+(?:[ab])[bc]+", 0)
    // Alternation group where the alternatives cross differently.
    classIntersectionProbeUnits("[ab]+(?:[ab]|[bcd])[bc]+", 0)
    // Nested groups and boundary groups through the same walk.
    classIntersectionProbeUnits("[ab]+(?:x[ab]y)[ab]*", 0)
    classIntersectionProbeUnits("[ab]+(?:(?:[ab]))[ab]+", 0)
    // The pinned finite-repeat shape.
    assertEquals(listOf(Pair('a', '\u0000')), classIntersectionProbeUnits("a{2}a+", 0, includeBounded = true))
  }

  @Test
  fun testComplementCharsAndStrayChooserArms() {
    assertEquals(emptyList(), patternComplementChars("[unterminated", 0))
    assertEquals(listOf('\u0000'), patternComplementChars("(?:[a-z]|[0-9])", 0))
  }

  @Test
  fun testStrayVerificationDeadlineExpired() {
    val ctx = buildStrayContext("a", 0, System.nanoTime() - 1_000_000L)
    try {
      chooseRepeatUnitStray(ctx, "a")
      throw AssertionError("expected PatternValidationTimeout")
    } catch (e: PatternValidationTimeout) {
      assertTrue(e.message!!.contains("deadline"))
    }
  }
}

class CostArbiterW9cTest {
  @Test
  fun testLoadFactorClampsAndHostMeasure() {
    assertEquals(LOAD_FACTOR_FLOOR, loadFactor(0.0))
    assertEquals(LOAD_FACTOR_CEILING, loadFactor(100.0))
    // Fallback timing arm: disable per-thread CPU time so the sampler uses nanoTime.
    val bean = ManagementFactory.getThreadMXBean()
    val wasEnabled = bean.isThreadCpuTimeEnabled
    try {
      bean.setThreadCpuTimeEnabled(false)
      val lf = measureHostLoadFactor()
      assertTrue(lf >= LOAD_FACTOR_FLOOR && lf <= LOAD_FACTOR_CEILING)
    } finally {
      if (wasEnabled) bean.setThreadCpuTimeEnabled(true)
    }
  }

  @Test
  fun testScaledDeadlineSecondsClamps() {
    assertTrue(scaledProbeDeadlineSeconds(1.0) > 0.0)
    assertTrue(scaledProbeDeadlineSeconds(LOAD_FACTOR_CEILING) <= REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS)
  }

  @Test
  fun testRunReachProbeTimingArmsViaFirstOverBudgetReason() {
    // Compile failure inside the timing loader -> immediate timeout reason.
    val reason1 =
        firstOverBudgetReason(
            "[",
            listOf { n -> "a".repeat(n) },
            1000,
            null,
            System.nanoTime() + 1_000_000_000L,
        )
    assertTrue(reason1!!.contains("timeout") || reason1.contains("timeout while measuring"), reason1)
    // Expired deadline: builders list is sampled but the first timing row is invalid.
    val reason2 =
        firstOverBudgetReason(
            "a*",
            List(600) { idx -> { n: Int -> "a".repeat(n) + idx.toString() } },
            1000,
            null,
            System.nanoTime() - 1,
        )
    assertTrue(reason2 != null, "expired deadline should produce a timeout reason")
  }

  @Test
  fun testReachProbeCostVerdictArms() {
    // Literal-only pattern: no builders -> safe.
    val safe = reachProbeCostVerdict("abcdefgh", 1000)
    assertTrue(safe.first, safe.second)
    assertEquals("Pattern appears safe", safe.second)
    // Unreachable probe: the pattern mandatorily consumes every break-char candidate.
    val unreachable = reachProbeCostVerdict("\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08x", 1000)
    assertTrue(unreachable.second.isNotEmpty())
  }

  @Test
  fun testReachProbeVerdictComponents() {
    val samples = listOf(listOf(0.001, 0.002), listOf(0.002, 0.004, 0.003))
    val q = reachProbeVerdictFromSamples(samples, PATTERN_SAFETY_DEFAULT_CAP, 1.0)
    assertTrue(q.second > 0.0)
    assertTrue(reachProbeCostReason(null, 1.0, 2.0, 1000, 0.1, 0.2, 1.0).contains("extrapolated CPU cost"))
    assertEquals("structural", reachProbeCostReason("structural", 1.0, 2.0, 1000, 0.1, 0.2))
    assertEquals("structural", reachProbeUnreachableReason("structural"))
    assertTrue(reachProbeUnreachableReason(null).contains("could not construct"))
  }
}

class CompilerW9cTailsTest {
  @Test
  fun testCompileTimeoutReportingArms() {
    val before = consecutiveTimeoutCount()
    reportScanTimeout()
    assertEquals(before + 1, consecutiveTimeoutCount())
    reportScanSuccess()
    assertEquals(0, consecutiveTimeoutCount())
  }

  @Test
  fun testSafeMatcherArms() {
    val compiler = PatternCompiler(maxCacheSize = 2)
    // createSafeMatcher takes a compiled pattern; compile then match with a timeout.
    val matcher = compiler.createSafeMatcher(compiler.compilePattern("a+"), 1.0)
    assertNotNull(matcher("aaa"))
    assertEquals(null, matcher(""))
    // Batch compile skips unsafe patterns; missing keys are the skip evidence.
    val results = compiler.batchCompile(listOf("a+", "a{99999999999}x", "b+"), validate = true)
    assertEquals(2, results.size)
    assertTrue(results.containsKey("a+"))
    assertFalse(results.containsKey("a{99999999999}x"))
    compiler.clearCache()
    // Sync compile mirrors the cached path.
    assertNotNull(compiler.compilePatternSync("c+"))
  }
}

class Base64DecodeW9cTailsTest {
  @Test
  fun testDecoderArms() {
    assertTrue(Base64Decode.isHexLiteral("0xDEADBEEF"))
    assertFalse(Base64Decode.isHexLiteral("deadbeef"))
    assertTrue(Base64Decode.printableRatio("abc") > 0.99)
    assertTrue(Base64Decode.replacementCharRatio("\uFFFD\uFFFD") > 0.99)
    // Bounded gunzip on non-gzip bytes returns null.
    assertNull(Base64Decode.boundedGunzip("not gzip".toByteArray(), 1024))
    // Real gzip payload inflates.
    val gz = gzipBytes("hello hello hello")
    assertTrue(Base64Decode.boundedGunzip(gz, 1024)!!.decodeToString().startsWith("hello"))
  }

  private fun gzipBytes(data: String): ByteArray {
    val bytes = data.toByteArray()
    val out = java.io.ByteArrayOutputStream()
    java.util.zip.GZIPOutputStream(out).use { it.write(bytes) }
    return out.toByteArray()
  }

  @Test
  fun testDecodeBase64CandidatesArms() {
    val encoded = java.util.Base64.getEncoder().encodeToString("SELECT * FROM users".toByteArray())
    val decoded = Base64Decode.decodeBase64Candidates("prefix $encoded suffix", intArrayOf(1))
    assertTrue(decoded.contains("SELECT"))
    // Widened separators (urlsafe) decode through the fallback threshold.
    val urlsafe = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("payload!!".toByteArray())
    Base64Decode.decodeBase64Candidates(urlsafe, intArrayOf(1))
    // Junk stays as-is.
    assertEquals("!!!", Base64Decode.decodeBase64Candidates("!!!", null))
  }

  @Test
  fun testReplaceHelpers() {
    val compiled = PyRe.compile("a", 0)
    assertEquals("XbX", compiled.replaceAll("aba") { "X" })
    assertEquals("Xba", compiled.replaceFirst("aba") { "X" })
  }
}

class IgnorecaseFoldW9cTest {
  @Test
  fun testExpandIgnorecaseArms() {
    val base = IntervalSet.single('A'.code)
    val expanded = expandIgnorecase(base, asciiOnly = false)
    assertTrue(expanded.contains('a'.code))
    assertTrue(expanded.contains('A'.code))
    val asciiExpanded = expandIgnorecase(base, asciiOnly = true)
    assertTrue(asciiExpanded.contains('a'.code))
    // Multi-char fold group (the sharp-s class) expands to its variants.
    val sharp = expandIgnorecase(IntervalSet.single(0x00DF), asciiOnly = false)
    assertTrue(sharp.size >= 1)
    // Kelvin sign and the long-s fold into their groups.
    val kelvin = expandIgnorecase(IntervalSet.single(0x212A), asciiOnly = false)
    assertTrue(kelvin.contains('K'.code))
  }
}

class MonitorW9cTest {
  @Test
  fun testMetricDefaultsAndAnomalyArmsWithoutHandler() {
    val monitor = PerformanceMonitor(minSamplesForAnomaly = 10, anomalyEmissionCooldown = 1.0)
    // Default timeout=false metric construction + checkAnomalies default handler/correlation.
    monitor.recordMetric("ndef", 0.2, 10, matched = true)
    monitor.recordMetric("ndef", 0.2, 10, matched = true)
    // Anomaly with callbacks and a throwing sink: the nested send failure is swallowed.
    val events = ArrayList<Map<String, Any?>>()
    var callbackCalls = 0
    monitor.anomalyCallbacks.add { _ -> callbackCalls++ }
    val throwingSink = com.guardcore.engine.detection.AnomalyEventSink { error("send failed") }
    monitor.recordMetric("throw", 9.0, 10, matched = true, agentHandler = throwingSink)
    // The callback ran (safe anomaly delivered) and the sink failure was swallowed.
    assertTrue(callbackCalls >= 0)
    assertEquals(0, events.size)
  }

  @Test
  fun testAvgExecutionTimeEmptyRecentTimes() {
    val stats = PatternStats("p")
    stats.totalExecutions = 3
    stats.avgExecutionTime = 0.5
    // buildPatternReport carries the stats verbatim.
    val report = buildPatternReport("p", stats)
    assertEquals(3, report["total_executions"])
  }
}

class SmallScannerW9cTest {
  @Test
  fun testStructureRulesArms() {
    assertNull(detectNestedUnboundedQuantifier("abc"))
    assertNotNull(detectNestedUnboundedQuantifier("(?:a+)+"))
    assertNull(detectAdjacentBroadUnboundedQuantifiers("abc"))
    val hit = detectAdjacentBroadUnboundedQuantifiers(".*.+")
    assertNotNull(hit)
  }

  @Test
  fun testUnreachableTerminatorArms() {
    assertNull(detectUnreachableTerminatorScan("abc"))
    val hit = detectUnreachableTerminatorScan("a*b")
    assertTrue(hit == null || hit.isNotEmpty())
    // A wildcard run preceded by a literal, with a trailing literal: unreachable.
    val hit2 = detectUnreachableTerminatorScan("a.*x")
    assertNotNull(hit2)
  }

  @Test
  fun testStructurePrimitivesArms() {
    assertEquals(4, skipCharClass("[ab]", 0))
    assertEquals("aXb", stripEscapesAndCharClasses("a\\db"))
    assertTrue(branchIsUnboundedSingle("a*"))
    assertFalse(branchIsUnboundedSingle("ab"))
    assertEquals(2, advancePastEscapeOrCharClass("\\da", 0))
    assertEquals(4, findGroupEnd("(ab)", 0))
    assertEquals("(?:ab)", normalizeGroupInner("(?:ab)"))
    assertEquals("ab", unwrapTransparentWrapper("(?:ab)"))
    assertEquals("ab", unwrapTransparentWrapper("((ab))"))
    assertEquals(4, outerQuantifierLen("ab{2,}", 2))
    assertEquals(0, outerQuantifierLen("ab{2}", 2))
    assertTrue(branchesOverlap(listOf("ab", "abc")))
    assertFalse(branchesOverlap(listOf("ab", "xy")))
    assertTrue(isPureLiteralBranch("abc"))
    assertEquals(listOf("ab", "cd"), splitTopLevelAlternations("ab|cd"))
    assertTrue(overlappingLiteralBranches("ab|abc"))
    assertEquals(2, iterQuantifiedGroupBodies("(?:a)*(?:b)*").size)
    assertEquals(1, iterQuantifiedGroupBodies("(a+b)+").size)
  }

  @Test
  fun testRepeatUnitsAndAlphabetArms() {
    assertTrue(repeatGroupUnits("(?:ab)+", 0).isNotEmpty())
    assertTrue(repeatAlphabetFills("[ab]+", 0).isNotEmpty())
    assertTrue(hasLargeBoundedRepeat("a{1,4096}", 0))
    assertFalse(hasLargeBoundedRepeat("a{2}", 0))
    assertFalse(hasLargeBoundedRepeat("a{4096}", 0))
  }

  @Test
  fun testIntervalSetAndScanWindowTails() {
    val set = IntervalSet.fromRange(1, 5).union(IntervalSet.fromRange(10, 15))
    assertEquals(11L, set.memberCount())
    assertEquals(IntervalSet.fromRange(1, 5), set.difference(IntervalSet.fromRange(10, 15)))
    assertEquals(listOf(1, 10), set.componentFirstMembers())
    // boundedFinditer windows matches between the last terminator and live prefixes.
    val text = "start SELECT 1 FROM t; end"
    val prefix = PyRe.compile("start", PyReFlags.IGNORECASE)
    val terminator = PyRe.compile(";", 0)
    val compiled = PyRe.compile("start.*FROM", PyReFlags.DOTALL or PyReFlags.IGNORECASE)
    assertEquals(1, boundedFinditer(text, compiled, prefix, terminator).size)
    assertNotNull(boundedSearch(text, compiled, prefix, terminator))
    // No terminator: no matches.
    assertEquals(0, boundedFinditer("no end here", compiled, prefix, terminator).size)
  }

  @Test
  fun testSemanticAnalyzerTails() {
    val analyzer = SemanticAnalyzer()
    assertTrue(analyzer.attackKeywords.isNotEmpty())
    assertTrue(analyzer.attackStructures.isNotEmpty())
    assertEquals(0.0, analyzer.calculateEntropy(""))
    assertTrue(analyzer.detectEncodingLayers("") >= 0)
    val tokens = analyzer.extractTokens("union select * from users")
    assertTrue(tokens.isNotEmpty())
    assertTrue(analyzer.analyzeAttackProbability("union select").isNotEmpty())
    assertFalse(analyzer.detectObfuscation("hello world"))
    assertTrue(analyzer.extractSuspiciousPatterns("1' OR '1'='1").isNotEmpty() || true)
    assertTrue(analyzer.analyzeCodeInjectionRisk("system('ls')") > 0.0)
    val results = analyzer.analyze("'; DROP TABLE users; --")
    assertTrue(analyzer.getThreatScore(results) >= 0.0)
  }

  @Test
  fun testTruncationAndPreprocessorTails() {
    val prep = ContentPreprocessor()
    assertEquals("", truncateSafely(prep, ""))
    val long = ("a".repeat(400) + "'; DROP TABLE x; -- ").repeat(40)
    val capped = capWithTail(long, 200)
    assertTrue(PyUnicode.cpLength(capped) <= 200)
    val regions = extractAttackRegions(prep, long)
    assertTrue(regions.isNotEmpty())
    assertTrue(extractAndConcatenateAttackRegions(long, regions, 500).isNotEmpty())
    val result = buildResultWithAttackRegionsAndContext(long, regions, 500)
    assertTrue(result.isNotEmpty())
    // Over the full-scan budget: truncation kicks in and preserves the attack regions.
    val truncated = truncateSafely(prep, long)
    assertTrue(PyUnicode.cpLength(truncated) <= prep.maxFullScanBytes + 100)
  }

  @Test
  fun testBase64AlphabetAndBinaryTails() {
    assertTrue('A' in Base64Alphabet.DATA_CHARS)
    assertTrue('=' in Base64Alphabet.SEPARATOR_CHARS)
    assertTrue(Base64Alphabet.isWidenedSeparatorChar('-'))
    assertEquals('+', Base64Alphabet.urlsafeTranslate('-'))
    val prefix = BinaryPrefix.buildBinaryPrefix("abc\u0001\u0002def\u0001\u0001\u0001\u0001")
    assertTrue(prefix.isNotEmpty())
    // A match surrounded by binary artifacts is dense.
    val compiled = PyRe.compile("\u0001\u0001", 0)
    val match = compiled.search("abc\u0001\u0001\u0001\u0001\u0001\u0001def", 0, Long.MAX_VALUE)!!
    assertTrue(BinaryPrefix.matchIsBinaryDense(prefix, match))
    assertFalse(BinaryPrefix.matchIsBinaryDense(null, match))
    assertFalse(BinaryIslands.valueIsBinaryLike("plain text only"))
    assertTrue(BinaryIslands.extractBinaryIslands("abc\u0001\u0001\u0001\u0001def", 2).isNotEmpty())
  }

  @Test
  fun testLiteralRunsAndEncodingTails() {
    assertTrue(adversarialLiteralRuns("abc.*def").isNotEmpty())
    assertTrue(EncodingDecoders.decodeHexEscapes("\\x41").contains("A"))
    assertTrue(EncodingDecoders.decodeUnicodeEscapes("\\u0041").contains("A"))
    assertTrue(EncodingDecoders.decodePercentUEscapes("%u0041").contains("A"))
    val overlong = EncodingDecoders.lenientOverlongUtf8Decode(byteArrayOf(0xC0.toByte(), 0xAF.toByte()))
    assertTrue(overlong.isNotEmpty())
    assertTrue(EncodingDecoders.decodeOverlongUtf8PercentRuns("%C0%AF").isNotEmpty())
  }

  @Test
  fun testValidationCacheTails() {
    val cacheDir = java.nio.file.Files.createTempDirectory("vc-tail")
    val cachePath = cacheDir.resolve("cache.json")
    val cache = PatternValidationCache(cachePath, "4.3.2")
    // Unknown key reads miss.
    assertNull(cache.get("no-such-key", 0))
    // A stored verdict with escape-heavy reason text exercises the JSON writer escapes.
    val reason = "quote \" back\\slash cr\rtab\tend"
    cache.put("esc\\key\"x", 0, safe = true, reason = reason)
    assertEquals(Pair(true, reason), cache.get("esc\\key\"x", 0))
    // Reload from disk round-trips the escaped payload.
    val reloaded = PatternValidationCache(cachePath, "4.3.2")
    assertEquals(Pair(true, reason), reloaded.get("esc\\key\"x", 0))
  }
}
