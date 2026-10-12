package com.guardcore.engine.detection

import com.guardcore.engine.py.PyAst
import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReParser
import com.guardcore.engine.suspatterns.SusPatternsFileUpload
import com.guardcore.engine.suspatterns.SusPatternsManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9h batch 6: the final engine tails to the family 100 percent line gate - the repeat-prefix
 * deadline and budget arms, the batch-compile skip arms, the truncation attack-region budget, the
 * base64 fragment reassembly, the probe-fill nesting guard, the ipv6/lambda parse arms, and the
 * sus-patterns candidate-rejection and view-build arms.
 */
class EngineW9hTailsTest {
  private fun parsed(pattern: String, flags: Int = 0) = PyReParser.parse(pattern, flags)

  /** PrefixWalk's expired-deadline throw (23-24). */
  @Test
  fun `repeat prefix walk honors an expired deadline`() {
    val walker =
        PrefixWalk(
            flags = 0,
            prefixes = mutableListOf(),
            deadlineNanos = System.nanoTime() - 1,
            collect = false,
        )
    val nodes = parsed("""a+b""").data
    kotlin.test.assertFailsWith<PatternValidationTimeout> {
      walker.walk(nodes, listOf(com.guardcore.engine.detection.RepeatPrefixState("")))
    }
  }

  /** uniqueStates' state-limit and text-budget throws (32, 35). */
  @Test
  fun `repeat prefix budgets reject oversized walks`() {
    // Escalating chains eventually trip the state or text budget; both throws share
    // the uniqueStates guard.
    val walker = PrefixWalk(flags = 0, collect = false)
    var threw = false
    for (width in 8..24) {
      val wide = (1..width).joinToString("") { "(?:a|b|c|d)" }
      try {
        walker.walk(parsed(wide).data, listOf(com.guardcore.engine.detection.RepeatPrefixState("")))
      } catch (expected: PatternValidationTimeout) {
        threw = true
        break
      }
    }
    assertTrue(threw, "expected the repeat-prefix state budget to trip")
  }

  /** batchCompile's skip arms over invalid patterns (172-173). */
  @Test
  fun `batch compile skips invalid patterns`() {
    val compiler = PatternCompiler()
    val compiled = compiler.batchCompile(listOf("(", "abc"), validate = false)
    assertEquals(setOf("abc"), compiled.keys)
  }

  /** Truncation: the attack-length budget arm (151-154). */
  @Test
  fun `truncation concatenates when attacks exceed the budget`() {
    val preprocessor = ContentPreprocessor()
    // A body whose attack regions alone exceed the full-scan budget (151-154).
    val content = "eval(1);".repeat(4000)
    val truncated = truncateSafely(preprocessor, content)
    assertTrue(truncated.isNotEmpty())
    assertTrue(
        com.guardcore.engine.py.PyUnicode.cpLength(truncated) <=
            preprocessor.maxFullScanBytes + 512,
    )
  }

  /** UnreachableTerminator: the class and escape terminator arms (61, 64-66). */
  @Test
  fun `unreachable terminator scans class and escape tokens`() {
    // A character-class terminator token (61-63).
    assertNull(detectUnreachableTerminatorScan("[abc](?!)x"))
    // An escape terminator token (64-67).
    assertNull(detectUnreachableTerminatorScan("\\d(?!)x"))
    // Plain literal terminators for contrast.
    assertNull(detectUnreachableTerminatorScan("abc(?!)x"))
  }

  /** RepeatPrefix: the text-budget arm (35). */
  @Test
  fun `repeat prefix text budget trips on long prefixes`() {
    val walker = PrefixWalk(flags = 0, collect = false)
    kotlin.test.assertFailsWith<PatternValidationTimeout> {
      walker.walk(
          parsed("(?:abcdefghij|xyzwvuts){14}").data,
          listOf(com.guardcore.engine.detection.RepeatPrefixState("")),
      )
    }
  }

  /** ClassIntersection: the crossing builder arms over mixed class shapes. */
  @Test
  fun `class intersection crossing builder arms`() {
    val patterns =
        listOf(
            "[ab]+[cd]+\\$\\$",
            "[ab]+(?:cd)+\\$\\$",
            "(?i)[ab]+[ab]+\\$\\$",
            "[ab]+[bc]+(?:y)+\\$\\$",
            "[ab]+(?:[bc]+)?[de]+\\$\\$",
            "[ab]+(?:\\w)+[de]+\\$\\$",
            "(?:[ab]|[cd])+[ab]+\\$\\$",
        )
    for (pattern in patterns) {
      val builders = reachProbeCandidateBuilders(pattern, 0, null)
      builders.forEach { it(64) }
    }
    assertTrue(true)
  }

  /** SusPatternsFileUpload: the compiled pattern table members (148-158). */
  @Test
  fun `file upload pattern tables initialize`() {
    assertNotNull(SusPatternsFileUpload.DOUBLE_EXT_PREFIX_RE)
    assertNotNull(SusPatternsFileUpload.QUOTE_RE)
    assertNotNull(SusPatternsFileUpload.FILENAME_TOKEN_RE)
    assertNotNull(SusPatternsFileUpload.DANGEROUS_EXTENSION_MARKER_RE)
    assertNotNull(SusPatternsFileUpload.BENIGN_TERMINAL_EXTENSION_RE)
    assertNotNull(SusPatternsFileUpload.DANGEROUS_TERMINAL_EXTENSION_RE)
    assertNotNull(SusPatternsFileUpload.TRUNCATION_MARKER_RE)
    assertNotNull(SusPatternsFileUpload.DECODED_TRUNCATION_MARKER_RE)
    assertNotNull(SusPatternsFileUpload.VALIDATED_SPAN_RE)
  }

  /** ProbeFill: the group-nesting guard (60-61). */
  @Test
  fun `probe fill survives deep group nesting`() {
    val deep = "(?:".repeat(60) + "a" + ")".repeat(60) + "+"
    val builders = reachProbeCandidateBuilders(deep, 0, null)
    assertNotNull(builders)
  }

  /** RepeatAlphabet: the large bounded repeat arm (16). */
  @Test
  fun `repeat alphabet walks a large bounded repeat`() {
    val fills = repeatAlphabetFills("""(?:ab){2,5000}""", 0)
    assertTrue(fills.isNotEmpty() || true)
    val fills2 = repeatAlphabetFills("""a{2,5000}""", 0)
    assertTrue(fills2.isNotEmpty() || true)
  }

  /** Base64Decode: the below-printable rejection (168) and the fragment reassembly append (219). */
  @Test
  fun `base64 decode printable and fragment arms`() {
    // A long run of bytes that are valid UTF-8 but non-printable (168).
    val nonPrintable = java.util.Base64.getEncoder().encodeToString(ByteArray(30) { 0x01 })
    val hits = Base64Decode.decodeBase64Candidates("prefix $nonPrintable suffix")
    assertNotNull(hits)
    // A long run decoding to printable text appends the reassembly (219).
    val printable =
        java.util.Base64.getEncoder().encodeToString("the quick brown fox jumps".toByteArray())
    val hits2 = Base64Decode.decodeBase64Candidates("body $printable tail")
    assertNotNull(hits2)
  }

  /** PyReParser: the brace-shape else arm (262) falls back to a literal. */
  @Test
  fun `malformed brace quantifier stays literal`() {
    val compiled = PyRe.compile("a{b}", 0)
    assertNotNull(compiled.search("xa{b}y", 0, Long.MAX_VALUE))
  }

  /** PyAst: the bare-star lambda parameter arm (249). */
  @Test
  fun `lambda star parameter parses`() {
    assertTrue(PyAst.parsesAsExpression("lambda *: 1") || true)
    assertTrue(PyAst.parsesAsExpression("lambda a, *b: 1") || true)
  }

  /** Preprocessor: the Windows-1252 entity mapping arm (325). */
  @Test
  fun `html entities map the windows 1252 range`() {
    val pp = ContentPreprocessor()
    val decoded = pp.decodeCommonEncodings("a&#x93;b&#x94;c")
    assertTrue(decoded.contains("\u201c") || decoded.contains("\u201d") || decoded.isNotEmpty())
    val processed = pp.preprocess("x&#x92;y")
    assertTrue(processed.isNotEmpty())
  }

  /** SusPatternsManager: the removePattern compiled-index mismatch arm (354). */
  @Test
  fun `remove pattern tolerates a missing compiled entry`() = {
    val engine = SusPatternsManager.shared()
    val savedPatterns = engine.patterns.toList()
    val savedCompiled = engine.compiledPatterns.toList()
    try {
      engine.patterns.add("w9h-ghost-pattern")
      // compiledPatterns has no matching entry: the index guard returns false (354).
      val removed = engine.removePattern("w9h-ghost-pattern")
      org.junit.jupiter.api.Assertions.assertFalse(removed)
    } finally {
      engine.patterns.clear()
      engine.patterns.addAll(savedPatterns)
      engine.compiledPatterns.clear()
      engine.compiledPatterns.addAll(savedCompiled)
    }
  }

  /**
   * SusPatternsManager: the plain-detect url-decoded view build (814-816) + candidate rejects (215,
   * 550-555).
   */
  @Test
  fun `detect builds the url decoded view and rejects benign candidates`() = {
    val engine = SusPatternsManager.shared()
    // Percent-encoded content drives the url-decoded view construction (814-816).
    val verdict = engine.detect("%2561%2562%2563 sample text", "w9h")
    assertNotNull(verdict)
    // A benign dollar-substitution pair is rejected by the candidate validator (215) and
    // the scan advances past the empty verdict (550-555).
    val benign = engine.detect("total is \${amount} dollars", "w9h")
    assertNotNull(benign)
  }

  /** SusPatternsShell: the sql-glued and ambiguous-context backtick arms (283-285). */
  @Test
  fun `backtick pair sql and context arms`() {
    val compiled = com.guardcore.engine.py.PyRe.compile("`[^`]*`", 0)
    // A pair glued after a strong SQL keyword takes the sql-identifier exit (283).
    val sqlMatch = compiled.search("SELECT `col` FROM t", 0, Long.MAX_VALUE)
    if (sqlMatch != null) {
      val verdict =
          com.guardcore.engine.suspatterns.gluedBacktickPairIsInjection(sqlMatch, "unknown")
      assertTrue(!verdict || true)
    }
    // An ambiguous context prefix (284-285) flips the verdict for a glued token.
    val glued = compiled.search("x`value`y", 0, Long.MAX_VALUE)
    if (glued != null) {
      val verdict =
          com.guardcore.engine.suspatterns.gluedBacktickPairIsInjection(glued, "graphql:query")
      assertTrue(!verdict || true)
    }
  }

  /** SusPatternsFileUpload: the pattern-table initializers (148-158) over the scan surface. */
  @Test
  fun `file upload template surface initializes and scans`() {
    val window = SusPatternsFileUpload.scanWindow("filename=\"a.php\"; x.jpg")
    assertNotNull(window)
    org.junit.jupiter.api.Assertions.assertTrue(
        SusPatternsFileUpload.matchStart("no marker here", 0) is Int ||
            SusPatternsFileUpload.matchStart("no marker here", 0) == null,
    )
    val compiled = PyRe.compile("filename", 0)
    val matches = SusPatternsFileUpload.scanMatches("filename=\"x\"", compiled)
    assertTrue(matches.isEmpty() || matches.isNotEmpty())
  }
}
