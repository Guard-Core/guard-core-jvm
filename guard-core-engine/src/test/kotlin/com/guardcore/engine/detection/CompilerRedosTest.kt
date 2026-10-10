package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Behavioral core of tests/test_sus_patterns/test_compiler.py, test_redos_cost_arbiter.py (verdict
 * classes), and the hard-deadline contract.
 */
class CompilerRedosTest {
  private fun compiler(): PatternCompiler =
      PatternCompiler(defaultTimeout = 5.0, maxCacheSize = 100)

  // ---- compiler core (test_compiler.py) ----

  @Test
  fun initializationDefaults() {
    val compiler = PatternCompiler()
    assertEquals(5.0, compiler.defaultTimeout)
    assertEquals(1000, compiler.maxCacheSize)
    val sized = PatternCompiler(defaultTimeout = 10.0, maxCacheSize = 500)
    assertEquals(10.0, sized.defaultTimeout)
    assertEquals(500, sized.maxCacheSize)
    val capped = PatternCompiler(maxCacheSize = 10000)
    assertEquals(5000, capped.maxCacheSize)
  }

  @Test
  fun compilePatternSyncCompiles() {
    val compiled = compiler().compilePatternSync("test\\d+")
    assertTrue(compiled.search("test123", 0, Long.MAX_VALUE) != null)
    assertTrue(compiled.search("test", 0, Long.MAX_VALUE) == null)
    val caseSensitive = compiler().compilePatternSync("TEST\\d+", 0)
    assertTrue(caseSensitive.search("TEST123", 0, Long.MAX_VALUE) != null)
    assertTrue(caseSensitive.search("test123", 0, Long.MAX_VALUE) == null)
  }

  @Test
  fun compilePatternCaches() {
    val compiler = compiler()
    val first = compiler.compilePattern("cached_pattern\\d+")
    val second = compiler.compilePattern("cached_pattern\\d+")
    assertEquals(first, second)
  }

  @Test
  fun validatePatternSafetyDangerousPatterns() {
    val compiler = compiler()
    val dangerous = listOf("(.*)+", "(.+)+", "([a-z]*)+", "([a-z]+)+", ".*.*", ".+.+")
    for (pattern in dangerous) {
      val (isSafe, reason) = compiler.validatePatternSafety(pattern)
      assertFalse(isSafe, "expected rejection: $pattern")
      assertTrue(reason.lowercase().contains("dangerous"), "reason: $reason")
    }
  }

  @Test
  fun validatePatternSafetyAcceptsSafePatterns() {
    val compiler = compiler()
    // The email-shaped patterns are REJECTED by the reference arbiter too (quadratic
    // probe scans), so the safe set here mirrors the reference-verified safe list.
    val safe =
        listOf(
            "https?://[^\\s]+",
            "\\d{3}-\\d{3}-\\d{4}",
            "[a-zA-Z0-9]+",
            "^[^>]*x",
        )
    for (pattern in safe) {
      val (isSafe, reason) = compiler.validatePatternSafety(pattern)
      assertTrue(isSafe, "expected safe: $pattern ($reason)")
    }
    // The reference rejects the quadratic email scan; the JVM arbiter agrees in class.
    val (emailSafe, emailReason) = compiler.validatePatternSafety("[a-z]+@[a-z]+\\.[a-z]+")
    assertFalse(emailSafe)
    assertTrue(emailReason.contains("extrapolated CPU cost"))
  }

  @Test
  fun validatePatternSafetyInvalidSyntax() {
    val compiler = compiler()
    val (isSafe, reason) = compiler.validatePatternSafety("[unclosed")
    assertFalse(isSafe)
    assertTrue(reason.contains("Pattern validation failed") || reason.contains("unterminated"))
  }

  @Test
  fun validatePatternSafetyTestStringsSlowPattern() {
    val compiler = compiler()
    // A genuinely slow search on the probe string exceeds the per-string threshold and is
    // rejected with the timed-out reason class (the reference test mocks the probe; this
    // port exercises the real per-string measurement).
    val (isSafe, reason) =
        compiler.validatePatternSafety(
            "x*x*x*x*y",
            testStrings = listOf("x".repeat(60)),
        )
    assertFalse(isSafe, "slow probe must be rejected (reason=$reason)")
    assertTrue(reason.contains("timed out on test string"), "reason=$reason")
  }

  @Test
  fun createSafeMatcherReturnsMatchesAndNullOnDeadline() {
    val compiler = PatternCompiler(defaultTimeout = 0.05)
    val pattern = compiler.compilePatternSync("(a+)+b")
    val matcher = compiler.createSafeMatcher(pattern)
    // Fast match on benign input
    assertTrue(matcher("aaab") != null)
    // Catastrophic input aborts to null under the deadline
    assertNull(matcher("a".repeat(64)))
  }

  @Test
  fun createSafeFinditerMatcherReturnsEmptyOnDeadline() {
    val compiler = PatternCompiler(defaultTimeout = 0.05)
    val pattern = compiler.compilePatternSync("(a+)+b")
    val finder = compiler.createSafeFinditerMatcher(pattern)
    assertTrue(finder("aaab").isNotEmpty())
    assertTrue(finder("a".repeat(64)).isEmpty())
  }

  @Test
  fun batchCompileSkipsUnsafe() {
    val compiler = compiler()
    val compiled = compiler.batchCompile(listOf("safe_\\d+", "(.*)+", "[unclosed"))
    assertTrue(compiled.containsKey("safe_\\d+"))
    assertFalse(compiled.containsKey("(.*)+"))
    assertFalse(compiled.containsKey("[unclosed"))
  }

  // ---- cost arbiter verdict classes (test_redos_cost_arbiter.py core) ----

  @Test
  fun reachProbeCostVerdictRejectsQuadraticPatterns() {
    val (safe, reason) = reachProbeCostVerdict("(a+)+\$", 262144)
    assertFalse(safe, "quadratic pattern must be rejected")
    // The structural layer rejects the nested form fail-closed before timing (the same
    // reason class the reference produces).
    assertTrue(
        reason.contains("nested unbounded quantifier") ||
            reason.contains("extrapolated CPU cost") ||
            reason.contains("dangerous"),
        "reason class: $reason",
    )
  }

  @Test
  fun reachProbeCostVerdictAgreesWithReferenceOnEmailScans() {
    // Reference verdict for the email scans is REJECT (quadratic probe cost); the JVM
    // arbiter agrees in class.
    val (emailSafe, emailReason) = reachProbeCostVerdict("[a-z]+@\\w+\\.com", 262144)
    assertFalse(emailSafe)
    assertTrue(emailReason.contains("extrapolated CPU cost"))
    val (safe, reason) = reachProbeCostVerdict("[a-zA-Z0-9]+", 262144)
    assertTrue(safe, "linear scan must be accepted (reason=$reason)")
    assertEquals("Pattern appears safe", reason)
  }

  @Test
  fun reachProbeCostVerdictRejectsUnreachableProbes() {
    // A pattern whose quantified regions cannot be reached by any synthesized probe is
    // rejected rather than certified on an unreachable probe.
    val (safe, reason) = reachProbeCostVerdict("\\1a", 262144)
    assertFalse(safe)
    assertTrue(
        reason.contains("unreachable") || reason.contains("invalid group"),
        "reason class: $reason",
    )
  }

  // ---- deadline idiom ----

  @Test
  fun deadlineCharSequenceAbortsLongMatches() {
    // java.util.regex folds (a+)+ into a linear GroupCurly, so the abort probe uses a
    // genuinely quadratic-in-java alternation.
    val pattern = PyRe.compile("x*x*x*x*x*x*x*x*y", 0)
    val deadline = System.nanoTime() + 200_000_000L
    try {
      val text = "x".repeat(100)
      pattern.search(text, 0, deadline)
      throw AssertionError("expected deadline abort")
    } catch (e: PyRe.DeadlineExceededException) {
      assertTrue(e.message!!.contains("deadline"))
    }
  }

  @Test
  fun deadlineSentinelNeverAborts() {
    val pattern = PyRe.compile("[a-z]+", 0)
    // Long.MAX_VALUE is the no-deadline sentinel
    assertTrue(pattern.search("abc", 0, Long.MAX_VALUE) != null)
  }

  @Test
  fun validateFlagsDefaultIsIgnorecaseMultiline() {
    assertEquals(3, PyReFlags.DEFAULT)
    assertEquals(PyReFlags.IGNORECASE or PyReFlags.MULTILINE, PyReFlags.DEFAULT)
  }
}
