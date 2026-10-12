package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_compiler_cache.py and the compiler arms of
 * tests/test_sus_patterns/test_builtin_redos_protection.py: the cached compiler, the safety probe,
 * safe matchers, and batch compilation.
 */
class CompilerSafetyTest {
  @Test
  fun distinctPatternsGetDistinctCacheEntries() {
    val compiler = PatternCompiler()
    val p1 = compiler.compilePattern("alpha", PyReFlags.IGNORECASE)
    val p2 = compiler.compilePattern("beta", PyReFlags.IGNORECASE)
    assertEquals("alpha", p1.source)
    assertEquals("beta", p2.source)
  }

  @Test
  fun samePatternSameFlagsHitsCache() {
    val compiler = PatternCompiler()
    val p1 = compiler.compilePattern("repeat", PyReFlags.IGNORECASE)
    val p2 = compiler.compilePattern("repeat", PyReFlags.IGNORECASE)
    assertTrue(p1 === p2)
  }

  @Test
  fun samePatternDifferentFlagsCreatesSeparateEntries() {
    val compiler = PatternCompiler()
    val ci = compiler.compilePattern("Word", PyReFlags.IGNORECASE)
    val cs = compiler.compilePattern("Word", 0)
    assertFalse(ci === cs)
  }

  @Test
  fun cacheEvictionWhenFull() {
    val compiler = PatternCompiler(maxCacheSize = 2)
    compiler.compilePattern("first", 0)
    compiler.compilePattern("second", 0)
    compiler.compilePattern("third", 0)
    // The oldest entry was evicted; recompiling first works and refreshes.
    compiler.compilePattern("first", 0)
    compiler.clearCache()
  }

  @Test
  fun compilePatternSyncAndDefaultTimeout() {
    val compiler = PatternCompiler(defaultTimeout = 1.5)
    val compiled = compiler.compilePatternSync("hello", PyReFlags.IGNORECASE)
    assertEquals("hello", compiled.source)
    assertEquals(1.5, compiler.defaultTimeout)
    // maxCacheSize clamps at 5000.
    assertEquals(5000, PatternCompiler(maxCacheSize = 99999).maxCacheSize)
  }

  @Test
  fun validatePatternSafetySafePattern() {
    val compiler = PatternCompiler()
    val (safe, msg) = compiler.validatePatternSafety("hello world")
    assertTrue(safe)
    assertEquals("Pattern appears safe", msg)
  }

  @Test
  fun validatePatternSafetyDangerousPattern() {
    val compiler = PatternCompiler()
    val (safe, msg) = compiler.validatePatternSafety("(.*)+")
    assertFalse(safe)
    assertTrue("dangerous construct" in msg)
  }

  @Test
  fun validatePatternSafetyCustomTestStrings() {
    val compiler = PatternCompiler()
    val (safe, msg) = compiler.validatePatternSafety("test", testStrings = listOf("abc", "xyz"))
    assertTrue(safe)
    assertEquals("Pattern appears safe", msg)
  }

  @Test
  fun validatePatternSafetyInvalidRegex() {
    val compiler = PatternCompiler()
    val (safe, msg) = compiler.validatePatternSafety("[invalid")
    assertFalse(safe)
    assertTrue("Pattern validation failed" in msg)
  }

  @Test
  fun validatePatternSafetyReportsTimeoutForAGenuinelySlowMatch() {
    val compiler = PatternCompiler()
    val subject = "START#" + "a".repeat(16000)
    val (safe, msg) =
        compiler.validatePatternSafety(
            """START#(?:[a-z]+[a-z]*)Z$""",
            testStrings = listOf(subject),
        )
    assertFalse(safe)
    assertTrue("timed out" in msg || "timeout" in msg, msg)
  }

  @Test
  fun compilerUsesTheCacheAndSkipsTheCostVerdict() {
    val path = Files.createTempDirectory("w9b-compiler").resolve("cache.json")
    val warm = PatternValidationCache(path, "4.3.2")
    val defaultFlags = PyReFlags.IGNORECASE or PyReFlags.MULTILINE
    warm.put("hello world", defaultFlags, true, "Pattern appears safe")
    val compiler = PatternCompiler(validationCache = warm)
    val (safe, reason) = compiler.validatePatternSafety("hello world", flags = defaultFlags)
    assertTrue(safe)
    assertEquals("Pattern appears safe", reason)
  }

  @Test
  fun compilerPopulatesTheCacheOnAMiss() {
    val path = Files.createTempDirectory("w9b-compiler").resolve("cache.json")
    val cache = PatternValidationCache(path, "4.3.2")
    val compiler = PatternCompiler(validationCache = cache)
    val flags = PyReFlags.IGNORECASE or PyReFlags.MULTILINE
    val (safe, _) =
        compiler.validatePatternSafety("""\d{3}-\d{4}""", maxContentLength = 10000, flags = flags)
    assertTrue(safe)
    assertEquals(1, cache.size)
    assertNotNull(PatternValidationCache(path, "4.3.2").get("""\d{3}-\d{4}""", flags))
  }

  @Test
  fun testStringsModeBypassesTheCache() {
    val path = Files.createTempDirectory("w9b-compiler").resolve("cache.json")
    val cache = PatternValidationCache(path, "4.3.2")
    cache.put("hello", 0, true, "would be wrong to trust here")
    val compiler = PatternCompiler(validationCache = cache)
    val (safe, reason) =
        compiler.validatePatternSafety("hello", testStrings = listOf("hello world"))
    assertTrue(safe)
    assertEquals("Pattern appears safe", reason)
    assertEquals(1, cache.size)
  }

  @Test
  fun dangerousConstructsAreCheckedBeforeTheCache() {
    val path = Files.createTempDirectory("w9b-compiler").resolve("cache.json")
    val cache = PatternValidationCache(path, "4.3.2")
    cache.put("(.*)+", 0, true, "poisoned entry")
    val compiler = PatternCompiler(validationCache = cache)
    val (safe, reason) = compiler.validatePatternSafety("(.*)+")
    assertFalse(safe)
    assertTrue(reason.startsWith("Pattern contains dangerous construct"))
  }

  @Test
  fun structuralViolationCheckedInTestStringsMode() {
    val compiler = PatternCompiler()
    // An adjacent broad unbounded quantifier pair trips the structural layer.
    val (safe, reason) =
        compiler.validatePatternSafety("""\S+[^\d]+""", testStrings = listOf("abc123"))
    assertFalse(safe)
    assertTrue(reason.isNotEmpty())
  }

  @Test
  fun createSafeMatcherReturnsNullOnDeadline() {
    val compiler = PatternCompiler(defaultTimeout = 0.05)
    val catastrophic = compiler.compilePatternSync("""(a+)+b""")
    val matcher = compiler.createSafeMatcher(catastrophic)
    assertNull(matcher("a".repeat(200) + "c"))
    // Non-matching text within budget returns a null match, not an exception.
    val simple = compiler.compilePatternSync("needle")
    val finder = compiler.createSafeMatcher(simple)
    assertNull(finder("haystack"))
    assertNotNull(finder("find the needle here"))
  }

  @Test
  fun createSafeFinditerMatcherReturnsEmptyOnDeadline() {
    val compiler = PatternCompiler(defaultTimeout = 0.05)
    val catastrophic = compiler.compilePatternSync("""(a+)+b""")
    val finder = compiler.createSafeFinditerMatcher(catastrophic)
    assertTrue(finder("a".repeat(200) + "c").isEmpty())
    val simple = compiler.compilePatternSync("\\d+")
    val counter = compiler.createSafeFinditerMatcher(simple)
    assertEquals(listOf("1", "22", "333"), counter("1 22 333").map { it.group() })
    // The success counter resets the timeout streak.
    reportScanSuccess()
    assertEquals(0, consecutiveTimeoutCount())
  }

  @Test
  fun batchCompileSkipsUnsafeAndInvalidPatterns() {
    val compiler = PatternCompiler()
    val compiled =
        compiler.batchCompile(
            listOf("safe\\d+", "(.*)+", "[also-invalid"),
            validate = true,
            maxContentLength = 1000,
        )
    assertTrue("safe\\d+" in compiled)
    assertFalse("(.*)+" in compiled)
    assertFalse("[also-invalid" in compiled)
  }

  @Test
  fun batchCompileWithoutValidationStillGuardsCompileErrors() {
    val compiler = PatternCompiler()
    val compiled = compiler.batchCompile(listOf("ok\\d+", "["), validate = false)
    assertTrue("ok\\d+" in compiled)
    assertFalse("[" in compiled)
  }

  @Test
  fun timeoutCountersTrack() {
    val before = consecutiveTimeoutCount()
    reportScanTimeout()
    assertEquals(before + 1, consecutiveTimeoutCount())
    reportScanSuccess()
    assertEquals(0, consecutiveTimeoutCount())
  }

  @Test
  fun probeDeadlineConstants() {
    assertEquals(2.0, PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS)
    assertEquals(0.05, PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS)
    assertTrue(PyRe.DeadlineExceededException() is RuntimeException)
  }
}
