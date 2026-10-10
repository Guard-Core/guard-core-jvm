package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyRePattern

/**
 * PatternCompiler: cached compilation plus the ReDoS validation chain.
 *
 * Port of guard_core/detection_engine/compiler.py. The reference submits regex work to a shared
 * thread pool with a future timeout; the JVM port runs matches inline under the
 * DeadlineCharSequence hard deadline (the Go posture), which aborts inside the match instead of
 * abandoning a pool thread.
 */
public class PatternCompiler(
    public val defaultTimeout: Double = 5.0,
    maxCacheSize: Int = 1000,
    private val validationCache: PatternValidationCache? = null,
) {
  public val maxCacheSize: Int = minOf(maxCacheSize, 5000)
  private val compiledCache = LinkedHashMap<String, PyRePattern>()
  private val cacheLock = Any()

  public fun compilePattern(pattern: String, flags: Int = PyReFlags.DEFAULT): PyRePattern {
    val cacheKey = "$pattern:$flags"
    synchronized(cacheLock) {
      compiledCache[cacheKey]?.let { cached ->
        // LRU refresh: remove and re-append.
        compiledCache.remove(cacheKey)
        compiledCache[cacheKey] = cached
        return cached
      }
      if (compiledCache.size >= maxCacheSize) {
        val oldestKey = compiledCache.keys.first()
        compiledCache.remove(oldestKey)
      }
      val compiled = PyRe.compile(pattern, flags)
      compiledCache[cacheKey] = compiled
      return compiled
    }
  }

  public fun compilePatternSync(pattern: String, flags: Int = PyReFlags.DEFAULT): PyRePattern =
      PyRe.compile(pattern, flags)

  /**
   * validate_pattern_safety: dangerous constructs, compile check, structural checks, then either
   * test-string probing or the empirical cost verdict (cached when a cache is set).
   */
  public fun validatePatternSafety(
      pattern: String,
      testStrings: List<String>? = null,
      maxContentLength: Int? = null,
      flags: Int = PyReFlags.DEFAULT,
  ): Pair<Boolean, String> {
    val dangerousViolation = dangerousConstructViolation(pattern)
    if (dangerousViolation != null) return Pair(false, dangerousViolation)

    try {
      compilePatternSync(pattern, flags)
    } catch (e: Exception) {
      return Pair(false, "Pattern validation failed: ${e.message}")
    }

    if (testStrings != null) {
      val structuralViolation = firstStructuralSafetyViolation(pattern)
      if (structuralViolation != null) return Pair(false, structuralViolation)
      return runPatternSafetyProbe(pattern, testStrings, flags)
    }

    if (validationCache != null) {
      val cached = validationCache.get(pattern, flags)
      if (cached != null) return cached
    }
    val verdict = reachProbeCostVerdict(pattern, maxContentLength, flags)
    if (validationCache != null) {
      validationCache.put(pattern, flags, verdict.first, verdict.second)
    }
    return verdict
  }

  /**
   * _run_pattern_safety_probe_subprocess analog: every test string must match inside the per-string
   * threshold, all under one hard deadline.
   */
  private fun runPatternSafetyProbe(
      pattern: String,
      testStrings: List<String>,
      flags: Int,
  ): Pair<Boolean, String> {
    val compiled =
        try {
          PyRe.compile(pattern, flags)
        } catch (e: Exception) {
          return Pair(false, "Pattern validation failed: ${e.message}")
        }
    val deadlineNanos = System.nanoTime() + (PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS * 1e9).toLong()
    for (testStr in testStrings) {
      val start = System.nanoTime()
      try {
        compiled.search(testStr, 0, deadlineNanos)
      } catch (e: PyRe.DeadlineExceededException) {
        return Pair(
            false,
            "Pattern validation probe exceeded the " +
                "${PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS}s killable-subprocess timeout",
        )
      }
      val elapsedSeconds = (System.nanoTime() - start) / 1e9
      if (elapsedSeconds > PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS) {
        return Pair(
            false,
            "Pattern timed out on test string of length ${testStr.length}",
        )
      }
    }
    return Pair(true, "Pattern appears safe")
  }

  /** create_safe_matcher: search with the configured timeout, null on deadline. */
  public fun createSafeMatcher(
      pattern: PyRePattern,
      timeout: Double? = null,
  ): (String) -> PyReMatch? {
    val matchTimeout = timeout ?: defaultTimeout
    return { text ->
      try {
        pattern.search(text, 0, relativeDeadlineNanos(matchTimeout))
      } catch (e: PyRe.DeadlineExceededException) {
        reportScanTimeout()
        null
      } catch (e: Exception) {
        null
      }
    }
  }

  /** create_safe_finditer_matcher: all matches with the configured timeout, empty on deadline. */
  public fun createSafeFinditerMatcher(
      pattern: PyRePattern,
      timeout: Double? = null,
  ): (String) -> List<PyReMatch> {
    val matchTimeout = timeout ?: defaultTimeout
    return { text ->
      try {
        pattern.finditer(text, relativeDeadlineNanos(matchTimeout))
      } catch (e: PyRe.DeadlineExceededException) {
        reportScanTimeout()
        emptyList()
      } catch (e: Exception) {
        emptyList()
      }
    }
  }

  public fun batchCompile(
      patterns: List<String>,
      validate: Boolean = true,
      maxContentLength: Int? = null,
  ): Map<String, PyRePattern> {
    val compiledPatterns = LinkedHashMap<String, PyRePattern>()
    for (pattern in patterns) {
      if (validate) {
        val (isSafe, _) = validatePatternSafety(pattern, maxContentLength = maxContentLength)
        if (!isSafe) continue
      }
      try {
        compiledPatterns[pattern] = compilePattern(pattern)
      } catch (e: com.guardcore.engine.py.ReParseError) {
        continue
      } catch (e: PyRe.ReCompileError) {
        continue
      }
    }
    return compiledPatterns
  }

  public fun clearCache() {
    synchronized(cacheLock) { compiledCache.clear() }
  }

  private fun relativeDeadlineNanos(timeoutSeconds: Double): Long =
      System.nanoTime() + (timeoutSeconds * 1e9).toLong()
}

/**
 * report_scan_timeout / report_scan_success: the reference replaces its shared executor after
 * repeated timeouts; the JVM deadline abort never poisons shared state, so these are counters kept
 * for the monitor surface (kept behavior-compatible no-ops).
 */
private val consecutiveTimeouts = java.util.concurrent.atomic.AtomicInteger(0)

public fun reportScanTimeout() {
  consecutiveTimeouts.incrementAndGet()
}

public fun reportScanSuccess() {
  consecutiveTimeouts.set(0)
}

public fun consecutiveTimeoutCount(): Int = consecutiveTimeouts.get()
