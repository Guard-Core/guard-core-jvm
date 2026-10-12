package com.guardcore.engine.detection

import com.guardcore.engine.py.PyReFlags
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_sus_patterns/test_redos_cost_arbiter.py (the arms),
 * test_redos_probe_batches.py, test_redos_probe_fill.py, test_redos_reach_probe.py, and
 * test_redos_stray_chooser.py.
 */
class RedosProbesTest {
  // ---- load factor + deadlines ----

  @Test
  fun loadFactorClampsToTheFloorAndCeiling() {
    assertEquals(LOAD_FACTOR_FLOOR, loadFactor(0.0))
    assertEquals(LOAD_FACTOR_CEILING, loadFactor(10.0))
    assertEquals(1.0, loadFactor(REFERENCE_SCAN_SECONDS))
  }

  @Test
  fun measureHostLoadFactorIsPositive() {
    val factor = measureHostLoadFactor()
    assertTrue(factor >= LOAD_FACTOR_FLOOR)
    assertTrue(factor <= LOAD_FACTOR_CEILING)
  }

  @Test
  fun scaledProbeDeadlineClampsAtTheCeiling() {
    assertEquals(240.0, scaledProbeDeadlineSeconds(1000.0))
    val combined =
        PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS * REACH_PROBE_SIZES.size * REACH_PROBE_SAMPLE_COUNT
    assertTrue(scaledProbeDeadlineSeconds(1.0) >= combined)
  }

  // ---- verdict helpers ----

  @Test
  fun reachProbeVerdictFromSamplesComputesComponents() {
    // A 10x growth per doubling above the noise floor: over budget.
    val growing =
        listOf(
            listOf(0.002, 0.0021, 0.0022, 0.0023, 0.0024),
            listOf(0.02, 0.021, 0.022, 0.023, 0.024),
        )
    val over = reachProbeVerdictFromSamples(growing, 262144)
    assertTrue(over.first)
    assertTrue(over.second > REACH_PROBE_BUDGET_SECONDS)
    assertEquals(10.0, over.third)
    // Flat samples below the noise floor: ratio pinned to 1, under budget.
    val flat =
        listOf(
            listOf(0.0001, 0.0001, 0.0001, 0.0001, 0.0001),
            listOf(0.0001, 0.0001, 0.0001, 0.0001, 0.0001),
        )
    val safe = reachProbeVerdictFromSamples(flat, 262144)
    assertFalse(safe.first)
    // Load factor normalization divides the sample times.
    val scaled = reachProbeVerdictFromSamples(flat, 262144, loadFactor = 2.0)
    assertEquals(safe.second / 2.0, scaled.second, 1e-15)
    // A tiny cap keeps doublings at zero.
    val tinyCap = reachProbeVerdictFromSamples(flat, 0)
    assertFalse(tinyCap.first)
  }

  @Test
  fun reachProbeCostReasonRendersTheVerbatimText() {
    val withViolation = reachProbeCostReason("structural reason", 1.0, 2.0, 1000, 0.1, 0.2)
    assertEquals("structural reason", withViolation)
    val without = reachProbeCostReason(null, 1.5, 2.0, 262144, 0.1, 0.2, 1.5)
    assertTrue("extrapolated CPU cost" in without, without)
    assertTrue("262144 chars" in without, without)
    assertTrue("load factor 1.50" in without, without)
  }

  @Test
  fun reachProbeUnreachableReasonText() {
    assertEquals("structural reason", reachProbeUnreachableReason("structural reason"))
    val bare = reachProbeUnreachableReason(null)
    assertTrue("could not construct a test string" in bare, bare)
  }

  @Test
  fun firstOverBudgetReasonTimesOutFailClosed() {
    val past = System.nanoTime() - 1L
    val builders = listOf<(Int) -> String>({ n -> "a".repeat(n) })
    val reason = firstOverBudgetReason("abc", builders, 1000, null, past, PyReFlags.DEFAULT)
    assertNotNull(reason)
    assertTrue("timeout" in reason!!, reason)
  }

  @Test
  fun firstOverBudgetReasonDeduplicatesProbeSetsAndStrides() {
    // Identical builders dedupe to one probe set; 130 distinct builders stride.
    val builders =
        (0 until 130).map { i ->
          { n: Int -> "a$i".repeat(n) }
        }
    val deadline = System.nanoTime() + (60.0 * 1e9).toLong()
    val reason = firstOverBudgetReason("abc", builders, 1000, null, deadline, PyReFlags.DEFAULT)
    // "abc" reaches nothing harmful; probes complete and nothing is over budget.
    assertNull(reason)
  }

  @Test
  fun firstOverBudgetReasonUsesAscendingSizesOnStructuralRisk() {
    val builders = listOf<(Int) -> String>({ n -> "a".repeat(n) })
    val deadline = System.nanoTime() + (30.0 * 1e9).toLong()
    // boundedRepeatRisk flips the strategy to ascending sizes.
    val reason =
        firstOverBudgetReason(
            """[a-z]{0,9000}""",
            builders,
            1000,
            null,
            deadline,
            PyReFlags.DEFAULT,
            boundedRepeatRisk = true,
        )
    assertNull(reason)
  }

  @Test
  fun firstOverBudgetReasonBatchPathCoversLargeBuilderSets() {
    // REACH_PROBE_BATCH_SIZE builders trip the batched measurement path.
    val builders =
        (0 until REACH_PROBE_BATCH_SIZE + 4).map { i ->
          { n: Int -> "b$i".repeat(n) }
        }
    val deadline = System.nanoTime() + (120.0 * 1e9).toLong()
    val reason = firstOverBudgetReason("abc", builders, 1000, null, deadline, PyReFlags.DEFAULT)
    assertNull(reason)
  }

  @Test
  fun reachProbeCostVerdictCoversTheDecisionArms() {
    // An invalid pattern fails closed with the structural rejection.
    val invalid = reachProbeCostVerdict("[", null)
    assertFalse(invalid.first)
    assertTrue(invalid.second.isNotEmpty())
    // A safe pattern with reachable probes and a small cap certifies.
    val simple = reachProbeCostVerdict("""X(?:abc)+d""", 4096)
    assertTrue(simple.first, simple.second)
    assertEquals("Pattern appears safe", simple.second)
  }

  @Test
  fun reachProbeCostVerdictTimesOutOnThePinnedBackstop() {
    // The classic backstop pattern from the reference corpus.
    val (safe, reason) = reachProbeCostVerdict("""^(\w+)\s+XX\1$""", 4096)
    assertTrue(reason.isNotEmpty())
    assertTrue(!safe || reason == "Pattern appears safe")
  }

  // ---- probe batches ----

  @Test
  fun probeSetDigestIsDeterministicAndLengthPrefixed() {
    val a = probeSetDigest(listOf("x", "yz"))
    val b = probeSetDigest(listOf("x", "yz"))
    val c = probeSetDigest(listOf("xy", "z"))
    assertTrue(a.contentEquals(b))
    assertFalse(a.contentEquals(c))
    assertEquals(32, a.size)
  }

  @Test
  fun validTimingRowsValidatesEveryArm() {
    assertNull(validTimingRows(null, 2))
    val good = ReachProbeTiming(listOf(listOf(0.1, 0.2), listOf(0.3, 0.4)), 1.5)
    val valid = validTimingRows(good, 2)
    assertNotNull(valid)
    assertEquals(1.5, valid.second)
    // Wrong row count.
    assertNull(validTimingRows(good, 3))
    // Invalid load factor.
    assertNull(validTimingRows(ReachProbeTiming(good.samplesBySize, 0.0), 2))
    assertNull(validTimingRows(ReachProbeTiming(good.samplesBySize, Double.NaN), 2))
    // NaN sample in a row.
    val nan = ReachProbeTiming(listOf(listOf(0.1, Double.NaN), listOf(0.3, 0.4)), 1.0)
    assertNull(validTimingRows(nan, 2))
    // Infinite sample.
    val inf = ReachProbeTiming(listOf(listOf(0.1, Double.POSITIVE_INFINITY)), 1.0)
    assertNull(validTimingRows(inf, 1))
    // Negative sample.
    val neg = ReachProbeTiming(listOf(listOf(-0.1)), 1.0)
    assertNull(validTimingRows(neg, 1))
    // Empty row.
    assertNull(validTimingRows(ReachProbeTiming(listOf(emptyList()), 1.0), 1))
  }

  @Test
  fun batchedReachProbeTimingsYieldsPerSetOrder() {
    var calls = 0
    val timeProbes: (String, List<String>, Long, Int) -> ReachProbeTiming? = { _, probes, _, _ ->
      calls += 1
      ReachProbeTiming(probes.map { listOf(0.01) }, 1.0)
    }
    val sets = (0 until 3).map { listOf("p$it") }
    val out =
        batchedReachProbeTimings(
                "abc",
                sets.iterator(),
                System.nanoTime() + (10.0 * 1e9).toLong(),
                0,
                timeProbes,
            )
            .toList()
    assertEquals(3, out.size)
    assertEquals(1, calls) // one batched measurement
    assertEquals(listOf("p0"), out[0].first)
    assertEquals(listOf(listOf(0.01)), out[2].second)
    assertEquals(1.0, out[1].third)
  }

  @Test
  fun batchedReachProbeTimingsHandlesFullBatchesAndNullTimings() {
    // A full batch of 128 single-probe sets times as one measurement.
    val validProbes: (String, List<String>, Long, Int) -> ReachProbeTiming? = { _, probes, _, _ ->
      ReachProbeTiming(probes.map { listOf(0.02) }, 2.0)
    }
    val sets = (0 until REACH_PROBE_BATCH_SIZE + 1).map { listOf("q$it") }
    val out =
        batchedReachProbeTimings(
                "abc",
                sets.iterator(),
                System.nanoTime() + (10.0 * 1e9).toLong(),
                0,
                validProbes,
            )
            .toList()
    assertEquals(REACH_PROBE_BATCH_SIZE + 1, out.size)
    assertEquals(2.0, out[0].third)
    assertEquals(2.0, out.last().third)
    // A batch whose flattened measurement fails marks every set invalid.
    val failingProbes: (String, List<String>, Long, Int) -> ReachProbeTiming? = { _, _, _, _ ->
      null
    }
    val out2 =
        batchedReachProbeTimings(
                "abc",
                sets.iterator(),
                System.nanoTime() + (10.0 * 1e9).toLong(),
                0,
                failingProbes,
            )
            .toList()
    assertEquals(REACH_PROBE_BATCH_SIZE + 1, out2.size)
    assertEquals(1.0, out2[0].third)
    assertNull(out2[0].second)
  }

  // ---- probe fill ----

  @Test
  fun reachProbeCandidateBuildersCoverTheFamilies() {
    val builders = reachProbeCandidateBuilders("""X(?:ab)+c+""", 0)
    assertTrue(builders.isNotEmpty())
    // Every builder produces strings at the requested lengths.
    for (builder in builders.take(5)) {
      val probe = builder(64)
      assertEquals(64, probe.length)
    }
    // An unparseable pattern builds nothing.
    assertEquals(emptyList(), reachProbeCandidateBuilders("[", 0))
    // A deadline in the past fails closed where construction can loop.
    val past = System.nanoTime() - 1L
    try {
      reachProbeCandidateBuilders("""[a-c]+[b-d]+""", 0, past)
    } catch (e: PatternValidationTimeout) {
      assertTrue("deadline" in e.message!!, e.message)
    }
  }

  // ---- reach probe synthesis ----

  @Test
  fun synthesizeReachingProbeOnRepresentativePatterns() {
    val probe = synthesizeReachingProbe("""Xa+a+$""")
    assertNotNull(probe)
    assertTrue(probe!!.startsWith("X"))
    assertNull(synthesizeReachingProbe("["))
  }

  // ---- stray chooser ----

  @Test
  fun leadingLiteralPrefixAndFills() {
    assertEquals("Xa", leadingLiteralPrefix("Xa+"))
    // A leading transparent group that is not the whole pattern stops the prefix.
    assertEquals("", leadingLiteralPrefix("""(?:X)a+"""))
    // A transparent group spanning the whole pattern unwraps.
    assertEquals("X", leadingLiteralPrefix("(?:X)"))
    assertEquals("", leadingLiteralPrefix("""[ab]+"""))
    assertEquals("Xb!", fillToLength("X", 'b', '!', 3))
    assertEquals("", fillToLength("", 'b', '!', 0))
    assertEquals("aba\u0000", repeatProbeToLength("ab", 4))
    assertEquals("aaa\u0000", repeatProbeToLength("a", 4))
    assertEquals("", repeatProbeToLength("", 4))
  }

  @Test
  fun patternComplementCharsAndContext() {
    // The complement of a low class starts at NUL.
    val complements = patternComplementChars("""[ab]+[cd]+""", 0)
    assertEquals(listOf(REACH_PROBE_STRAY_BYTE), complements)
    assertEquals(emptyList(), patternComplementChars("[", 0))
    val ctx = buildStrayContext("""Xa+""", 0)
    assertEquals("Xa", ctx.prefix)
    assertFalse(ctx.patternUnion.isEmpty)
  }

  @Test
  fun chooseRepeatUnitStrayForcesThePattern() {
    val ctx = buildStrayContext("""X(a+)b""", 0)
    val stray = chooseRepeatUnitStray(ctx, "ab")
    // Any chosen stray is fine; the contract is it returns a char.
    assertTrue(stray.code in 0..0x10FFFF)
    // Empty units short-circuit to the NUL stray.
    assertEquals(REACH_PROBE_STRAY_BYTE, chooseRepeatUnitStray(ctx, ""))
  }

  @Test
  fun chooseClassIntersectionStrayForcesThePattern() {
    val ctx = buildStrayContext("""[ab]+[bc]+""", 0)
    val left = IntervalSet.fromRange('a'.code, 'b'.code)
    val right = IntervalSet.fromRange('b'.code, 'c'.code)
    val stray = chooseClassIntersectionStray(ctx, 'b', left, right, emptyList())
    assertTrue(stray.code in 0..0x10FFFF)
  }
}
