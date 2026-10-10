package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyRePattern
import java.lang.management.ManagementFactory
import kotlin.math.log2
import kotlin.math.pow

/**
 * The cost arbiter: decide whether a pattern's extrapolated CPU cost at the configured cap stays
 * inside the safety budget, by synthesizing reaching probes and timing them.
 *
 * Port of guard_core/detection_engine/_redos_cost_arbiter.py. The reference times probes in
 * killable subprocesses; the JVM analog is in-process timing under the DeadlineCharSequence abort
 * (the Go-posture hard match deadline), with thread CPU time as the clock (time.process_time
 * analog) so a loaded host is normalized out.
 */
public const val PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS: Double = 2.0
public const val PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS: Double = 0.05

public val REACH_PROBE_SIZES: IntArray = intArrayOf(4000, 8000, 16000, 32000)
public val REACH_VERDICT_PROBE_SIZES: IntArray = intArrayOf(16000, 32000)
public const val REACH_PROBE_BUDGET_SECONDS: Double = 0.05
public const val REFERENCE_SCAN_SECONDS: Double = 0.00229
public const val LOAD_FACTOR_FLOOR: Double = 0.25
public const val LOAD_FACTOR_CEILING: Double = 8.0
public const val REACH_PROBE_NOISE_FLOOR_SECONDS: Double = 0.001
public const val REACH_PROBE_SAMPLE_COUNT: Int = 5
public const val REACH_PROBE_LARGE_SAMPLE_SECONDS: Double = 0.2
public const val REACH_PROBE_FULL_SAMPLE_TRIGGER_SECONDS: Double = REACH_PROBE_NOISE_FLOOR_SECONDS
public const val PATTERN_SAFETY_DEFAULT_CAP: Int = 262144
public const val MAX_TIMED_PROBE_SETS: Int = 512
public const val REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS: Double = 240.0
private const val REFERENCE_SCAN_PROBE_LENGTH = 32000

private val REFERENCE_SCAN_PATTERN: PyRePattern =
    PyRe.compile(
        "/[0-9]*\\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|CONCAT|CHAR|UPDATE)\\b",
        PyReFlags.IGNORECASE,
    )

private val referenceProbe: String = "/" + "0".repeat(REFERENCE_SCAN_PROBE_LENGTH)

private fun threadCpuNanos(): Long {
  val bean = ManagementFactory.getThreadMXBean()
  if (bean.isCurrentThreadCpuTimeSupported) {
    bean.setThreadCpuTimeEnabled(true)
    val t = bean.currentThreadCpuTime
    if (t >= 0) return t
  }
  return System.nanoTime()
}

/** _load_factor. */
public fun loadFactor(referenceSeconds: Double): Double {
  val raw = referenceSeconds / REFERENCE_SCAN_SECONDS
  return raw.coerceIn(LOAD_FACTOR_FLOOR, LOAD_FACTOR_CEILING)
}

/** _measure_host_load_factor: reference scan timed in-process. */
public fun measureHostLoadFactor(): Double {
  return try {
    val times = ArrayList<Double>()
    repeat(REACH_PROBE_SAMPLE_COUNT) {
      val start = threadCpuNanos()
      REFERENCE_SCAN_PATTERN.search(referenceProbe, 0, Long.MAX_VALUE)
      times.add((threadCpuNanos() - start) / 1e9)
    }
    loadFactor(times.min())
  } catch (e: Exception) {
    1.0
  }
}

/** _scaled_probe_deadline_seconds. */
public fun scaledProbeDeadlineSeconds(loadFactor: Double): Double =
    minOf(
        REACH_PROBE_COMBINED_TIMEOUT_SECONDS * maxOf(loadFactor, 1.0),
        REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS,
    )

private val REACH_PROBE_COMBINED_TIMEOUT_SECONDS: Double =
    PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS * REACH_PROBE_SIZES.size * REACH_PROBE_SAMPLE_COUNT

private fun remainingBudgetNanos(deadlineNanos: Long): Long = deadlineNanos - System.nanoTime()

private fun clippedTimeoutSeconds(defaultTimeoutSeconds: Double, deadlineNanos: Long): Double =
    minOf(defaultTimeoutSeconds, remainingBudgetNanos(deadlineNanos) / 1e9)

/** Timing rows loader used by both strategies. */
private fun runReachProbeTiming(
    pattern: String,
    probes: List<String>,
    timeoutSeconds: Double,
    flags: Int,
): ReachProbeTiming? {
  if (timeoutSeconds <= 0) return null
  val compiled =
      try {
        PyRe.compile(pattern, flags)
      } catch (e: Exception) {
        return null
      }
  val deadlineNanos = System.nanoTime() + (timeoutSeconds * 1e9).toLong()
  val referenceTimes = ArrayList<Double>()
  try {
    repeat(REACH_PROBE_SAMPLE_COUNT) {
      val start = threadCpuNanos()
      REFERENCE_SCAN_PATTERN.search(referenceProbe, 0, deadlineNanos)
      referenceTimes.add((threadCpuNanos() - start) / 1e9)
    }
  } catch (e: PyRe.DeadlineExceededException) {
    return null
  }
  val results = ArrayList<List<Double>>()
  for (probe in probes) {
    val probeTimes = ArrayList<Double>()
    try {
      val start = threadCpuNanos()
      compiled.search(probe, 0, deadlineNanos)
      probeTimes.add((threadCpuNanos() - start) / 1e9)
      if (probeTimes[0] >= REACH_PROBE_FULL_SAMPLE_TRIGGER_SECONDS) {
        for (i in 1 until REACH_PROBE_SAMPLE_COUNT) {
          val s = threadCpuNanos()
          compiled.search(probe, 0, deadlineNanos)
          probeTimes.add((threadCpuNanos() - s) / 1e9)
          if (probeTimes.last() > REACH_PROBE_LARGE_SAMPLE_SECONDS) break
        }
      }
    } catch (e: PyRe.DeadlineExceededException) {
      return null
    }
    results.add(probeTimes.sorted())
  }
  return ReachProbeTiming(results, loadFactor(referenceTimes.min()))
}

/** _time_reach_probes_subprocess: one batched timing call for the last-2 sizes. */
private fun timeReachProbes(
    pattern: String,
    probes: List<String>,
    deadlineNanos: Long,
    flags: Int,
): ReachProbeTiming? {
  val timeout = clippedTimeoutSeconds(REACH_PROBE_COMBINED_TIMEOUT_SECONDS, deadlineNanos)
  if (timeout <= 0) return null
  return runReachProbeTiming(pattern, probes, timeout, flags)
}

/** _time_reach_probes_ascending: one probe per call, all sizes. */
private fun timeReachProbesAscending(
    pattern: String,
    probes: List<String>,
    deadlineNanos: Long,
    flags: Int,
): ReachProbeTiming? {
  val samplesBySize = ArrayList<List<Double>>()
  var load = LOAD_FACTOR_CEILING
  for (probe in probes) {
    val timeout = clippedTimeoutSeconds(REACH_PROBE_CHILD_TIMEOUT_SECONDS, deadlineNanos)
    if (timeout <= 0) return null
    val timing = runReachProbeTiming(pattern, listOf(probe), timeout, flags) ?: return null
    samplesBySize.addAll(timing.samplesBySize)
    load = minOf(load, timing.loadFactor)
  }
  return ReachProbeTiming(samplesBySize, load)
}

private const val REACH_PROBE_CHILD_START_ALLOWANCE_SECONDS: Double = 0.5

// PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS + REACH_PROBE_CHILD_START_ALLOWANCE_SECONDS (the
// reference's derived constant; inlined because Kotlin const initializers cannot compute).
private const val REACH_PROBE_CHILD_TIMEOUT_SECONDS: Double = 2.5

private fun median(samples: List<Double>): Double = samples[samples.size / 2]

/** _reach_probe_verdict_from_samples. */
public fun reachProbeVerdictFromSamples(
    samplesBySize: List<List<Double>>,
    cap: Int,
    loadFactor: Double = 1.0,
): Quintuple {
  val median32 = median(samplesBySize[samplesBySize.size - 1]) / loadFactor
  val min16 = samplesBySize[samplesBySize.size - 2][0] / loadFactor
  val min32 = samplesBySize[samplesBySize.size - 1][0] / loadFactor
  val ratio = if (min16 > REACH_PROBE_NOISE_FLOOR_SECONDS) maxOf(min32 / min16, 1.0) else 1.0
  val doublings = log2(maxOf(cap, 1).toDouble() / REACH_PROBE_SIZES[3].toDouble())
  val extrapolated = if (ratio > 0) min32 * Math.pow(ratio, doublings) else min32
  val overBudget = extrapolated > REACH_PROBE_BUDGET_SECONDS
  return Quintuple(overBudget, extrapolated, ratio, min32, median32)
}

/** Simple 5-tuple for the verdict components (python returns a tuple). */
public class Quintuple(
    public val first: Boolean,
    public val second: Double,
    public val third: Double,
    public val fourth: Double,
    public val fifth: Double,
)

/** _reach_probe_cost_reason: the over-budget rejection text (format kept verbatim). */
public fun reachProbeCostReason(
    structuralViolation: String?,
    extrapolated: Double,
    ratio: Double,
    cap: Int,
    min32: Double,
    median32: Double,
    loadFactor: Double = 1.0,
): String {
  if (structuralViolation != null) return structuralViolation
  return ("Pattern extrapolated CPU cost at cap ($cap chars) is %.3fs, exceeding the " +
          "%.2fs safety budget (growth ratio %.2fx per doubling, CPU time at 32000 " +
          "chars: min %.4fs, median %.4fs over %d runs, normalized by host load " +
          "factor %.2f)")
      .format(
          extrapolated,
          REACH_PROBE_BUDGET_SECONDS,
          ratio,
          min32,
          median32,
          REACH_PROBE_SAMPLE_COUNT,
          loadFactor,
      )
}

/** _reach_probe_unreachable_reason. */
public fun reachProbeUnreachableReason(structuralViolation: String?): String {
  if (structuralViolation != null) return structuralViolation
  return ("Pattern validation probe could not construct a test string that " +
      "reaches every quantified region of this pattern; rejecting rather " +
      "than certifying safety on an unreachable probe")
}

private fun reachProbeTimingStrategy(
    structuralViolation: String?,
    boundedRepeatRisk: Boolean,
): (String, List<String>, Long, Int) -> ReachProbeTiming? =
    if (structuralViolation != null || boundedRepeatRisk) ::timeReachProbesAscending
    else ::timeReachProbes

private fun reachProbeSizesForStrategy(
    structuralViolation: String?,
    boundedRepeatRisk: Boolean,
): IntArray =
    if (structuralViolation != null || boundedRepeatRisk) REACH_PROBE_SIZES
    else REACH_VERDICT_PROBE_SIZES

private fun uniqueProbeSets(
    builders: List<(Int) -> String>,
    probeSizes: IntArray,
): Iterator<List<String>> {
  val seen = HashSet<ByteArray>()
  val sets = ArrayList<List<String>>()
  outer@ for (builder in builders) {
    val probes = probeSizes.map { size -> builder(size) }
    val digest = probeSetDigest(probes)
    if (!seen.add(digest)) continue@outer
    sets.add(probes)
  }
  return sets.iterator()
}

private fun strideSampledProbeSets(
    probeSets: List<List<String>>,
    cap: Int,
): List<List<String>> {
  val total = probeSets.size
  if (total <= cap) return probeSets
  val stride = ceil(total.toDouble() / cap).toInt()
  return probeSets.filterIndexed { index, _ -> index % stride == 0 }
}

/** _retry_reach_probe_timing. */
private fun retryReachProbeTiming(
    pattern: String,
    probes: List<String>,
    deadlineNanos: Long,
    flags: Int,
    timeProbes: (String, List<String>, Long, Int) -> ReachProbeTiming?,
): ReachProbeTiming? {
  val validated =
      validTimingRows(timeProbes(pattern, probes, deadlineNanos, flags), probes.size) ?: return null
  return ReachProbeTiming(validated.first, validated.second)
}

/** _first_over_budget_reason. */
public fun firstOverBudgetReason(
    pattern: String,
    builders: List<(Int) -> String>,
    cap: Int,
    structuralViolation: String?,
    deadlineNanos: Long,
    flags: Int = PyReFlags.DEFAULT,
    boundedRepeatRisk: Boolean = false,
): String? {
  val timeProbes = reachProbeTimingStrategy(structuralViolation, boundedRepeatRisk)
  val probeSizes = reachProbeSizesForStrategy(structuralViolation, boundedRepeatRisk)
  val sampled =
      strideSampledProbeSets(
          uniqueProbeSets(builders, probeSizes).asSequence().toList(),
          MAX_TIMED_PROBE_SETS,
      )
  val useBatching =
      structuralViolation == null && !boundedRepeatRisk && builders.size >= REACH_PROBE_BATCH_SIZE
  val timedResults: Iterator<Triple<List<String>, List<List<Double>>?, Double>> =
      if (useBatching) {
        batchedReachProbeTimings(pattern, sampled.iterator(), deadlineNanos, flags, timeProbes)
            .iterator()
      } else {
        sampled
            .map { probes ->
              val validated =
                  validTimingRows(timeProbes(pattern, probes, deadlineNanos, flags), probes.size)
              if (validated == null) Triple(probes, null, 1.0)
              else Triple(probes, validated.first, validated.second)
            }
            .iterator()
      }
  for ((probes, sampleRows, load) in timedResults) {
    var timing = if (sampleRows == null) null else ReachProbeTiming(sampleRows, load)
    if (timing == null) {
      return structuralViolation
          ?: ("Pattern validation probe exceeded the killable-subprocess " +
              "timeout while measuring reach-probe cost at scale")
    }
    var verdict = reachProbeVerdictFromSamples(timing.samplesBySize, cap, timing.loadFactor)
    if (verdict.first && remainingBudgetNanos(deadlineNanos) > 0) {
      val retry = retryReachProbeTiming(pattern, probes, deadlineNanos, flags, timeProbes)
      if (retry != null) {
        timing = retry
        verdict = reachProbeVerdictFromSamples(timing.samplesBySize, cap, timing.loadFactor)
      }
    }
    if (verdict.first) {
      return reachProbeCostReason(
          structuralViolation,
          verdict.second,
          verdict.third,
          cap,
          verdict.fourth,
          verdict.fifth,
          timing.loadFactor,
      )
    }
  }
  return null
}

/**
 * _reach_probe_cost_verdict: (safe, reason). Deadline scale uses the in-process reference scan; the
 * construction helpers honor the same deadline.
 */
public fun reachProbeCostVerdict(
    pattern: String,
    maxContentLength: Int?,
    flags: Int = PyReFlags.DEFAULT,
): Pair<Boolean, String> =
    // Probe timing runs on the big-stack pool: the synthesized probes drive deep matcher
    // recursion, and one hop per verdict keeps the timed sections on one thread (matching
    // the reference's per-probe subprocess isolation in spirit and cost model).
    com.guardcore.engine.py.RegexWorkers.submit {
      reachProbeCostVerdictInternal(pattern, maxContentLength, flags)
    }

private fun reachProbeCostVerdictInternal(
    pattern: String,
    maxContentLength: Int?,
    flags: Int,
): Pair<Boolean, String> {
  val deadlineNanos =
      System.nanoTime() + (scaledProbeDeadlineSeconds(measureHostLoadFactor()) * 1e9).toLong()
  val cap = maxContentLength ?: PATTERN_SAFETY_DEFAULT_CAP
  val structuralViolation = firstStructuralSafetyViolation(pattern)
  val boundedRepeatRisk = hasLargeBoundedRepeat(pattern, flags)
  if (synthesizeReachingProbe(pattern) == null) {
    return Pair(false, reachProbeUnreachableReason(structuralViolation))
  }
  val builders =
      try {
        reachProbeCandidateBuilders(pattern, flags, deadlineNanos)
      } catch (e: PatternValidationTimeout) {
        return Pair(false, structuralViolation ?: (e.message ?: "probe construction failed"))
      }
  if (remainingBudgetNanos(deadlineNanos) <= 0) {
    return Pair(false, "Pattern validation probe construction exceeded its deadline")
  }
  if (builders.isEmpty()) {
    return Pair(true, "Pattern appears safe")
  }
  val overBudgetReason =
      firstOverBudgetReason(
          pattern,
          builders,
          cap,
          structuralViolation,
          deadlineNanos,
          flags,
          boundedRepeatRisk,
      )
  if (overBudgetReason != null) {
    return Pair(false, overBudgetReason)
  }
  return Pair(true, "Pattern appears safe")
}

private fun ceil(x: Double): Int = kotlin.math.ceil(x).toInt()
