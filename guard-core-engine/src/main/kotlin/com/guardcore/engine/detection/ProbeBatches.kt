package com.guardcore.engine.detection

import java.security.MessageDigest

/**
 * Probe-set deduplication, timing-row validation, and batched measurement.
 *
 * Port of guard_core/detection_engine/_redos_probe_batches.py. The reference batches probe sets
 * into one subprocess per 128 sets; the JVM timer is in-process under the deadline, so the batcher
 * simply forwards sets while keeping the same validation and yield order.
 */
public const val REACH_PROBE_BATCH_SIZE: Int = 128

/** Timing rows by probe size plus the host load factor (reference ReachProbeTiming). */
public class ReachProbeTiming(
    public val samplesBySize: List<List<Double>>,
    public val loadFactor: Double,
)

/** _probe_set_digest: sha256 over the probe set (length-prefixed). */
public fun probeSetDigest(probes: List<String>): ByteArray {
  val digest = MessageDigest.getInstance("SHA-256")
  var n = probes.size
  digest.update(
      byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()),
  )
  for (probe in probes) {
    val encoded = probe.toByteArray(Charsets.UTF_8)
    n = encoded.size
    for (shift in 56 downTo 0 step 8) {
      digest.update(((n ushr shift) and 0xFF).toByte())
    }
    digest.update(encoded)
  }
  return digest.digest()
}

private fun validSample(value: Any?): Boolean =
    value is Double && !value.isNaN() && !value.isInfinite() && value >= 0

private fun validLoadFactor(value: Any?): Boolean = validSample(value) && (value as Double) > 0

private fun validSampleRow(row: Any?): Boolean =
    row is List<*> && row.isNotEmpty() && row.all { validSample(it) }

/** _valid_timing_rows: validated (rows, load_factor) or null. */
public fun validTimingRows(
    timing: ReachProbeTiming?,
    expectedRows: Int,
): Pair<List<List<Double>>, Double>? {
  if (timing == null) return null
  val rows = timing.samplesBySize
  val loadFactor = timing.loadFactor
  if (rows.size != expectedRows || !validLoadFactor(loadFactor)) return null
  if (!rows.all { validSampleRow(it) }) return null
  return Pair(rows, loadFactor)
}

/**
 * _batched_reach_probe_timings with the in-process timer: yields (probe set, rows-or-null, load
 * factor) per set, preserving the reference's yield order.
 */
public fun batchedReachProbeTimings(
    pattern: String,
    probeSets: Iterator<List<String>>,
    deadlineNanos: Long,
    flags: Int,
    timeProbes: (String, List<String>, Long, Int) -> ReachProbeTiming?,
): Sequence<Triple<List<String>, List<List<Double>>?, Double>> = sequence {
  val batch = ArrayList<List<String>>()
  while (probeSets.hasNext()) {
    batch.add(probeSets.next())
    if (batch.size < REACH_PROBE_BATCH_SIZE) continue
    yieldAll(measureProbeBatch(pattern, batch, deadlineNanos, flags, timeProbes))
    batch.clear()
  }
  if (batch.isNotEmpty()) {
    yieldAll(measureProbeBatch(pattern, batch, deadlineNanos, flags, timeProbes))
  }
}

private fun measureProbeBatch(
    pattern: String,
    batch: List<List<String>>,
    deadlineNanos: Long,
    flags: Int,
    timeProbes: (String, List<String>, Long, Int) -> ReachProbeTiming?,
): List<Triple<List<String>, List<List<Double>>?, Double>> {
  val flattened = batch.flatten()
  val timing = timeProbes(pattern, flattened, deadlineNanos, flags)
  val valid = validTimingRows(timing, flattened.size)
  if (valid == null) {
    return batch.map { Triple(it, null, 1.0) }
  }
  val (rows, loadFactor) = valid
  val out = ArrayList<Triple<List<String>, List<List<Double>>?, Double>>()
  var offset = 0
  for (probes in batch) {
    val nextOffset = offset + probes.size
    out.add(Triple(probes, rows.subList(offset, nextOffset), loadFactor))
    offset = nextOffset
  }
  return out
}
