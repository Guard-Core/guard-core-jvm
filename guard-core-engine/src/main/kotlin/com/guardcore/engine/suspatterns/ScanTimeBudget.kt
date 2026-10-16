package com.guardcore.engine.suspatterns

import java.lang.management.ManagementFactory
import java.util.logging.Logger

/** Pattern name of the weighted threat recorded when a request spends its scan time budget. */
public const val SCAN_TIME_BUDGET_EXHAUSTED_PATTERN: String = "scan_time_budget_exhausted"

/**
 * The per-request regex scan budget (detection_max_scan_seconds), accumulated across every field.
 *
 * It counts the CPU time of the thread that runs the scan, not wall time: on a loaded host a benign
 * request waits on the 4 shared scan workers for far longer than it computes, and wall time would
 * flag it. A request scans on one worker at a time and the pool hands results back through a
 * FutureTask, so the counters need no further synchronization.
 *
 * CPU is charged per pass (one loop over the pattern table): the CPU clock is read when the pass
 * opens, at each [SLICE_NANOS] wall-clock slice boundary and when the pass closes, never per
 * pattern. The slice clock starts with the budget, so it spans every value of the request. The
 * [exhausted] check only compares accumulated time and never reads a clock.
 */
public class ScanTimeBudget(
    public val capSeconds: Double,
    private val cpuClock: () -> Long = { THREADS.currentThreadCpuTime },
    private val wallClock: () -> Long = System::nanoTime,
) {
  private var spentNanos: Long = 0L
  private var sliceStartNanos: Long = wallClock()
  private var cpuMark: Long = NO_PASS
  private var warned: Boolean = false

  public val spentSeconds: Double
    get() = spentNanos / 1e9

  /** Python `_scan_time_budget_exhausted`: no time left. */
  public fun exhausted(): Boolean = capSeconds - spentSeconds <= 0.0

  /** Opens a pass: one CPU clock reading on the calling (worker) thread. */
  public fun openPass() {
    cpuMark = cpuClock()
  }

  /** Called after each pattern of a pass: charges CPU only when the 2 ms wall slice has elapsed. */
  public fun sliceCheck() {
    val now = wallClock()
    if (now - sliceStartNanos >= SLICE_NANOS) {
      charge()
      sliceStartNanos = now
    }
  }

  /** Charges the CPU spent since the last charge of the open pass. */
  public fun charge() {
    if (cpuMark != NO_PASS) {
      val now = cpuClock()
      spentNanos += now - cpuMark
      cpuMark = now
    }
  }

  /** Closes the pass with a final charge. */
  public fun closePass() {
    charge()
    cpuMark = NO_PASS
  }

  /** Python `_warn_scan_time_cap_reached_once`. */
  public fun warnOnce(clientIp: String) {
    if (warned) {
      return
    }
    warned = true
    LOGGER.warning(
        "detection_max_scan_seconds ($capSeconds) reached for client $clientIp; remaining " +
            "patterns and request values are not scanned",
    )
  }

  private companion object {
    const val SLICE_NANOS: Long = 2_000_000L
    const val NO_PASS: Long = Long.MIN_VALUE
    val THREADS = ManagementFactory.getThreadMXBean()
    val LOGGER: Logger = Logger.getLogger("guard_core")
  }
}
