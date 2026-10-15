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
 */
public class ScanTimeBudget(public val capSeconds: Double) {
  private var spentNanos: Long = 0L
  private var warned: Boolean = false

  public val spentSeconds: Double
    get() = spentNanos / 1e9

  /** Python `_scan_time_budget_exhausted`: no time left. */
  public fun exhausted(): Boolean = capSeconds - spentSeconds <= 0.0

  /** CPU time of the calling thread; pair two readings and [record] the difference. */
  public fun currentCpuNanos(): Long = THREADS.currentThreadCpuTime

  public fun record(cpuNanos: Long) {
    spentNanos += cpuNanos
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
    val THREADS = ManagementFactory.getThreadMXBean()
    val LOGGER: Logger = Logger.getLogger("guard_core")
  }
}
