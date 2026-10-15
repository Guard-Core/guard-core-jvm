package com.guardcore.util

import java.util.logging.Logger

/**
 * W1 seam holder for the detection scan-budget context
 * (`guard_core/_utils/detection_scan.py:10-40`). The Python module keeps the budget in context vars
 * with these exact defaults; the redaction paths only consume `_json_depth_cap_value`
 * (detection_scan.py:116) until the W2 engine wires live scans through `withScanBudget`.
 *
 * The redaction call chain is synchronous on the JVM, so a ThreadLocal faithfully carries what
 * Python carries in context vars.
 */
public object DetectionScanContext {
  public const val DEFAULT_MAX_SCAN_VALUES: Int = 512
  public const val DEFAULT_MAX_SCAN_CHARS: Int = 65536
  public const val DEFAULT_MAX_SCAN_SECONDS: Double = 10.0
  public const val DEFAULT_MAX_JSON_DEPTH: Int = 32
  public const val DEFAULT_BINARY_MIN_RUN_LENGTH: Int = 16

  private val jsonDepthCap: ThreadLocal<Int> =
      object : ThreadLocal<Int>() {
        override fun initialValue(): Int = DEFAULT_MAX_JSON_DEPTH
      }

  /** Port of `_json_depth_cap_value` (detection_scan.py:116). */
  public fun jsonDepthCapValue(): Int = jsonDepthCap.get()

  /** Budget setter used by the G-7a scan-budget scope (DetectionScanBudget.withScanBudget). */
  internal fun setJsonDepthCap(value: Int) {
    jsonDepthCap.set(value)
  }

  /**
   * Port of the `_scan_value_budget` context manager (detection_scan.py:46), restricted to the
   * fields the W1 modules consume. The full value/char accounting lands with the W2 detection
   * engine.
   */
  public fun <T> withScanBudget(
      @Suppress("UNUSED_PARAMETER") maxValues: Int,
      maxJsonDepth: Int,
      @Suppress("UNUSED_PARAMETER") maxScanChars: Int,
      @Suppress("UNUSED_PARAMETER") binaryMinRunLength: Int,
      block: () -> T,
  ): T {
    val previous = jsonDepthCap.get()
    jsonDepthCap.set(maxJsonDepth)
    try {
      return block()
    } finally {
      jsonDepthCap.set(previous)
    }
  }

  /** Shared "guard_core" logger mirroring `logging.getLogger("guard_core")`. */
  internal val guardLogger: Logger = Logger.getLogger("guard_core")
}
