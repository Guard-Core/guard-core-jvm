package com.guardcore.util

import java.util.logging.Level

/**
 * G-7a closure: the full scan-budget accounting of `guard_core/_utils/detection_scan.py:19-129`
 * (value count/cap, char count/cap, warned flags, binary min-run), extending the W1 seam that only
 * carried the JSON depth cap. The redaction and scan call chain is synchronous on the JVM, so a
 * ThreadLocal faithfully carries what Python carries in context vars.
 */
public object DetectionScanBudget {
  /** Python `_scanned_value_count` / `_scan_value_cap` (detection_scan.py:19-24). */
  private val scannedValueCount: ThreadLocal<Int> =
      object : ThreadLocal<Int>() {
        override fun initialValue(): Int = 0
      }

  private val scanValueCap: ThreadLocal<Int> =
      object : ThreadLocal<Int>() {
        override fun initialValue(): Int = DetectionScanContext.DEFAULT_MAX_SCAN_VALUES
      }

  /**
   * Python `_scanned_char_count` / `_scan_char_cap` / `_scan_char_cap_warned`
   * (detection_scan.py:25-33).
   */
  private val scannedCharCount: ThreadLocal<Int> =
      object : ThreadLocal<Int>() {
        override fun initialValue(): Int = 0
      }

  private val scanCharCap: ThreadLocal<Int> =
      object : ThreadLocal<Int>() {
        override fun initialValue(): Int = DetectionScanContext.DEFAULT_MAX_SCAN_CHARS
      }

  private val scanCharCapWarned: ThreadLocal<Boolean> =
      object : ThreadLocal<Boolean>() {
        override fun initialValue(): Boolean = false
      }

  /** Python `_json_depth_warned` (detection_scan.py:37-39). */
  private val jsonDepthWarned: ThreadLocal<Boolean> =
      object : ThreadLocal<Boolean>() {
        override fun initialValue(): Boolean = false
      }

  /** Python `_binary_min_run` (detection_scan.py:40-42). */
  private val binaryMinRun: ThreadLocal<Int> =
      object : ThreadLocal<Int>() {
        override fun initialValue(): Int = DetectionScanContext.DEFAULT_BINARY_MIN_RUN_LENGTH
      }

  /** Python `_semantic_excluded_headers` (detection_scan.py). */
  private val semanticExcludedHeaders: ThreadLocal<Set<String>> =
      object : ThreadLocal<Set<String>>() {
        override fun initialValue(): Set<String> = emptySet()
      }

  /**
   * Port of the `_scan_value_budget` context manager (detection_scan.py:46). Resets every budget
   * counter for the block and restores the previous values afterwards.
   */
  public suspend fun <T> withScanBudget(
      maxValues: Int,
      maxJsonDepth: Int = DetectionScanContext.DEFAULT_MAX_JSON_DEPTH,
      maxScanChars: Int = DetectionScanContext.DEFAULT_MAX_SCAN_CHARS,
      binaryMinRunLength: Int = DetectionScanContext.DEFAULT_BINARY_MIN_RUN_LENGTH,
      semanticExcludedHeaders: Set<String> = emptySet(),
      block: suspend () -> T,
  ): T {
    val prevCount = scannedValueCount.get()
    val prevValueCap = scanValueCap.get()
    val prevCharCount = scannedCharCount.get()
    val prevCharCap = scanCharCap.get()
    val prevCharWarned = scanCharCapWarned.get()
    val prevDepthCap = DetectionScanContext.jsonDepthCapValue()
    val prevDepthWarned = jsonDepthWarned.get()
    val prevBinaryRun = binaryMinRun.get()
    val prevSemanticExcluded = this.semanticExcludedHeaders.get()
    scannedValueCount.set(0)
    scanValueCap.set(maxValues)
    scannedCharCount.set(0)
    scanCharCap.set(maxScanChars)
    scanCharCapWarned.set(false)
    DetectionScanContext.setJsonDepthCap(maxJsonDepth)
    jsonDepthWarned.set(false)
    binaryMinRun.set(binaryMinRunLength)
    this.semanticExcludedHeaders.set(semanticExcludedHeaders)
    try {
      return block()
    } finally {
      scannedValueCount.set(prevCount)
      scanValueCap.set(prevValueCap)
      scannedCharCount.set(prevCharCount)
      scanCharCap.set(prevCharCap)
      scanCharCapWarned.set(prevCharWarned)
      DetectionScanContext.setJsonDepthCap(prevDepthCap)
      jsonDepthWarned.set(prevDepthWarned)
      binaryMinRun.set(prevBinaryRun)
      this.semanticExcludedHeaders.set(prevSemanticExcluded)
    }
  }

  /**
   * Python `_context_header_is_semantic_excluded`: the header context names an opted-out header.
   */
  public fun contextHeaderIsSemanticExcluded(context: String): Boolean {
    val excluded = semanticExcludedHeaders.get()
    if (excluded.isEmpty()) {
      return false
    }
    if (!context.startsWith("header:")) {
      return false
    }
    val name = context.removePrefix("header:").removeSuffix(":embedded_json")
    return name.trim().lowercase() in excluded
  }

  /** Python `_binary_island_min_run_length` (detection_scan.py:73). */
  public fun binaryIslandMinRunLength(): Int = binaryMinRun.get()

  /** Python `_scan_value_budget_exhausted` (detection_scan.py:77). */
  public fun scanValueBudgetExhausted(clientIp: String): Boolean {
    val count = scannedValueCount.get() + 1
    scannedValueCount.set(count)
    val cap = scanValueCap.get()
    if (count <= cap) {
      return false
    }
    if (count == cap + 1) {
      DetectionScanContext.guardLogger.warning(
          "detection_max_scan_values ($cap) reached for client $clientIp; remaining " +
              "request values are not scanned",
      )
    }
    return true
  }

  /** Python `_scan_char_budget_exhausted` (detection_scan.py:93). */
  public fun scanCharBudgetExhausted(clientIp: String, valueLength: Int): Boolean {
    val consumedBefore = scannedCharCount.get()
    val cap = scanCharCap.get()
    if (consumedBefore >= cap) {
      if (!scanCharCapWarned.get()) {
        scanCharCapWarned.set(true)
        DetectionScanContext.guardLogger.warning(
            "detection_max_scan_chars ($cap) reached for client $clientIp; remaining " +
                "request values are not scanned",
        )
      }
      return true
    }
    scannedCharCount.set(consumedBefore + valueLength)
    return false
  }

  /** Python `_scan_budget_exhausted` (detection_scan.py:110). */
  public fun scanBudgetExhausted(clientIp: String, value: String): Boolean {
    if (scanValueBudgetExhausted(clientIp)) {
      return true
    }
    return scanCharBudgetExhausted(clientIp, value.length)
  }

  /** Python `_json_depth_cap_value` (detection_scan.py:116) re-exported for the scan modules. */
  public fun jsonDepthCapValue(): Int = DetectionScanContext.jsonDepthCapValue()

  /** Python `_warn_json_depth_cap_reached_once` (detection_scan.py:120). */
  public fun warnJsonDepthCapReachedOnce(clientIp: String) {
    if (jsonDepthWarned.get()) {
      return
    }
    jsonDepthWarned.set(true)
    DetectionScanContext.guardLogger.warning(
        "detection_max_json_depth (${jsonDepthCapValue()}) reached for client $clientIp; " +
            "nested content below that depth is scanned as text",
    )
  }

  /** Python `_log_at_level` (logging_utils.py:162) shape used by the scan modules. */
  public fun logAtLevel(level: String?, msg: String) {
    when (level) {
      "DEBUG" -> DetectionScanContext.guardLogger.fine(msg)
      "INFO" -> DetectionScanContext.guardLogger.info(msg)
      "WARNING" -> DetectionScanContext.guardLogger.warning(msg)
      "ERROR",
      "CRITICAL" -> DetectionScanContext.guardLogger.severe(msg)
      null -> {}
      else -> DetectionScanContext.guardLogger.log(Level.WARNING, msg)
    }
  }
}
