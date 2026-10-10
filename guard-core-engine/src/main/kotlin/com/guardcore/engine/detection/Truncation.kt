package com.guardcore.engine.detection

import com.guardcore.engine.py.PyUnicode

/**
 * Attack-region extraction and safe truncation for oversized content.
 *
 * Port of guard_core/detection_engine/truncation.py. The reference bounds each indicator scan with
 * a thread-pool future timeout; the JVM port bounds the same scans with the hard deadline, which
 * fails closed the same way (skip the indicator on timeout).
 */
private const val FULL_SCAN_TAIL_BYTES = 4096
private const val INDICATOR_SCAN_TIMEOUT_SECONDS = 0.5

public fun extractAttackRegions(
    preprocessor: ContentPreprocessor,
    content: String,
): List<IntRange> {
  val maxRegions = minOf(100, preprocessor.maxContentLength / 100)
  val regions = ArrayList<IntRange>()

  for (indicator in preprocessor.compiledIndicators) {
    val found = ArrayList<IntRange>()
    try {
      val deadlineNanos = System.nanoTime() + (INDICATOR_SCAN_TIMEOUT_SECONDS * 1e9).toLong()
      for (match in indicator.finditer(content, deadlineNanos)) {
        if (found.size >= maxRegions) break
        val start = maxOf(0, match.start() - 100)
        val end = minOf(PyUnicode.cpLength(content), match.end() + 100)
        found.add(IntRange(start, end))
      }
    } catch (e: PyReDeadlines) {
      continue
    }
    regions.addAll(found)
    if (regions.size >= maxRegions) break
  }

  if (regions.isNotEmpty()) {
    val sorted = regions.sortedBy { it.first }
    val merged = ArrayList<IntRange>()
    merged.add(sorted[0])
    for (region in sorted.drop(1)) {
      val last = merged[merged.size - 1]
      if (region.first <= last.last) {
        merged[merged.size - 1] = IntRange(last.first, maxOf(last.last, region.last))
      } else {
        merged.add(region)
      }
    }
    return merged.take(maxRegions)
  }

  return emptyList()
}

/** The deadline abort surfaces as PyRe.DeadlineExceededException; alias for readability. */
private typealias PyReDeadlines = com.guardcore.engine.py.PyRe.DeadlineExceededException

public fun extractAndConcatenateAttackRegions(
    content: String,
    attackRegions: List<IntRange>,
    budget: Int,
): String {
  val result = StringBuilder()
  var remaining = budget

  for (region in attackRegions) {
    val chunkLen = minOf(region.last - region.first + 1, remaining)
    if (chunkLen <= 0) break
    result.append(PyUnicode.cpSlice(content, region.first, region.first + chunkLen))
    remaining -= chunkLen
    if (remaining <= 0) break
  }

  return result.toString()
}

private fun consumeGap(
    content: String,
    lastEnd: Int,
    start: Int,
    gapBudget: Int,
): Pair<String, Int> {
  val gapLen = start - lastEnd
  if (gapLen <= gapBudget) {
    return Pair(PyUnicode.cpSlice(content, lastEnd, start), gapBudget - gapLen)
  }
  val chunkLen = gapBudget - 1
  val piece = if (chunkLen > 0) PyUnicode.cpSlice(content, lastEnd, lastEnd + chunkLen) else ""
  return Pair("$piece ", 0)
}

public fun buildResultWithAttackRegionsAndContext(
    content: String,
    attackRegions: List<IntRange>,
    budget: Int,
): String {
  val attackLength = attackRegions.sumOf { it.last - it.first + 1 }
  var gapBudget = budget - attackLength
  val resultParts = ArrayList<String>()
  var lastEnd = 0

  for (region in attackRegions) {
    if (lastEnd < region.first && gapBudget > 0) {
      val (piece, newBudget) = consumeGap(content, lastEnd, region.first, gapBudget)
      gapBudget = newBudget
      resultParts.add(piece)
    }
    resultParts.add(PyUnicode.cpSlice(content, region.first, region.last + 1))
    lastEnd = region.last + 1
  }

  val totalLen = PyUnicode.cpLength(content)
  if (lastEnd < totalLen && gapBudget > 0) {
    val tailLen = minOf(totalLen - lastEnd, gapBudget)
    resultParts.add(PyUnicode.cpSlice(content, lastEnd, lastEnd + tailLen))
  }

  return resultParts.joinToString("")
}

public fun capWithTail(content: String, maxFullScanBytes: Int): String {
  val cap = maxFullScanBytes
  val tail = minOf(FULL_SCAN_TAIL_BYTES, cap)
  val totalLen = PyUnicode.cpLength(content)
  val headLen = cap - tail
  return PyUnicode.cpSlice(content, 0, headLen) +
      PyUnicode.cpSlice(content, totalLen - tail, totalLen)
}

public fun truncateSafely(preprocessor: ContentPreprocessor, content: String): String {
  val maxFullScanBytes = preprocessor.maxFullScanBytes
  val totalLen = PyUnicode.cpLength(content)

  if (totalLen <= maxFullScanBytes) return content

  if (!preprocessor.preserveAttackPatterns) {
    return PyUnicode.cpSlice(content, 0, maxFullScanBytes)
  }

  val attackRegions = preprocessor.extractAttackRegions(content)

  if (attackRegions.isEmpty()) {
    return capWithTail(content, maxFullScanBytes)
  }

  val attackLength = attackRegions.sumOf { it.last - it.first + 1 }

  if (attackLength >= maxFullScanBytes) {
    return extractAndConcatenateAttackRegions(
        content,
        attackRegions,
        budget = maxFullScanBytes,
    )
  }

  return buildResultWithAttackRegionsAndContext(
      content,
      attackRegions,
      budget = maxFullScanBytes,
  )
}
