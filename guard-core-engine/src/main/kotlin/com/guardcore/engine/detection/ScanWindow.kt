package com.guardcore.engine.detection

import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyRePattern

/**
 * Bounded scan windows: run an unmodified pattern between a prefix occurrence and the farthest
 * reachable terminator occurrence (quadratic-rescan protection).
 *
 * Port of guard_core/detection_engine/scan_window.py. Span outcomes agree with the unbounded run;
 * only the span identity across multiple prefixes may differ, which no caller consumes.
 */

/** bounded_finditer: all matches within reachable windows (python generator -> list). */
public fun boundedFinditer(
    text: String,
    compiled: PyRePattern,
    prefix: PyRePattern,
    terminator: PyRePattern,
): List<PyReMatch> {
  val out = ArrayList<PyReMatch>()
  val terminatorEnds = terminator.finditer(text, Long.MAX_VALUE).map { it.charEnd() }
  if (terminatorEnds.isEmpty()) return out
  val ceiling = terminatorEnds.last()

  val prefixStarts = prefix.finditer(text, Long.MAX_VALUE).map { it.charStart() }
  if (prefixStarts.isEmpty()) return out

  var searchFrom = 0
  while (true) {
    var startIdx = prefixStarts.binarySearch(searchFrom)
    if (startIdx < 0) startIdx = -(startIdx + 1)
    val match = matchFromLivePrefixes(text, compiled, prefixStarts, startIdx, ceiling) ?: return out
    out.add(match)
    searchFrom = if (match.charEnd() > match.charStart()) match.charEnd() else match.charStart() + 1
  }
}

private fun matchFromLivePrefixes(
    text: String,
    compiled: PyRePattern,
    prefixStarts: List<Int>,
    startIdx: Int,
    ceiling: Int,
): PyReMatch? {
  for (i in startIdx until prefixStarts.size) {
    val start = prefixStarts[i]
    if (start >= ceiling) break
    val match = compiled.matchAt(text, start, ceiling, Long.MAX_VALUE)
    if (match != null) return match
  }
  return null
}

/** bounded_search: the first windowed match, or null. */
public fun boundedSearch(
    text: String,
    compiled: PyRePattern,
    prefix: PyRePattern,
    terminator: PyRePattern,
): PyReMatch? = boundedFinditer(text, compiled, prefix, terminator).firstOrNull()
