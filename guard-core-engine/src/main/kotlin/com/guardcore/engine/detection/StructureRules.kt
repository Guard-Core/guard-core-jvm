package com.guardcore.engine.detection

/**
 * Structural rules: nested unbounded quantifier and adjacent broad unbounded quantifiers.
 *
 * Port of guard_core/detection_engine/_redos_structure_rules.py.
 */
public const val NESTING_DEPTH_REJECTION_REASON: String =
    "pattern exceeds the maximum group nesting depth of $MAX_GROUP_NESTING_DEPTH " +
        "the ReDoS structural analyzer supports"

/** _nested_body_is_unbounded: a body whose alternation can match unboundedly. */
public fun nestedBodyIsUnbounded(inner: String): Boolean {
  val strippedInner = stripEscapesAndCharClasses(inner)
  if (strippedInner.split("|").any { branchIsUnboundedSingle(it) }) return true
  return overlappingLiteralBranches(inner)
}

/** _detect_nested_unbounded_quantifier: the offending span, or null. */
public fun detectNestedUnboundedQuantifier(pattern: String): String? {
  return try {
    for ((start, end, inner) in iterQuantifiedGroupBodies(pattern)) {
      if (nestedBodyIsUnbounded(inner)) return pattern.substring(start, end)
    }
    null
  } catch (e: GroupNestingTooDeep) {
    NESTING_DEPTH_REJECTION_REASON
  }
}

private val BROAD_SHORTHAND_ESCAPE_LETTERS = "SWD".toSet()
private val ALREADY_BROAD_SHORTHAND = Regex("\\\\[SWD]")

/** A broad char class: any non-negated class, or a negated one without an S/D/W shorthand. */
public fun isBroadCharClassInner(inner: String): Boolean {
  if (inner.startsWith("^")) {
    val excluded = inner.substring(1)
    return ALREADY_BROAD_SHORTHAND.find(excluded) == null
  }
  return inner == "\\s\\S" || inner == "\\S\\s"
}

/** (end index, is broad) for the atom starting at [i]. */
public fun broadAtomSpan(pattern: String, i: Int): Pair<Int, Boolean> {
  val c = pattern[i]
  val n = pattern.length
  return when {
    c == '\\' && i + 1 < n -> Pair(i + 2, pattern[i + 1] in BROAD_SHORTHAND_ESCAPE_LETTERS)
    c == '[' -> {
      val j = skipCharClass(pattern, i)
      Pair(j, isBroadCharClassInner(pattern.substring(i + 1, j - 1)))
    }
    c == '.' -> Pair(i + 1, true)
    else -> Pair(i + 1, false)
  }
}

/** (broad unbounded atom count, spans) at nesting [depth]. */
private fun broadUnboundedRunAt(pattern: String, depth: Int): Pair<Int, List<String>> {
  if (depth > MAX_GROUP_NESTING_DEPTH) throw GroupNestingTooDeep(MAX_GROUP_NESTING_DEPTH)
  var count = 0
  val spans = ArrayList<String>()
  var i = 0
  val n = pattern.length
  while (i < n) {
    if (pattern[i] == '(') {
      val j = findGroupEnd(pattern, i)
      if (j == null) {
        i++
        continue
      }
      val inner = normalizeGroupInner(pattern.substring(i + 1, j - 1))
      if (inner != null) {
        var bestCount = -1
        var bestSpans: List<String> = emptyList()
        for (branch in splitTopLevelAlternations(inner)) {
          val (branchCount, branchSpans) = broadUnboundedRunAt(branch, depth + 1)
          if (branchCount > bestCount) {
            bestCount = branchCount
            bestSpans = branchSpans
          }
        }
        if (bestCount > 0) {
          count += bestCount
          spans.addAll(bestSpans)
        }
      }
      i = j
      continue
    }
    val (atomEnd, isBroad) = broadAtomSpan(pattern, i)
    if (isBroad && outerQuantifierLen(pattern, atomEnd) > 0) {
      count++
      spans.add(pattern.substring(i, atomEnd))
    }
    i = atomEnd
  }
  return Pair(count, spans)
}

/** _detect_adjacent_broad_unbounded_quantifiers: description, or null. */
public fun detectAdjacentBroadUnboundedQuantifiers(pattern: String): String? {
  val (count, spans) =
      try {
        broadUnboundedRunAt(pattern, 0)
      } catch (e: GroupNestingTooDeep) {
        return NESTING_DEPTH_REJECTION_REASON
      }
  if (count >= 2) return spans.take(2).joinToString(" and ")
  return null
}
