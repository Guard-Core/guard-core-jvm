package com.guardcore.engine.detection

import com.guardcore.engine.py.PyReParser
import com.guardcore.engine.py.ReNode
import com.guardcore.engine.py.ReParseError

/**
 * Repeat-group unit pairs: (prefix, unit) pairs at every large repeat site.
 *
 * Port of guard_core/detection_engine/_redos_repeat_units.py.
 */
private const val REPEAT_UNIT_PAIR_LIMIT = 4096
private const val REPEAT_UNIT_TEXT_BUDGET = 1000000

private fun repeatedBodyUnits(
    body: List<ReNode>,
    flags: Int,
    deadlineNanos: Long?,
): List<String> {
  val states =
      PrefixWalk(flags = flags, deadlineNanos = deadlineNanos, collect = false)
          .walk(body, listOf(RepeatPrefixState("")))
  return states.filter { it.text.length > 1 }.map { it.text }
}

/** _repeat_group_units. */
public fun repeatGroupUnits(
    pattern: String,
    flags: Int,
    deadlineNanos: Long? = null,
): List<Pair<String, String>> {
  val parsed =
      try {
        PyReParser.parse(pattern, flags)
      } catch (e: ReParseError) {
        return emptyList()
      }
  val pairs = LinkedHashSet<Pair<String, String>>()
  var pairTextSize = 0

  val collect: (List<ReNode>, Int, List<RepeatPrefixState>) -> Unit = { body, localFlags, states ->
    val units = repeatedBodyUnits(body, localFlags, deadlineNanos)
    for (state in states) {
      val prefix = state.text + state.pending
      for (unit in units) {
        val pair = Pair(prefix, unit)
        if (pairs.add(pair)) {
          pairTextSize += prefix.length + unit.length
        }
        if (pairs.size > REPEAT_UNIT_PAIR_LIMIT) {
          throw PatternValidationTimeout("Pattern validation repeat-unit budget exceeded")
        }
        if (pairTextSize > REPEAT_UNIT_TEXT_BUDGET) {
          throw PatternValidationTimeout(
              "Pattern validation repeat-unit text budget exceeded",
          )
        }
      }
    }
  }

  PrefixWalk(
          parsed.stateFlags,
          ArrayList(),
          deadlineNanos,
          false,
          repeatCollector = collect,
          canonicalOptionals = true,
          requireReachable = true,
      )
      .walk(parsed.data, listOf(RepeatPrefixState("")))
  return pairs.toList()
}
