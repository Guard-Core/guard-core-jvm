package com.guardcore.engine.detection

import com.guardcore.engine.py.AssertAv
import com.guardcore.engine.py.BranchAv
import com.guardcore.engine.py.ReNode
import com.guardcore.engine.py.ReOp
import com.guardcore.engine.py.RepeatAv
import com.guardcore.engine.py.SubPatternAv

/**
 * History-observability analysis over parsed node sequences (whether a site's match can depend on
 * what came before it: anchors, backrefs, captures).
 *
 * Port of guard_core/detection_engine/_redos_prefix_history.py.
 */
internal val pairingOpsForHistory =
    setOf(
        com.guardcore.engine.py.ReOp.LITERAL,
        com.guardcore.engine.py.ReOp.NOT_LITERAL,
        com.guardcore.engine.py.ReOp.IN,
        com.guardcore.engine.py.ReOp.ANY,
        com.guardcore.engine.py.ReOp.CATEGORY,
    )

private fun nodeObservesHistory(op: ReOp, av: Any?): Boolean {
  if (op in pairingOpsForHistory) return false
  when (op) {
    ReOp.AT -> {
      val anchor = av as com.guardcore.engine.py.AtAnchor
      return anchor == com.guardcore.engine.py.AtAnchor.BOUNDARY ||
          anchor == com.guardcore.engine.py.AtAnchor.NON_BOUNDARY
    }
    ReOp.MAX_REPEAT,
    ReOp.MIN_REPEAT -> return observesHistory((av as RepeatAv).body)
    ReOp.SUBPATTERN -> {
      val sp = av as SubPatternAv
      return sp.group != null || sp.addFlags != 0 || sp.delFlags != 0 || observesHistory(sp.body)
    }
    ReOp.BRANCH -> return (av as BranchAv).alternatives.any { observesHistory(it) }
    ReOp.ATOMIC_GROUP -> return true
    else -> return true
  }
}

private fun observesHistory(items: List<ReNode>): Boolean = items.any {
  nodeObservesHistory(it.op, it.av)
}

internal fun suffixHistory(items: List<ReNode>, enclosing: Boolean): List<Boolean> {
  var observed = enclosing
  val result = ArrayList<Boolean>(items.size)
  for (index in items.indices.reversed()) {
    result.add(observed)
    observed = observed || nodeObservesHistory(items[index].op, items[index].av)
  }
  result.reverse()
  return result
}

internal fun optionalStatesAreEquivalent(
    body: List<ReNode>,
    states: List<RepeatPrefixState>,
    historyObservable: Boolean,
): Boolean =
    !historyObservable &&
        !observesHistory(body) &&
        states.all { it.pending.isEmpty() && it.forbidden.isEmpty() && it.excluded.isEmpty }

internal fun containsRepeat(items: List<ReNode>): Boolean = items.any {
  nodeContainsRepeat(it.op, it.av)
}

private fun nodeContainsRepeat(op: ReOp, av: Any?): Boolean {
  if (op == ReOp.MAX_REPEAT || op == ReOp.MIN_REPEAT) {
    val repeat = av as RepeatAv
    return repeat.high > 1 || containsRepeat(repeat.body)
  }
  return nestedRepeatNodes(op, av).any { containsRepeat(it) }
}

private fun nestedRepeatNodes(op: ReOp, av: Any?): List<List<ReNode>> =
    when (op) {
      ReOp.SUBPATTERN -> listOf((av as SubPatternAv).body)
      ReOp.BRANCH -> (av as BranchAv).alternatives.toList()
      ReOp.ASSERT,
      ReOp.ASSERT_NOT -> listOf((av as AssertAv).body)
      ReOp.ATOMIC_GROUP -> listOf(av as List<ReNode>)
      else -> emptyList()
    }
