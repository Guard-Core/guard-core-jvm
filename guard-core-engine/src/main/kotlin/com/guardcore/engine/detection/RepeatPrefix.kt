package com.guardcore.engine.detection

import com.guardcore.engine.py.AssertAv
import com.guardcore.engine.py.BranchAv
import com.guardcore.engine.py.ReNode
import com.guardcore.engine.py.ReOp
import com.guardcore.engine.py.ReParseError
import com.guardcore.engine.py.RepeatAv
import com.guardcore.engine.py.SubPatternAv

/**
 * The prefix walk: what literal prefix must precede a pattern position, walking the parse tree with
 * state-set semantics (branches union, repeats expand, assertions constrain).
 *
 * Port of guard_core/detection_engine/_redos_repeat_prefix.py.
 */
private val repeatPrefixRepeatOps = setOf(ReOp.MAX_REPEAT, ReOp.MIN_REPEAT)
private val repeatPrefixAtomOps =
    setOf(ReOp.LITERAL, ReOp.NOT_LITERAL, ReOp.IN, ReOp.ANY, ReOp.CATEGORY)

private fun checkDeadline(deadlineNanos: Long?) {
  if (deadlineNanos != null && System.nanoTime() >= deadlineNanos) {
    throw PatternValidationTimeout(
        "Pattern validation repeat-prefix construction exceeded its deadline",
    )
  }
}

private fun uniqueStates(states: List<RepeatPrefixState>): List<RepeatPrefixState> {
  val unique = states.distinct()
  if (unique.size > PREFIX_WALK_STATE_LIMIT) {
    throw PatternValidationTimeout("Pattern validation repeat-prefix state budget exceeded")
  }
  if (unique.sumOf { stateTextSize(it) } > PREFIX_WALK_TEXT_BUDGET) {
    throw PatternValidationTimeout("Pattern validation repeat-prefix text budget exceeded")
  }
  return unique
}

private fun assertionWitnesses(
    body: List<ReNode>,
    flags: Int,
    deadlineNanos: Long?,
): List<RepeatPrefixState> {
  val states =
      PrefixWalk(
              flags = flags,
              deadlineNanos = deadlineNanos,
              collect = false,
          )
          .walk(body, listOf(RepeatPrefixState("")))
  if (
      states.any {
        it.pending.isNotEmpty() || it.forbidden.isNotEmpty() || !it.excluded.isEmpty
      }
  ) {
    throw PatternValidationTimeout(
        "Pattern validation cannot resolve nested assertion constraints",
    )
  }
  return states
}

/**
 * The walk. Mirrors python's _PrefixWalk: collect gathers reaching prefixes at repeat sites;
 * repeatCollector observes (body, flags, states) at every repeat with high > 1; canonicalOptionals
 * collapses optional expansions that provably change nothing; requireReachable fails closed when a
 * repeat site could not be reached with a prefix.
 */
public class PrefixWalk(
    private val flags: Int,
    private val prefixes: MutableList<String> = ArrayList(),
    private val deadlineNanos: Long? = null,
    private val collect: Boolean,
    private val alphabet: List<Char> = emptyList(),
    private val repeatCollector: ((List<ReNode>, Int, List<RepeatPrefixState>) -> Unit)? = null,
    private val canonicalOptionals: Boolean = false,
    private val requireReachable: Boolean = false,
) {
  fun walk(
      items: List<ReNode>,
      statesIn: List<RepeatPrefixState>,
      historyObservable: Boolean = false,
  ): List<RepeatPrefixState> {
    var states = statesIn
    val history = suffixHistory(items, historyObservable)
    for ((index, node) in items.withIndex()) {
      checkDeadline(deadlineNanos)
      states = uniqueStates(nodeWalk(node, states, history[index]))
      if (states.isEmpty()) {
        checkRemainingRepeats(items.subList(index + 1, items.size))
        break
      }
    }
    return states
  }

  private fun checkRemainingRepeats(items: List<ReNode>) {
    if (requireReachable && containsRepeat(items)) {
      throw PatternValidationTimeout("Pattern validation cannot resolve repeat-site prefixes")
    }
  }

  private fun atoms(node: ReNode, states: List<RepeatPrefixState>): List<RepeatPrefixState> {
    val intervals = nodeIntervals(node, flags)
    return states.mapNotNull { consumeAtom(it, intervals) }
  }

  private fun recordPrefixes(high: Int, states: List<RepeatPrefixState>) {
    if (collect && high > 1) {
      for (state in states) {
        prefixes.add(state.text + state.pending)
      }
      if (prefixes.size > REPEAT_PREFIX_STATE_LIMIT * 4) {
        throw PatternValidationTimeout(
            "Pattern validation repeat-prefix candidate budget exceeded",
        )
      }
    }
  }

  private fun repeat(
      av: RepeatAv,
      states: List<RepeatPrefixState>,
      historyObservable: Boolean,
  ): List<RepeatPrefixState> {
    val low = av.low
    val high = av.high
    val body = av.body
    recordPrefixes(high, states)
    if (high > 1 && repeatCollector != null) {
      repeatCollector(body, flags, states)
    }
    if (low == 0 && high > 0) {
      val expanded = walk(body, states, historyObservable)
      if (canonicalOptionals && optionalStatesAreEquivalent(body, states, historyObservable)) {
        return states
      }
      return pendingRepeats(
          body,
          uniqueStates(states + expanded),
          expanded,
          high - 1,
          historyObservable,
      )
    }
    var current = states
    for (i in 0 until low) {
      checkDeadline(deadlineNanos)
      val previous = current
      current = walk(body, current, historyObservable)
      if (current == previous || current.isEmpty()) break
    }
    return pendingRepeats(body, current, current, high - low, historyObservable)
  }

  private fun pendingRepeats(
      body: List<ReNode>,
      resultIn: List<RepeatPrefixState>,
      frontierIn: List<RepeatPrefixState>,
      remainingIn: Int,
      historyObservable: Boolean,
  ): List<RepeatPrefixState> {
    var result = resultIn
    var frontier = frontierIn
    var remaining = remainingIn
    while (remaining > 0) {
      val pending = frontier.filter { it.pending.isNotEmpty() }
      if (pending.isEmpty()) break
      checkDeadline(deadlineNanos)
      frontier = walk(body, pending, historyObservable)
      result = uniqueStates(result + frontier)
      if (frontier == pending) break
      remaining--
    }
    return result
  }

  private fun branch(
      av: BranchAv,
      states: List<RepeatPrefixState>,
      historyObservable: Boolean,
  ): List<RepeatPrefixState> {
    var result: List<RepeatPrefixState> = emptyList()
    for (alternative in av.alternatives) {
      result = uniqueStates(result + walk(alternative, states, historyObservable))
    }
    return result
  }

  private fun group(
      av: SubPatternAv,
      states: List<RepeatPrefixState>,
      historyObservable: Boolean,
  ): List<RepeatPrefixState> {
    val childFlags = (flags or av.addFlags) and av.delFlags.inv()
    val child =
        PrefixWalk(
            childFlags,
            prefixes,
            deadlineNanos,
            collect,
            alphabet,
            repeatCollector,
            canonicalOptionals,
            requireReachable,
        )
    val out = ArrayList<RepeatPrefixState>()
    for (state in states) {
      for (nextState in child.walk(av.body, listOf(state), historyObservable)) {
        out.add(captureState(nextState, av.group, state.text.length))
      }
    }
    return out
  }

  private fun assertion(
      node: ReNode,
      states: List<RepeatPrefixState>,
  ): List<RepeatPrefixState> {
    val av = node.av as AssertAv
    val witnesses = assertionWitnesses(av.body, flags, deadlineNanos)
    if (node.op == ReOp.ASSERT) {
      val out = ArrayList<RepeatPrefixState>()
      for (state in states) {
        for (nextState in positiveAssertion(av.direction, witnesses, state)) {
          out.add(nextState)
        }
      }
      return out
    }
    if (av.direction < 0) {
      return walkNegativeBehind(av.body, flags, witnesses, states, alphabet)
    }
    val out = ArrayList<RepeatPrefixState>()
    for (state in states) {
      for (nextState in negativeAssertion(av.body, flags, witnesses, state)) {
        out.add(nextState)
      }
    }
    return out
  }

  private fun backreference(group: Int, states: List<RepeatPrefixState>): List<RepeatPrefixState> {
    val result = ArrayList<RepeatPrefixState>()
    for (state in states) {
      val captured = state.captures.toMap()[group] ?: continue
      val nextState = consumePiece(state, captured) ?: continue
      result.add(nextState)
    }
    return result
  }

  private fun conditional(
      av: com.guardcore.engine.py.ConditionalAv,
      states: List<RepeatPrefixState>,
      historyObservable: Boolean,
  ): List<RepeatPrefixState> {
    val out = ArrayList<RepeatPrefixState>()
    for (state in states) {
      val branchBody = if (state.captures.toMap().containsKey(av.group)) av.yes else av.no
      for (nextState in walk(branchBody, listOf(state), historyObservable)) {
        out.add(nextState)
      }
    }
    return out
  }

  private fun nodeWalk(
      node: ReNode,
      states: List<RepeatPrefixState>,
      historyObservable: Boolean,
  ): List<RepeatPrefixState> {
    return when {
      node.op in repeatPrefixAtomOps -> atoms(node, states)
      node.op in repeatPrefixRepeatOps -> repeat(node.av as RepeatAv, states, historyObservable)
      node.op == ReOp.GROUPREF -> backreference(node.av as Int, states)
      node.op == ReOp.BRANCH -> branch(node.av as BranchAv, states, historyObservable)
      node.op == ReOp.SUBPATTERN -> group(node.av as SubPatternAv, states, historyObservable)
      node.op == ReOp.GROUPREF_EXISTS ->
          conditional(node.av as com.guardcore.engine.py.ConditionalAv, states, historyObservable)
      node.op == ReOp.ASSERT || node.op == ReOp.ASSERT_NOT -> assertion(node, states)
      node.op == ReOp.ATOMIC_GROUP -> walk(node.av as List<ReNode>, states, true)
      else ->
          when (node.op) {
            ReOp.AT -> states
            else -> emptyList()
          }
    }
  }
}

/** _repeat_reaching_prefixes: literal prefixes that reach every repeat site. */
public fun repeatReachingPrefixes(
    pattern: String,
    flags: Int,
    deadlineNanos: Long? = null,
    requireReachable: Boolean = false,
): List<String> {
  val parsed =
      try {
        com.guardcore.engine.py.PyReParser.parse(pattern, flags)
      } catch (e: ReParseError) {
        return emptyList()
      }
  val prefixes = ArrayList<String>()
  val alphabet = repeatAlphabetFills(pattern, flags, deadlineNanos, includePrefix = true)
  PrefixWalk(
          parsed.stateFlags,
          prefixes,
          deadlineNanos,
          true,
          alphabet,
          canonicalOptionals = true,
          requireReachable = requireReachable,
      )
      .walk(parsed.data, listOf(RepeatPrefixState("")))
  return prefixes.filter { it.isNotEmpty() }.distinct()
}
