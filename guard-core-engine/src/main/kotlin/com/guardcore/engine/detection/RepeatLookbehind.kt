package com.guardcore.engine.detection

import com.guardcore.engine.py.ReNode

/**
 * Negative-lookbehind handling in the prefix walk: mutate the prefix so the behind-assertion holds,
 * or enumerate alphabet variants when the body is not a single atom.
 *
 * Port of guard_core/detection_engine/_redos_repeat_lookbehind.py.
 */
private fun checkMutationBudget(state: RepeatPrefixState, count: Int = 0) {
  if (state.captures.isNotEmpty()) {
    throw PatternValidationTimeout(
        "Pattern validation cannot resolve capture-dependent lookbehind",
    )
  }
  if (count > REPEAT_PREFIX_STATE_LIMIT) {
    throw PatternValidationTimeout("Pattern validation lookbehind state budget exceeded")
  }
}

private fun forbiddenFinalAtom(body: List<ReNode>, flags: Int): IntervalSet? {
  if (body.size != 1 || body[0].op !in pairingOpsForHistory) return null
  val node = body[0]
  return nodeIntervals(node, flags)
}

private fun negativeLookbehind(
    forbidden: IntervalSet,
    state: RepeatPrefixState,
): List<RepeatPrefixState> {
  if (state.text.isEmpty() || !forbidden.contains(state.text[state.text.length - 1].code)) {
    return listOf(state)
  }
  checkMutationBudget(state)
  val lastAtom = state.lastAtom ?: IntervalSet.single(state.text[state.text.length - 1].code)
  val available = lastAtom.difference(forbidden)
  val member = available.firstMember() ?: return emptyList()
  val replacement = Character.toChars(member)[0]
  return listOf(
      RepeatPrefixState(
          text = state.text.dropLast(1) + replacement,
          pending = state.pending,
          excluded = state.excluded,
          forbidden = state.forbidden,
          captures = state.captures,
          lastAtom = available,
      ),
  )
}

private fun matchingWitnessWidth(text: String, witnesses: List<RepeatPrefixState>): Int =
    witnesses
        .filter { it.text.isNotEmpty() && text.endsWith(it.text) }
        .maxOfOrNull { it.text.length } ?: 0

private fun changedPrefixes(
    state: RepeatPrefixState,
    width: Int,
    alphabet: List<Char>,
): List<RepeatPrefixState> {
  val out = ArrayList<RepeatPrefixState>()
  val n = state.text.length
  if (width <= 0) return out
  for (i in n - 1 downTo n - width) {
    if (i < 0) break
    for (char in alphabet) {
      if (char == state.text[i]) continue
      out.add(
          RepeatPrefixState(
              text = state.text.substring(0, i) + char + state.text.substring(i + 1),
              pending = state.pending,
              excluded = state.excluded,
              forbidden = state.forbidden,
              captures = state.captures,
              lastAtom = state.lastAtom,
          ),
      )
    }
  }
  return out
}

private fun lookbehindAlternatives(
    state: RepeatPrefixState,
    witnesses: List<RepeatPrefixState>,
    alphabet: List<Char>,
): List<RepeatPrefixState> {
  val width = matchingWitnessWidth(state.text, witnesses)
  if (width == 0) return listOf(state)
  checkMutationBudget(state, width * alphabet.size)
  return changedPrefixes(state, width, alphabet)
}

/** _walk_negative_behind. */
public fun walkNegativeBehind(
    body: List<ReNode>,
    flags: Int,
    witnesses: List<RepeatPrefixState>,
    states: List<RepeatPrefixState>,
    alphabet: List<Char>,
): List<RepeatPrefixState> {
  val forbidden = forbiddenFinalAtom(body, flags)
  if (forbidden == null) {
    return states.flatMap { lookbehindAlternatives(it, witnesses, alphabet) }
  }
  return states.flatMap { negativeLookbehind(forbidden, it) }
}
