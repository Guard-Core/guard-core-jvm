package com.guardcore.engine.detection

/**
 * Exact first-char state for group crossing and exact-overlap fills.
 *
 * Port of guard_core/detection_engine/_redos_exact_state.py.
 */
public const val MAX_GROUP_CROSSING_DEPTH: Int = 16

/** _narrow_exact_state_raw. */
public fun narrowExactStateRaw(state: IntervalSet?, right: IntervalSet?): IntervalSet? {
  if (state == null || right == null) return null
  return state.intersection(right)
}

/** _exact_overlap_fill_raw: a char both the state and right can start with. */
public fun exactOverlapFillRaw(state: IntervalSet?, right: IntervalSet?): Char? {
  if (state == null || right == null) return null
  val member = state.intersection(right).firstMember() ?: return null
  return Character.toChars(member)[0]
}

private fun isolatedAlternativeExactState(altSlots: List<Slot>, depth: Int): IntervalSet? {
  var state: IntervalSet? = IntervalSet.full()
  for (slot in altSlots) {
    val atom = slot as? PairingAtom
    if (atom != null) {
      if (atom.allowsZero) continue
      state = narrowExactStateRaw(state, atom.intervals)
    } else {
      val nonPairing = slot as NonPairingSlot
      if (nonPairing.isBoundary) {
        if (nonPairing.inner == null) return null
        val groupState = isolatedGroupExactState(nonPairing.inner, depth + 1)
        state = narrowExactStateRaw(state, groupState)
      }
    }
    if (state == null) return null
  }
  return state
}

/** _isolated_group_exact_state: the union of alternative exact states, or null. */
public fun isolatedGroupExactState(alternatives: List<List<Slot>>, depth: Int): IntervalSet? {
  if (depth > MAX_GROUP_CROSSING_DEPTH) return null
  var combined: IntervalSet? = null
  for (alt in alternatives) {
    val altState = isolatedAlternativeExactState(alt, depth) ?: continue
    combined = combined?.union(altState) ?: altState
  }
  return combined
}
