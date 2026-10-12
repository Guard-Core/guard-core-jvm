package com.guardcore.engine.detection

/**
 * Repeat alphabets: the distinct chars a repeatable region can consume, split by constraint classes
 * so probe fills exercise every class combination.
 *
 * Port of guard_core/detection_engine/_redos_repeat_alphabet.py.
 */
private const val LARGE_BOUNDED_REPEAT_LIMIT = 4096

private fun isLargeBoundedRepeat(slot: Slot): Boolean {
  val maxRepeat = slot.maxRepeat ?: return false
  return slot.variableBounded && maxRepeat >= LARGE_BOUNDED_REPEAT_LIMIT
}

private fun collectAlphabetAtoms(
    slots: List<Slot>,
    repeated: Boolean,
): List<Pair<IntervalSet, Boolean>> {
  val atoms = ArrayList<Pair<IntervalSet, Boolean>>()
  for (slot in slots) {
    val isRepeated = repeated || canRepeat(slot)
    when (slot) {
      is PairingAtom -> atoms.add(Pair(slot.intervals, isRepeated))
      is NonPairingSlot ->
          if (slot.inner != null) {
            for (alternative in slot.inner) {
              atoms.addAll(collectAlphabetAtoms(alternative, isRepeated))
            }
          }
    }
  }
  return atoms
}

private fun canRepeat(slot: Slot): Boolean =
    slot.unbounded || (slot.maxRepeat.let { it != null && it > 1 })

private fun splitAlphabet(
    regions: List<IntervalSet>,
    constraint: IntervalSet,
    deadlineNanos: Long?,
): List<IntervalSet> {
  val result = ArrayList<IntervalSet>()
  for (region in regions) {
    if (deadlineNanos != null && System.nanoTime() >= deadlineNanos) {
      throw PatternValidationTimeout("Pattern validation alphabet exceeded its deadline")
    }
    for (part in listOf(region.intersection(constraint), region.difference(constraint))) {
      if (!part.isEmpty) result.add(part)
    }
  }
  return result
}

private fun repeatedCharacters(atoms: List<Pair<IntervalSet, Boolean>>): IntervalSet {
  var repeated = IntervalSet.empty()
  for ((intervals, unbounded) in atoms) {
    if (unbounded) repeated = repeated.union(intervals)
  }
  return repeated
}

/** _repeat_alphabet_fills: one representative char per split region. */
public fun repeatAlphabetFills(
    pattern: String,
    flags: Int,
    deadlineNanos: Long? = null,
    includePrefix: Boolean = false,
): List<Char> {
  val slots = patternSlots(pattern, flags) ?: return emptyList()
  val atoms = collectAlphabetAtoms(slots, includePrefix)
  val repeated = repeatedCharacters(atoms)
  if (repeated.isEmpty) return emptyList()
  var regions = listOf(repeated)
  for (constraint in atoms.map { it.first }.distinct()) {
    regions = splitAlphabet(regions, constraint, deadlineNanos)
  }
  return regions.mapNotNull { region ->
    region.firstMember()?.let { Character.toChars(it)[0] }
  }
}

/** _has_large_bounded_repeat. */
public fun hasLargeBoundedRepeat(pattern: String, flags: Int): Boolean {
  val slots = patternSlots(pattern, flags) ?: return false
  return slotsHaveLargeBoundedRepeat(slots)
}

private fun slotsHaveLargeBoundedRepeat(slots: List<Slot>): Boolean {
  for (slot in slots) {
    if (isLargeBoundedRepeat(slot)) return true
    if (slot is NonPairingSlot && slot.inner != null) {
      if (slot.inner.any { slotsHaveLargeBoundedRepeat(it) }) return true
    }
  }
  return false
}
