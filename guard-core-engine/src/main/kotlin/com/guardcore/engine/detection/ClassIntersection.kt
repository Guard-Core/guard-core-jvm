package com.guardcore.engine.detection

/**
 * Class-intersection probe units: (fill char, stray) pairs where a left unbounded class can feed a
 * right class through a shared char.
 *
 * Port of guard_core/detection_engine/_redos_class_intersection.py.
 */
private fun crossingSlotNarrows(slot: Slot, shared: IntervalSet, depth: Int): IntervalSet? {
  when (slot) {
    is PairingAtom -> {
      if (slot.allowsZero) return shared
      val overlap = shared.intersection(slot.intervals)
      return if (overlap.isEmpty) null else overlap
    }
    is NonPairingSlot -> {
      if (!slot.isBoundary) return shared
      if (slot.inner == null) return null
      return if (groupCrossingResult(slot.inner, shared, depth + 1) != null) shared else null
    }
  }
}

private fun alternativeCrossing(
    altSlots: List<Slot>,
    shared: IntervalSet,
    depth: Int,
): IntervalSet? {
  var local = shared
  for (slot in altSlots) {
    val narrowed = crossingSlotNarrows(slot, local, depth) ?: return null
    local = narrowed
  }
  return local
}

private fun groupCrossingResult(
    alternatives: List<List<Slot>>,
    shared: IntervalSet,
    depth: Int,
): IntervalSet? {
  if (depth > MAX_GROUP_CROSSING_DEPTH) return null
  var combined: IntervalSet? = null
  for (alt in alternatives) {
    val result = alternativeCrossing(alt, shared, depth) ?: continue
    combined = combined?.union(result) ?: result
  }
  return combined
}

private class Crossing(
    val shared: IntervalSet,
    val fill: Char?,
    val groupState: IntervalSet?,
)

private fun crossNonPairingSlot(
    slot: NonPairingSlot,
    shared: IntervalSet,
    exactState: IntervalSet?,
): Crossing? {
  if (slot.inner == null) {
    if (slot.isBoundary) return null
    return Crossing(shared, null, null)
  }
  val crossing = groupCrossingResult(slot.inner, shared, 0)
  val groupState = isolatedGroupExactState(slot.inner, 0)
  if (crossing == null) {
    val fill = if (slot.unbounded) exactOverlapFillRaw(exactState, groupState) else null
    if (slot.isBoundary) {
      if (fill == null) return null
      return Crossing(IntervalSet.empty(), fill, groupState)
    }
    return Crossing(shared, fill, groupState)
  }
  val member = crossing.firstMember()
  val fill = if (slot.unbounded && member != null) Character.toChars(member)[0] else null
  val resultShared = if (slot.isBoundary) crossing else shared
  return Crossing(resultShared, fill, groupState)
}

private fun tailPairingIntervals(slots: List<Slot>, start: Int): List<IntervalSet> =
    slots.drop(start).mapNotNull { (it as? PairingAtom)?.intervals }

private fun fillConfirmed(left: PairingAtom, right: PairingAtom, fill: Char): Boolean {
  val leftPredicate = left.predicate
  val rightPredicate = right.predicate
  if (leftPredicate == null || rightPredicate == null) return true
  return leftPredicate(fill.code) && rightPredicate(fill.code)
}

private fun leftConfirmsFill(left: PairingAtom, fill: Char): Boolean {
  val predicate = left.predicate ?: return true
  return predicate(fill.code)
}

private class UnitCollector {
  val units = ArrayList<Pair<Char, Char>>()

  fun appendPairingUnit(
      left: PairingAtom,
      right: PairingAtom,
      fill: Char,
      tail: List<IntervalSet>,
      ctx: StrayContext,
  ) {
    if (fillConfirmed(left, right, fill)) {
      val stray = chooseClassIntersectionStray(ctx, fill, left.intervals, right.intervals, tail)
      units.add(Pair(fill, stray))
    }
  }
}

private fun advancePairingChain(
    units: UnitCollector,
    left: PairingAtom,
    sharedIn: IntervalSet,
    slot: PairingAtom,
    exactStateIn: IntervalSet?,
    tail: List<IntervalSet>,
    ctx: StrayContext,
): Triple<IntervalSet, IntervalSet?, Boolean> {
  var shared = sharedIn
  var exactState = exactStateIn
  val overlap = shared.intersection(slot.intervals)
  if (!overlap.isEmpty) {
    if (slot.unbounded) {
      val member = overlap.firstMember() ?: error("overlap not empty")
      units.appendPairingUnit(left, slot, Character.toChars(member)[0], tail, ctx)
    }
    if (!slot.allowsZero) {
      shared = overlap
      exactState = narrowExactStateRaw(exactState, slot.intervals)
    }
    return Triple(shared, exactState, false)
  }
  val exactFill = exactOverlapFillRaw(exactState, slot.intervals)
  if (exactFill == null) {
    return Triple(shared, exactState, !slot.allowsZero)
  }
  if (slot.unbounded) {
    units.appendPairingUnit(left, slot, exactFill, tail, ctx)
  }
  if (!slot.allowsZero) {
    shared = overlap
    exactState = null
  }
  return Triple(shared, exactState, false)
}

private fun pairingUnitsFrom(
    slots: List<Slot>,
    start: Int,
    ctx: StrayContext,
): List<Pair<Char, Char>> {
  val left = slots[start] as? PairingAtom ?: return emptyList()
  var shared = left.intervals
  var exactState: IntervalSet? = left.intervals
  val units = UnitCollector()
  for (index in start + 1 until slots.size) {
    val slot = slots[index]
    val tail = tailPairingIntervals(slots, index + 1)
    if (slot is NonPairingSlot) {
      val crossed = crossNonPairingSlot(slot, shared, exactState) ?: break
      shared = crossed.shared
      if (slot.isBoundary) {
        exactState = narrowExactStateRaw(exactState, crossed.groupState)
      }
      val fill = crossed.fill
      if (fill != null && leftConfirmsFill(left, fill)) {
        val stray = chooseClassIntersectionStray(ctx, fill, left.intervals, shared, tail)
        units.units.add(Pair(fill, stray))
      }
      continue
    }
    val pairing = slot as PairingAtom
    val (newShared, newExact, shouldStop) =
        advancePairingChain(units, left, shared, pairing, exactState, tail, ctx)
    shared = newShared
    exactState = newExact
    if (shouldStop) break
  }
  return units.units
}

private fun flattenAlternatives(alternatives: List<List<Slot>>): List<Slot> {
  if (alternatives.size == 1) return alternatives[0]
  val flat = ArrayList<Slot>()
  for ((index, alt) in alternatives.withIndex()) {
    if (index > 0) flat.add(NonPairingSlot(true, null))
    flat.addAll(alt)
  }
  return flat
}

private fun unitsInSlots(slots: List<Slot>, ctx: StrayContext): List<Pair<Char, Char>> {
  val units = ArrayList<Pair<Char, Char>>()
  for ((index, slot) in slots.withIndex()) {
    if (slot is NonPairingSlot) {
      if (slot.inner != null) {
        units.addAll(unitsInSlots(flattenAlternatives(slot.inner), ctx))
      }
      continue
    }
    if (slot.unbounded) {
      units.addAll(pairingUnitsFrom(slots, index, ctx))
    }
  }
  return units
}

private fun includeBoundedRepeats(slots: List<Slot>): List<Slot> {
  val result = ArrayList<Slot>()
  for (slot in slots) {
    var replaced = slot
    val repeating = slot.unbounded || (slot.maxRepeat.let { it != null && it > 1 })
    if (slot is NonPairingSlot && slot.inner != null) {
      replaced = slot.copy(inner = slot.inner.map { includeBoundedRepeats(it) })
    }
    when (replaced) {
      is PairingAtom -> result.add(replaced.copy(unbounded = repeating))
      is NonPairingSlot -> result.add(replaced.copy(unbounded = repeating))
    }
  }
  return result
}

/**
 * _class_intersection_probe_units: (fill, stray) pairs; include_bounded widens unboundedness to
 * large bounded repeats the way the reference does.
 */
public fun classIntersectionProbeUnits(
    pattern: String,
    flags: Int,
    ctx: StrayContext? = null,
    includeBounded: Boolean = false,
): List<Pair<Char, Char>> {
  var slots = patternSlots(pattern, flags) ?: return emptyList()
  val context = ctx ?: buildStrayContext(pattern, flags)
  if (includeBounded) slots = includeBoundedRepeats(slots)
  return unitsInSlots(slots, context)
}

/** _class_intersection_fills. */
public fun classIntersectionFills(pattern: String, flags: Int): List<Char> =
    classIntersectionProbeUnits(pattern, flags).map { it.first }
