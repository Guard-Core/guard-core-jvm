package com.guardcore.engine.detection

/**
 * Reach-probe candidate builders: the construction strategies timed by the cost arbiter.
 *
 * Port of guard_core/detection_engine/_redos_probe_fill.py.
 */
private val REACH_PROBE_PREFIX_CUT_LENGTHS = intArrayOf(20, 30, 50)
private const val REACH_PROBE_MAX_RUN_VARIANTS = 12

private fun repeatUnitBuilder(ctx: StrayContext, unit: String): (Int) -> String {
  val stray = chooseRepeatUnitStray(ctx, unit)
  return { length -> repeatProbeToLength(unit, length, stray) }
}

private fun literalRunBuilders(pattern: String, ctx: StrayContext): List<(Int) -> String> =
    adversarialLiteralRuns(pattern).take(REACH_PROBE_MAX_RUN_VARIANTS).map { run ->
      repeatUnitBuilder(ctx, run)
    }

private fun reachProbePrefixBuilders(pattern: String, ctx: StrayContext): List<(Int) -> String> {
  val fullProbe = synthesizeReachingProbe(pattern)
  if (fullProbe == null || fullProbe.isEmpty()) return emptyList()
  val bodyOnly = fullProbe.dropLast(1).replace("?", "")
  val builders = ArrayList<(Int) -> String>()
  for (cut in REACH_PROBE_PREFIX_CUT_LENGTHS) {
    val prefix = bodyOnly.take(cut)
    if (prefix.length >= 2) builders.add(repeatUnitBuilder(ctx, prefix))
  }
  return builders
}

private fun classIntersectionBuilders(
    pattern: String,
    flags: Int,
    ctx: StrayContext?,
): List<(Int) -> String> {
  val prefix = leadingLiteralPrefix(pattern)
  return classIntersectionProbeUnits(pattern, flags, ctx).map { (fillChar, stray) ->
    { length: Int -> fillToLength(prefix, fillChar, stray, length) }
  }
}

private fun ambiguousGroupFillUnit(inner: String): String? {
  val atoms = parseFlatQuantifiedAtomsWithText(inner) ?: return null
  val chars = atoms.map { representativeCharForAtom(it.text) }
  if (chars.any { it == null }) return null
  val unit = chars.filterNotNull().joinToString("")
  return unit.ifEmpty { null }
}

private fun ambiguousGroupFillBuilders(
    pattern: String,
    ctx: StrayContext,
): List<(Int) -> String> {
  val builders = ArrayList<(Int) -> String>()
  val groupBodies =
      try {
        iterQuantifiedGroupBodies(pattern)
      } catch (e: GroupNestingTooDeep) {
        return builders
      }
  for ((_, _, inner) in groupBodies) {
    if (!groupInnerIsAmbiguous(inner)) continue
    val unit = ambiguousGroupFillUnit(inner) ?: continue
    builders.add(repeatUnitBuilder(ctx, unit))
  }
  return builders
}

/**
 * _reach_probe_candidate_builders: every builder family the arbiter times. The deadline is honored
 * by the construction helpers that can loop (alphabet splitting, unit enumeration).
 */
public fun reachProbeCandidateBuilders(
    pattern: String,
    flags: Int,
    deadlineNanos: Long? = null,
): List<(Int) -> String> {
  val ctx = buildStrayContext(pattern, flags, deadlineNanos)
  val repeatFills = repeatAlphabetFills(pattern, flags, deadlineNanos)
  val classUnits = classIntersectionProbeUnits(pattern, flags, ctx, includeBounded = true)
  val groupPairs = repeatGroupUnits(pattern, flags, deadlineNanos)
  val groupStrays = patternComplementChars(pattern, flags)
  val prefixedBuilders =
      groupUnitBuilders(groupPairs, groupStrays) { unit -> chooseRepeatUnitStray(ctx, unit) }
  val classPrefixUnits =
      classUnits +
          classUnits.flatMap { (fill, _) -> groupStrays.map { stray -> Pair(fill, stray) } }
  val classPrefixes =
      if (classUnits.isNotEmpty()) {
        listOf("") + repeatReachingPrefixes(pattern, flags, deadlineNanos, requireReachable = true)
      } else {
        emptyList()
      }
  return (repeatFills.map { fill ->
    { length: Int -> fillToLength(ctx.prefix, fill, fill, length) }
  } +
      classIntersectionBuilders(pattern, flags, ctx) +
      prefixedUnitBuilders(classPrefixes, classPrefixUnits) +
      prefixedBuilders +
      literalRunBuilders(pattern, ctx) +
      reachProbePrefixBuilders(pattern, ctx) +
      classUnits.map { (fill, stray) ->
        { length: Int ->
          prefixedRepeatProbe(ctx.prefix, fill.toString(), stray, false, length)
        }
      } +
      ambiguousGroupFillBuilders(pattern, ctx))
}
