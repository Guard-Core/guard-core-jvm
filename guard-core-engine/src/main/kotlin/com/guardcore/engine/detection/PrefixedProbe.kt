package com.guardcore.engine.detection

/**
 * Prefixed repeat probes: unit floods behind a mandatory prefix.
 *
 * Port of guard_core/detection_engine/_redos_prefixed_probe.py.
 */
public fun prefixedRepeatProbe(
    prefix: String,
    unit: String,
    stray: Char,
    flood: Boolean,
    length: Int,
): String {
  if (length <= prefix.length) return prefix.substring(0, length)
  val remaining = length - prefix.length
  val tailLength = if (flood) maxOf(1, remaining / 2) else 1
  val bodyLength = remaining - tailLength
  val body = unit.repeat(bodyLength / unit.length + 1).substring(0, bodyLength)
  return prefix + body + stray.toString().repeat(tailLength)
}

private const val PREFIXED_CANDIDATE_BUDGET = 4096

/**
 * _prefixed_unit_builders: builders for every (prefix, unit, stray, flood) combination. [units] are
 * (unit, stray) pairs; the budget raises like the reference's TimeoutError.
 */
public fun prefixedUnitBuilders(
    prefixes: List<String>,
    units: List<Pair<Char, Char>>,
): List<(Int) -> String> {
  if (prefixes.isEmpty()) return emptyList()
  val uniqueUnits = LinkedHashSet<Pair<Char, Char>>()
  for (unit in units) {
    uniqueUnits.add(unit)
    if (prefixes.size * uniqueUnits.size * 2 > PREFIXED_CANDIDATE_BUDGET) {
      throw PatternValidationTimeout(
          "Pattern validation prefixed-probe candidate budget exceeded",
      )
    }
  }
  val out = ArrayList<(Int) -> String>()
  for (prefix in prefixes) {
    for ((unit, stray) in uniqueUnits) {
      out.add { length -> prefixedRepeatProbe(prefix, unit.toString(), stray, false, length) }
      out.add { length -> prefixedRepeatProbe(prefix, unit.toString(), stray, true, length) }
    }
  }
  return out
}

private const val GROUP_PREFIX_CANDIDATE_LIMIT = 8192

/** _group_probe_candidates: (prefix, unit, stray) candidates for group unit pairs. */
private fun groupProbeCandidates(
    groupPairs: List<Pair<String, String>>,
    strays: List<Char>,
    chooseStray: (String) -> Char,
): LinkedHashSet<Triple<String, String, Char>> {
  val unitStrays = HashMap<String, Char>()
  val candidates = LinkedHashSet<Triple<String, String, Char>>()
  for ((prefix, unit) in groupPairs) {
    if (unit !in unitStrays) {
      unitStrays[unit] = chooseStray(unit)
    }
    for (stray in listOf(unitStrays[unit]!!) + strays) {
      candidates.add(Triple(prefix, unit, stray))
      candidates.add(Triple("", unit, stray))
      if (candidates.size > GROUP_PREFIX_CANDIDATE_LIMIT) {
        throw PatternValidationTimeout(
            "Pattern validation group-probe candidate budget exceeded",
        )
      }
    }
  }
  return candidates
}

/** _group_unit_builders: builders for every group candidate, flood variants doubled. */
public fun groupUnitBuilders(
    groupPairs: List<Pair<String, String>>,
    strays: List<Char>,
    chooseStray: (String) -> Char,
): List<(Int) -> String> {
  val out = ArrayList<(Int) -> String>()
  for ((prefix, unit, stray) in groupProbeCandidates(groupPairs, strays, chooseStray)) {
    out.add { length -> prefixedRepeatProbe(prefix, unit, stray, false, length) }
    out.add { length -> prefixedRepeatProbe(prefix, unit, stray, true, length) }
  }
  return out
}
