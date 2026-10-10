package com.guardcore.engine.detection

/**
 * Unicode case-folding groups for ignorecase interval expansion.
 *
 * Port of guard_core/detection_engine/_redos_ignorecase_fold.py: a union-find over code points
 * where every char is grouped with its lower/upper/casefold variants, then expand_ignorecase widens
 * an interval set to whole fold groups (member scan for small sets, group scan for large ones;
 * ascii_only restricts to < 128).
 */
private val foldLock = Any()
private var foldGroupsCache: List<Set<Int>>? = null
private var foldGroupByCodePointCache: Map<Int, Set<Int>>? = null

private const val EXPAND_IGNORECASE_MEMBER_SCAN_CEILING = 4096

private class UnionFind {
  val parent: HashMap<Int, Int> = HashMap()

  fun find(codePoint: Int): Int {
    parent.putIfAbsent(codePoint, codePoint)
    var root = codePoint
    while (parent[root] != root) root = parent[root]!!
    // Path compression.
    var cur = codePoint
    while (parent[cur] != root) {
      val next = parent[cur]!!
      parent[cur] = root
      cur = next
    }
    return root
  }

  fun union(first: Int, second: Int) {
    val firstRoot = find(first)
    val secondRoot = find(second)
    if (firstRoot != secondRoot) parent[secondRoot] = firstRoot
  }
}

private fun registerFoldVariant(
    parent: UnionFind,
    multiCharFoldOwner: HashMap<String, Int>,
    codePoint: Int,
    char: String,
    variant: String,
) {
  when {
    variant.length == 1 -> {
      if (variant != char) parent.union(codePoint, variant.codePointAt(0))
    }
    else -> {
      val owner = multiCharFoldOwner[variant]
      if (owner == null) {
        multiCharFoldOwner[variant] = codePoint
      } else {
        parent.union(owner, codePoint)
      }
    }
  }
}

private fun buildFoldGroups(): List<Set<Int>> {
  val parent = UnionFind()
  val multiCharFoldOwner = HashMap<String, Int>()
  for (codePoint in MIN_CODE_POINT..MAX_CODE_POINT) {
    val char = String(Character.toChars(codePoint))
    registerFoldVariant(parent, multiCharFoldOwner, codePoint, char, char.lowercase())
    registerFoldVariant(parent, multiCharFoldOwner, codePoint, char, char.uppercase())
    registerFoldVariant(parent, multiCharFoldOwner, codePoint, char, char.lowercase())
  }
  val groups = HashMap<Int, MutableSet<Int>>()
  for (codePoint in parent.parent.keys) {
    groups.getOrPut(parent.find(codePoint)) { HashSet() }.add(codePoint)
  }
  return groups.values.filter { it.size > 1 }.map { it.toSet() }
}

private fun foldGroups(): List<Set<Int>> {
  val existing = foldGroupsCache
  if (existing != null) return existing
  synchronized(foldLock) {
    foldGroupsCache?.let {
      return it
    }
    val built = buildFoldGroups()
    foldGroupsCache = built
    return built
  }
}

private fun foldGroupByCodePoint(): Map<Int, Set<Int>> {
  foldGroupByCodePointCache?.let {
    return it
  }
  synchronized(foldLock) {
    foldGroupByCodePointCache?.let {
      return it
    }
    val mapping = HashMap<Int, Set<Int>>()
    for (group in foldGroups()) {
      for (codePoint in group) mapping[codePoint] = group
    }
    foldGroupByCodePointCache = mapping
    return mapping
  }
}

private fun foldPartners(group: Set<Int>, asciiOnly: Boolean): Set<Int> =
    if (!asciiOnly) group else group.filter { it < 128 }.toSet()

private fun addFoldCandidates(result: IntervalSet, candidates: Set<Int>): IntervalSet {
  var out = result
  for (candidate in candidates) {
    if (!out.contains(candidate)) out = out.union(IntervalSet.single(candidate))
  }
  return out
}

private fun expandIgnorecaseByMemberScan(
    intervalSet: IntervalSet,
    asciiOnly: Boolean,
): IntervalSet {
  val foldMap = foldGroupByCodePoint()
  var result = intervalSet
  val seenGroups = HashSet<Set<Int>>()
  for (range in intervalSet.ranges) {
    for (codePoint in range.first..range.last) {
      if (asciiOnly && codePoint >= 128) continue
      val group = foldMap[codePoint] ?: continue
      if (!seenGroups.add(group)) continue
      result = addFoldCandidates(result, foldPartners(group, asciiOnly))
    }
  }
  return result
}

private fun groupScanMatches(intervalSet: IntervalSet, candidates: Set<Int>): Boolean {
  if (candidates.size < 2) return false
  return candidates.any { intervalSet.contains(it) }
}

private fun expandIgnorecaseByGroupScan(intervalSet: IntervalSet, asciiOnly: Boolean): IntervalSet {
  var result = intervalSet
  for (group in foldGroups()) {
    val candidates = foldPartners(group, asciiOnly)
    if (!groupScanMatches(intervalSet, candidates)) continue
    result = addFoldCandidates(result, candidates)
  }
  return result
}

/** expand_ignorecase(interval_set, ascii_only). */
public fun expandIgnorecase(intervalSet: IntervalSet, asciiOnly: Boolean): IntervalSet {
  val memberCount = intervalSet.memberCount()
  return if (memberCount <= EXPAND_IGNORECASE_MEMBER_SCAN_CEILING) {
    expandIgnorecaseByMemberScan(intervalSet, asciiOnly)
  } else {
    expandIgnorecaseByGroupScan(intervalSet, asciiOnly)
  }
}
