package com.guardcore.util.py

import kotlin.math.min

/**
 * Port of `difflib.get_close_matches` and the `SequenceMatcher` internals it uses (junk = None,
 * autojunk enabled), which guard-core's unknown-field warning consumes for the "Did you mean" hint
 * (guard_core/models.py:144).
 *
 * The port follows CPython Lib/difflib.py: find_longest_match with the b2j index,
 * get_matching_blocks queue, ratio / quick_ratio / real_quick_ratio, then the nlargest selection
 * with cutoff 0.6.
 */
public object PyDiffLib {
  /** Port of `difflib.get_close_matches(word, possibilities, n=3, cutoff=0.6)`. */
  public fun getCloseMatches(
      word: String,
      possibilities: List<String>,
      n: Int = 3,
      cutoff: Double = 0.6,
  ): List<String> {
    require(n >= 1) { "n must be at least 1" }
    require(cutoff in 0.0..1.0) { "cutoff must be in [0.0, 1.0]" }
    val matcher = SequenceMatcher(b = word)
    val scored = ArrayList<Pair<Double, String>>()
    for (possibility in possibilities) {
      matcher.setSeq1(possibility)
      if (
          matcher.realQuickRatio() >= cutoff &&
              matcher.quickRatio() >= cutoff &&
              matcher.ratio() >= cutoff
      ) {
        scored.add(matcher.ratio() to possibility)
      }
    }
    // heapq.nlargest(n, scored) on (ratio, string) tuples: ratio desc,
    // then the string itself desc (tuple comparison inside nlargest).
    val sorted =
        scored.sortedWith(
            compareByDescending<Pair<Double, String>> { it.first }.thenByDescending { it.second },
        )
    return sorted.take(n).map { it.second }
  }
}

/** Port of `difflib.SequenceMatcher` with isjunk=None and autojunk=True. */
public class SequenceMatcher(
    a: String = "",
    b: String = "",
) {
  private var a: String = a
  private var b: String = b
  private var b2j: Map<Char, List<Int>> = emptyMap()
  private val bJunk: Set<Char> = emptySet()
  private var matchingBlocksCache: List<Triple<Int, Int, Int>>? = null
  private var ratioCache: Double? = null

  init {
    chainB()
  }

  public fun setSeq1(a: String) {
    if (a == this.a) return
    this.a = a
    matchingBlocksCache = null
    ratioCache = null
  }

  public fun setSeq2(b: String) {
    if (b == this.b) return
    this.b = b
    matchingBlocksCache = null
    ratioCache = null
    chainB()
  }

  private fun chainB() {
    // Python builds b2j, then (autojunk) removes elements of very popular
    // items when len(b) >= 200.
    val map = HashMap<Char, MutableList<Int>>()
    for ((i, ch) in b.withIndex()) {
      map.getOrPut(ch) { ArrayList() }.add(i)
    }
    if (b.length >= 200) {
      val nTest = b.length / 100 + 1
      for ((ch, indices) in map.entries.toList()) {
        if (indices.size > nTest) map.remove(ch)
      }
    }
    b2j = map
  }

  public fun findLongestMatch(alo: Int, ahi: Int, blo: Int, bhi: Int): Triple<Int, Int, Int> {
    val b2j = this.b2j
    var besti = alo
    var bestj = blo
    var bestsize = 0
    var j2len: HashMap<Int, Int> = HashMap()
    for (i in alo until ahi) {
      val newj2len = HashMap<Int, Int>()
      for (j in b2j[a[i]].orEmpty()) {
        if (j < blo) continue
        if (j >= bhi) break
        val k = (j2len[j - 1] ?: 0) + 1
        newj2len[j] = k
        if (k > bestsize) {
          besti = i - k + 1
          bestj = j - k + 1
          bestsize = k
        }
      }
      j2len = newj2len
    }
    // Junk-extension passes; with isjunk=None bJunk is empty, so these
    // collapse to plain boundary extension (kept for structural parity).
    while (
        besti > alo && bestj > blo && !bJunk.contains(b[bestj - 1]) && a[besti - 1] == b[bestj - 1]
    ) {
      besti--
      bestj--
      bestsize++
    }
    while (
        besti + bestsize < ahi &&
            bestj + bestsize < bhi &&
            !bJunk.contains(b[bestj + bestsize]) &&
            a[besti + bestsize] == b[bestj + bestsize]
    ) {
      bestsize++
    }
    while (
        besti > alo && bestj > blo && bJunk.contains(b[bestj - 1]) && a[besti - 1] == b[bestj - 1]
    ) {
      besti--
      bestj--
      bestsize++
    }
    while (
        besti + bestsize < ahi &&
            bestj + bestsize < bhi &&
            bJunk.contains(b[bestj + bestsize]) &&
            a[besti + bestsize] == b[bestj + bestsize]
    ) {
      bestsize++
    }
    return Triple(besti, bestj, bestsize)
  }

  public fun getMatchingBlocks(): List<Triple<Int, Int, Int>> {
    matchingBlocksCache?.let {
      return it
    }
    val la = a.length
    val lb = b.length
    val queue = ArrayDeque<List<Int>>()
    queue.add(listOf(0, la, 0, lb))
    val matched = ArrayList<Triple<Int, Int, Int>>()
    while (queue.isNotEmpty()) {
      val segment = queue.removeLast()
      val (i, j, k) = findLongestMatch(segment[0], segment[1], segment[2], segment[3])
      if (k > 0) {
        matched.add(Triple(i, j, k))
        if (segment[0] < i && segment[2] < j) {
          queue.add(listOf(segment[0], i, segment[2], j))
        }
        if (i + k < segment[1] && j + k < segment[3]) {
          queue.add(listOf(i + k, segment[1], j + k, segment[3]))
        }
      }
    }
    matched.sortWith(compareBy({ it.first }, { it.second }))
    var i1 = 0
    var j1 = 0
    var k1 = 0
    val nonAdjacent = ArrayList<Triple<Int, Int, Int>>()
    for ((i2, j2, k2) in matched) {
      if (i1 + k1 == i2 && j1 + k1 == j2) {
        k1 += k2
      } else {
        if (k1 > 0) nonAdjacent.add(Triple(i1, j1, k1))
        i1 = i2
        j1 = j2
        k1 = k2
      }
    }
    if (k1 > 0) nonAdjacent.add(Triple(i1, j1, k1))
    nonAdjacent.add(Triple(la, lb, 0))
    matchingBlocksCache = nonAdjacent
    return nonAdjacent
  }

  public fun ratio(): Double {
    val cached = ratioCache
    if (cached != null) return cached
    val matches = getMatchingBlocks().sumOf { it.third }
    val r = calculateRatio(matches)
    ratioCache = r
    return r
  }

  public fun realQuickRatio(): Double = calculateRatio(min(a.length, b.length))

  /** Port of quick_ratio: sum of min(count_a, count_b) over shared elements. */
  public fun quickRatio(): Double {
    val countsB = HashMap<Char, Int>()
    for (ch in b) countsB.merge(ch, 1, Int::plus)
    val countsA = HashMap<Char, Int>()
    for (ch in a) countsA.merge(ch, 1, Int::plus)
    var matches = 0
    for ((ch, countA) in countsA) {
      countsB[ch]?.let { matches += min(countA, it) }
    }
    return calculateRatio(matches)
  }

  private fun calculateRatio(matches: Int): Double {
    val total = a.length + b.length
    if (total == 0) return 1.0
    return 2.0 * matches / total
  }
}
