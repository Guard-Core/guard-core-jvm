package com.guardcore.engine.detection

/**
 * Code-point interval set with the exact operations the ReDoS static-safety chain needs.
 *
 * Port of guard_core/detection_engine/_redos_intervals.py (MIN_CODE_POINT 0, MAX_CODE_POINT
 * 0x10FFFF, normalization merges adjacent intervals, union/intersection/ complement/difference,
 * first-member and component-first-members accessors, and the category-interval cache).
 */
public const val MIN_CODE_POINT: Int = 0
public const val MAX_CODE_POINT: Int = 0x10FFFF

public class IntervalSet private constructor(private val intervals: List<IntRange>) {
  public companion object {
    private fun normalize(raw: List<IntRange>): List<IntRange> {
      if (raw.isEmpty()) return emptyList()
      val ordered = raw.sortedWith(compareBy({ it.first }, { it.last }))
      val merged = ArrayList<IntRange>()
      var current = ordered[0]
      for (i in 1 until ordered.size) {
        val next = ordered[i]
        current =
            if (next.first <= current.last + 1) {
              if (next.last > current.last) IntRange(current.first, next.last) else current
            } else {
              merged.add(current)
              next
            }
      }
      merged.add(current)
      return merged
    }

    private fun fromNormalized(intervals: List<IntRange>): IntervalSet = IntervalSet(intervals)

    public fun empty(): IntervalSet = fromNormalized(emptyList())

    public fun full(): IntervalSet =
        fromNormalized(listOf(IntRange(MIN_CODE_POINT, MAX_CODE_POINT)))

    public fun single(codePoint: Int): IntervalSet =
        fromNormalized(listOf(IntRange(codePoint, codePoint)))

    public fun fromRange(low: Int, high: Int): IntervalSet {
      val lo = maxOf(MIN_CODE_POINT, low)
      val hi = minOf(MAX_CODE_POINT, high)
      if (lo > hi) return empty()
      return fromNormalized(listOf(IntRange(lo, hi)))
    }

    public fun of(intervals: List<IntRange>): IntervalSet = IntervalSet(normalize(intervals))
  }

  init {
    // Intervals are expected pre-normalized; construction via the factories guarantees it.
  }

  public val isEmpty: Boolean
    get() = intervals.isEmpty()

  public val size: Int
    get() = intervals.size

  /** The normalized interval list (read-only use). */
  public val ranges: List<IntRange>
    get() = intervals

  public fun contains(codePoint: Int): Boolean {
    var lowBound = 0
    var highBound = intervals.size
    while (lowBound < highBound) {
      val mid = (lowBound + highBound) / 2
      val range = intervals[mid]
      if (codePoint < range.first) {
        highBound = mid
      } else if (codePoint > range.last) {
        lowBound = mid + 1
      } else {
        return true
      }
    }
    return false
  }

  public fun firstMember(): Int? = if (intervals.isEmpty()) null else intervals[0].first

  public fun componentFirstMembers(): List<Int> = intervals.map { it.first }

  public fun union(other: IntervalSet): IntervalSet =
      IntervalSet(normalize(intervals + other.intervals))

  public fun intersection(other: IntervalSet): IntervalSet {
    val result = ArrayList<IntRange>()
    var i = 0
    var j = 0
    val left = intervals
    val right = other.intervals
    while (i < left.size && j < right.size) {
      val a = left[i]
      val b = right[j]
      val low = maxOf(a.first, b.first)
      val high = minOf(a.last, b.last)
      if (low <= high) result.add(IntRange(low, high))
      if (a.last < b.last) i++ else j++
    }
    return fromNormalized(result)
  }

  public fun complement(): IntervalSet {
    val result = ArrayList<IntRange>()
    var cursor = MIN_CODE_POINT
    for (range in intervals) {
      if (range.first > cursor) result.add(IntRange(cursor, range.first - 1))
      cursor = range.last + 1
    }
    if (cursor <= MAX_CODE_POINT) result.add(IntRange(cursor, MAX_CODE_POINT))
    return fromNormalized(result)
  }

  public fun difference(other: IntervalSet): IntervalSet = intersection(other.complement())

  public fun memberCount(): Long = intervals.sumOf { (it.last - it.first + 1).toLong() }

  override fun equals(other: Any?): Boolean = other is IntervalSet && other.intervals == intervals

  override fun hashCode(): Int = intervals.hashCode()

  override fun toString(): String = "IntervalSet($intervals)"
}

private val categoryIntervalsCache: HashMap<Any, IntervalSet> = HashMap()

/**
 * cached_category_intervals: builds the interval set of every code point satisfying [predicate],
 * cached by [cacheKey]. Iterates the full code point range like the reference.
 */
public fun cachedCategoryIntervals(cacheKey: Any, predicate: (Int) -> Boolean): IntervalSet {
  synchronized(categoryIntervalsCache) {
    val cached = categoryIntervalsCache[cacheKey]
    if (cached != null) return cached
  }
  val intervals = ArrayList<IntRange>()
  var start: Int? = null
  for (codePoint in MIN_CODE_POINT..MAX_CODE_POINT) {
    if (predicate(codePoint)) {
      if (start == null) start = codePoint
    } else if (start != null) {
      intervals.add(IntRange(start, codePoint - 1))
      start = null
    }
  }
  if (start != null) intervals.add(IntRange(start, MAX_CODE_POINT))
  val result = IntervalSet.of(intervals)
  synchronized(categoryIntervalsCache) { categoryIntervalsCache[cacheKey] = result }
  return result
}
