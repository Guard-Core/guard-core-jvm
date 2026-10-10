package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe

/**
 * Stray character selection: the probe suffix that forces failed matches.
 *
 * Port of guard_core/detection_engine/_redos_stray_chooser.py. The reference verifies stray
 * candidates against untrusted patterns in a killable subprocess; the JVM analog is the
 * DeadlineCharSequence abort idiom: every candidate verification runs inline under a hard
 * wall-clock deadline, and exceeding it fails the validation closed.
 */

/** Python TimeoutError analog for the probe construction chain. */
public class PatternValidationTimeout(message: String) : RuntimeException(message)

public const val REACH_PROBE_STRAY_BYTE: Char = '\u0000'

private val LEADING_PREFIX_METACHARS = ".^$*+?{}[]()|\\".toSet()

private val STRAY_FALLBACK_CANDIDATES: List<Char> =
    listOf(
        '\u0000',
        'z',
        '\n',
        ' ',
        '-',
        '\t',
        '\r',
        '9',
        '!',
        '~',
        '_',
        '.',
        'A',
        '\u001f',
        '\u007f',
        '/',
    )

private const val STRAY_CANDIDATE_CAP = 16
private val STRAY_VERIFY_FILL_COUNTS = listOf(1, 2, 8)
private const val STRAY_VERIFY_TIMEOUT_SECONDS = 0.5

/** Unwraps leading transparent (?:...) groups. */
private fun unwrapLeadingTransparentGroup(pattern: String): String {
  var text = pattern
  while (text.startsWith("(?:")) {
    val end = findGroupEnd(text, 0) ?: break
    if (end != text.length) break
    text = text.substring(3, end - 1)
  }
  return text
}

/** _leading_literal_prefix: the mandatory literal prefix of the pattern. */
public fun leadingLiteralPrefix(pattern: String): String {
  val text = unwrapLeadingTransparentGroup(pattern)
  val prefix = StringBuilder()
  var i = 0
  val n = text.length
  while (i < n) {
    val c = text[i]
    if (
        c == '\\' &&
            i + 1 < n &&
            !text[i + 1].isDigitInternal() &&
            !text[i + 1].isAsciiLetterInternal()
    ) {
      prefix.append(text[i + 1])
      i += 2
      continue
    }
    if (c in LEADING_PREFIX_METACHARS) break
    prefix.append(c)
    i++
  }
  return prefix.toString()
}

/** _fill_to_length: prefix + fill run + stray, exactly [length] chars. */
public fun fillToLength(prefix: String, fillChar: Char, stray: Char, length: Int): String {
  if (length <= prefix.length) return prefix.substring(0, length)
  val bodyLength = length - prefix.length
  if (bodyLength > 1) {
    return prefix + fillChar.toString().repeat(bodyLength - 1) + stray
  }
  return prefix + fillChar.toString().repeat(bodyLength)
}

/** _repeat_probe_to_length: a [unit] run cut to [length] with the last char a stray. */
public fun repeatProbeToLength(
    unit: String,
    length: Int,
    stray: Char = REACH_PROBE_STRAY_BYTE,
): String {
  if (unit.isEmpty()) return unit
  val reps = length / unit.length + 1
  var result = unit.repeat(reps).substring(0, length)
  val homogeneous = unit.toSet().size <= 1
  if (homogeneous || length % unit.length == 0) {
    result = result.substring(0, result.length - 1) + stray
  }
  return result
}

private fun strayForPair(left: IntervalSet, right: IntervalSet): Char {
  val member = left.union(right).complement().firstMember() ?: return REACH_PROBE_STRAY_BYTE
  return Character.toChars(member)[0]
}

private fun firstComplementChar(intervals: IntervalSet): Char? {
  val member = intervals.complement().firstMember() ?: return null
  return Character.toChars(member)[0]
}

private fun dedupCappedCandidates(candidates: List<Char?>): List<Char> {
  val seen = HashSet<Char>()
  val result = ArrayList<Char>()
  for (candidate in candidates) {
    if (candidate == null || !seen.add(candidate)) continue
    result.add(candidate)
    if (result.size >= STRAY_CANDIDATE_CAP) break
  }
  return result
}

private fun collectPairingIntervals(slots: List<Slot>): List<IntervalSet> {
  val collected = ArrayList<IntervalSet>()
  for (slot in slots) {
    when (slot) {
      is PairingAtom -> collected.add(slot.intervals)
      is NonPairingSlot ->
          if (slot.inner != null) {
            for (alternative in slot.inner) collected.addAll(collectPairingIntervals(alternative))
          }
    }
  }
  return collected
}

private fun patternClassUnion(pattern: String, flags: Int): IntervalSet {
  val slots = patternSlots(pattern, flags) ?: return IntervalSet.empty()
  var union = IntervalSet.empty()
  for (intervals in collectPairingIntervals(slots)) union = union.union(intervals)
  return union
}

/** _pattern_complement_chars: first complement char of each pairing interval, deduped. */
public fun patternComplementChars(pattern: String, flags: Int): List<Char> {
  val slots = patternSlots(pattern, flags) ?: return emptyList()
  val out = LinkedHashSet<Char>()
  for (intervals in collectPairingIntervals(slots)) {
    val char = firstComplementChar(intervals) ?: continue
    out.add(char)
  }
  return out.toList()
}

/** _StrayContext: the pattern, its flags, its literal prefix, and its class union. */
public class StrayContext(
    public val pattern: String,
    public val flags: Int,
    public val prefix: String,
    public val patternUnion: IntervalSet,
    public val deadlineNanos: Long? = null,
)

public fun buildStrayContext(
    pattern: String,
    flags: Int,
    deadlineNanos: Long? = null,
): StrayContext =
    StrayContext(
        pattern,
        flags,
        leadingLiteralPrefix(pattern),
        patternClassUnion(pattern, flags),
        deadlineNanos,
    )

private fun strayVerificationTimeoutNanos(ctx: StrayContext): Long {
  val timeoutNanos = (STRAY_VERIFY_TIMEOUT_SECONDS * 1e9).toLong()
  val deadline = ctx.deadlineNanos ?: return timeoutNanos
  val remaining = deadline - System.nanoTime()
  if (remaining <= 0) {
    throw PatternValidationTimeout("Pattern validation probe construction exceeded its deadline")
  }
  return minOf(timeoutNanos, remaining)
}

/** The JVM analog of the reference's killable-subprocess stray verification. */
private fun firstBoundedForcingCandidate(
    ctx: StrayContext,
    candidates: List<Char>,
    probes: List<List<String>>,
): Char? {
  val timeoutNanos = strayVerificationTimeoutNanos(ctx)
  val compiled =
      try {
        PyRe.compile(ctx.pattern, ctx.flags)
      } catch (e: Exception) {
        return null
      }
  val deadlineNanos = System.nanoTime() + timeoutNanos
  for ((index, candidate) in candidates.withIndex()) {
    var forcedAll = true
    for (probe in probes[index]) {
      try {
        if (compiled.search(probe, 0, deadlineNanos) != null) {
          forcedAll = false
          break
        }
      } catch (e: PyRe.DeadlineExceededException) {
        throw PatternValidationTimeout(
            "Pattern validation stray verification exceeded its deadline",
        )
      }
    }
    if (forcedAll) return candidate
  }
  return null
}

private fun classIntersectionStrayCandidates(
    tail: List<IntervalSet>,
    left: IntervalSet,
    right: IntervalSet,
    patternUnion: IntervalSet,
): List<Char> {
  val ordered = ArrayList<Char?>()
  for (intervals in tail) ordered.add(firstComplementChar(intervals))
  ordered.add(firstComplementChar(right))
  ordered.add(firstComplementChar(left.union(right)))
  ordered.add(firstComplementChar(patternUnion))
  ordered.addAll(STRAY_FALLBACK_CANDIDATES)
  return dedupCappedCandidates(ordered)
}

/** choose_class_intersection_stray: the verified stray for a class-intersection fill. */
public fun chooseClassIntersectionStray(
    ctx: StrayContext,
    fillChar: Char,
    left: IntervalSet,
    right: IntervalSet,
    tail: List<IntervalSet>,
): Char {
  val candidates = classIntersectionStrayCandidates(tail, left, right, ctx.patternUnion)
  val probes = candidates.map { candidate ->
    STRAY_VERIFY_FILL_COUNTS.map { count ->
      fillToLength(ctx.prefix, fillChar, candidate, ctx.prefix.length + count + 1)
    }
  }
  return firstBoundedForcingCandidate(ctx, candidates, probes) ?: strayForPair(left, right)
}

private fun repeatUnitStrayCandidates(patternUnion: IntervalSet): List<Char> {
  val ordered = ArrayList<Char?>()
  ordered.add(firstComplementChar(patternUnion))
  ordered.addAll(STRAY_FALLBACK_CANDIDATES)
  return dedupCappedCandidates(ordered)
}

/** choose_repeat_unit_stray: the verified stray appended to a repeat-unit probe. */
public fun chooseRepeatUnitStray(ctx: StrayContext, unit: String): Char {
  if (unit.isEmpty()) return REACH_PROBE_STRAY_BYTE
  val candidates = repeatUnitStrayCandidates(ctx.patternUnion)
  val probes = candidates.map { candidate ->
    STRAY_VERIFY_FILL_COUNTS.map { count ->
      repeatProbeToLength(unit, unit.length * count, candidate)
    }
  }
  return firstBoundedForcingCandidate(ctx, candidates, probes) ?: REACH_PROBE_STRAY_BYTE
}
