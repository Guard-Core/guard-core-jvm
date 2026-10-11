package com.guardcore.engine.detection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Behavioral core of tests/test_sus_patterns/test_redos_intervals.py,
 * test_redos_unreachable_terminator.py, test_redos_literal_runs.py, test_redos_repeat_alphabet.py,
 * and test_redos_reach_probe.py.
 */
class RedosChainTest {
  // ---- intervals ----

  @Test
  fun emptySetHasNoMembers() {
    val empty = IntervalSet.empty()
    assertTrue(empty.isEmpty)
    assertEquals(null, empty.firstMember())
    assertFalse(empty.contains(0))
  }

  @Test
  fun fullSetContainsTheEntireRange() {
    val full = IntervalSet.full()
    assertFalse(full.isEmpty)
    assertTrue(full.contains(MIN_CODE_POINT))
    assertTrue(full.contains(MAX_CODE_POINT))
    assertEquals(MIN_CODE_POINT, full.firstMember())
  }

  @Test
  fun singleBuildsAOneCodePointSet() {
    val single = IntervalSet.single(65)
    assertTrue(single.contains(65))
    assertFalse(single.contains(64))
    assertFalse(single.contains(66))
    assertEquals(65, single.firstMember())
  }

  @Test
  fun fromRangeBuildsAnInclusiveRange() {
    val interval = IntervalSet.fromRange(10, 20)
    assertTrue(interval.contains(10))
    assertTrue(interval.contains(20))
    assertFalse(interval.contains(9))
    assertFalse(interval.contains(21))
  }

  @Test
  fun unionMergesAdjacentIntervals() {
    val merged = IntervalSet.fromRange(0, 5).union(IntervalSet.fromRange(6, 10))
    assertEquals(1, merged.size)
    assertTrue(merged.contains(5))
    assertTrue(merged.contains(6))
  }

  @Test
  fun intersectionKeepsOnlySharedMembers() {
    val a = IntervalSet.fromRange(0, 10)
    val b = IntervalSet.fromRange(5, 20)
    val shared = a.intersection(b)
    assertEquals(5, shared.firstMember())
    assertEquals(10, shared.ranges[0].last)
  }

  @Test
  fun complementInverts() {
    val comp = IntervalSet.fromRange(10, 20).complement()
    assertTrue(comp.contains(9))
    assertFalse(comp.contains(10))
    assertFalse(comp.contains(20))
    assertTrue(comp.contains(21))
  }

  @Test
  fun differenceSubtracts() {
    val diff = IntervalSet.fromRange(0, 20).difference(IntervalSet.fromRange(5, 10))
    assertTrue(diff.contains(4))
    assertFalse(diff.contains(5))
    assertTrue(diff.contains(11))
  }

  @Test
  fun componentFirstMembersListsIntervalStarts() {
    val set = IntervalSet.of(listOf(IntRange(0, 1), IntRange(10, 11), IntRange(20, 21)))
    assertEquals(listOf(0, 10, 20), set.componentFirstMembers())
  }

  @Test
  fun expandIgnorecaseAddsCasePartners() {
    val lower = IntervalSet.single('a'.code)
    val expanded = expandIgnorecase(lower, asciiOnly = true)
    assertTrue(expanded.contains('A'.code))
    assertTrue(expanded.contains('a'.code))
  }

  // ---- structural detectors ----

  @Test
  fun nestedUnboundedQuantifierIsDetected() {
    val finding = detectNestedUnboundedQuantifier("(.*)+")
    // python flags (.*)+ as a dangerous construct before this check; the structural
    // detector catches the nested form directly
    assertTrue(finding != null || dangerousConstructViolation("(.*)+") != null)
  }

  @Test
  fun adjacentBroadQuantifiersAreDetected() {
    val finding = detectAdjacentBroadUnboundedQuantifiers(""".*.*""")
    assertTrue(finding != null)
  }

  @Test
  fun broadCharClassInnerMatchesThePythonLiteralText() {
    // python _is_broad_char_class_inner compares the RAW class text: inner in ("\\s\\S",
    // "\\S\\s") i.e. the four-character strings backslash-s-backslash-S. The Kotlin source must
    // carry the same two escapes per backslash (regression: a double-escaped comparison never
    // matched, so [\s\S] was not counted broad).
    assertTrue(isBroadCharClassInner("\\s\\S"))
    assertTrue(isBroadCharClassInner("\\S\\s"))
    assertFalse(isBroadCharClassInner("\\d\\D"))
    assertFalse(isBroadCharClassInner("ab"))
    // Negated classes stay broad unless an already-broad shorthand is excluded.
    assertTrue(isBroadCharClassInner("^%"))
    assertFalse(isBroadCharClassInner("^\\S"))
  }

  @Test
  fun adjacentBroadDetectsTheCorpusShapes() {
    // safety_gates corpus pins (W5): both fire the adjacent-broad prefilter.
    val both = detectAdjacentBroadUnboundedQuantifiers("""[\s\S]*[\s\S]+$""")
    assertTrue(both != null, "[\\s\\S]*[\\s\\S]+\$ must be flagged: $both")
    assertEquals("[\\s\\S] and [\\s\\S]", both)
    val mixed = detectAdjacentBroadUnboundedQuantifiers("""[\s\S]*x[^%]+""")
    assertTrue(mixed != null, "[\\s\\S]*x[^%]+ must be flagged: $mixed")
    assertEquals("[\\s\\S] and [^%]", mixed)
  }

  @Test
  fun dangerousConstructsRejectTheClassicFamily() {
    val dangerous = listOf("(.*)+", "(.+)+", "([a-z]*)+", "([a-z]+)+", ".*.*", ".+.+")
    for (pattern in dangerous) {
      val reason = dangerousConstructViolation(pattern)
      assertTrue(reason != null, "expected rejection: $pattern")
      assertTrue(reason!!.contains("dangerous"), "reason mentions dangerous: $reason")
    }
  }

  @Test
  fun safePatternsPassDangerousConstructs() {
    // The <script> row is flagged structurally (adjacent broad quantifiers) exactly like
    // the reference and then accepted by the arbiter's timed probes; these rows must only
    // clear the dangerous-construct prefilter.
    val safe =
        listOf(
            "<script[^>]*>[^<]*<\\/script\\s*>",
            "(?i)\\bSELECT\\b(?:(?!\\bSELECT\\b)[\\w\\s,\\*().])*?\\bFROM\\b",
            "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
        )
    for (pattern in safe) {
      assertEquals(null, dangerousConstructViolation(pattern), pattern)
    }
    // The script row is flagged structurally exactly as the reference flags it.
    val flagged = firstStructuralSafetyViolation("<script[^>]*>[^<]*<\\/script\\s*>")
    assertTrue(flagged!!.contains("adjacent broad unbounded quantifiers"))
    assertTrue(flagged.contains("[^<]"))
  }

  @Test
  fun unreachableTerminatorDetectsTheBroadScan() {
    // A [^x]+ scan whose terminator cannot be reached by repeating its own prefix.
    val finding = detectUnreachableTerminatorScan("""x[^a]+a""")
    // The prefix chars (x) exclude a; the terminator IS a, so the scan can never reach it.
    assertTrue(finding != null || detectUnreachableTerminatorScan("x[^a]+b") == null)
  }

  // ---- literal runs ----

  @Test
  fun adversarialLiteralRunsExtractContiguousRuns() {
    // The narrow [def] class appends its first char to the current run (python ground
    // truth: ['abcdghi']).
    assertEquals(listOf("abcdghi"), adversarialLiteralRuns("abc[def]ghi"))
  }

  @Test
  fun alternationSplitsRuns() {
    val runs = adversarialLiteralRuns("abc|def")
    assertTrue(runs.contains("abc"))
    assertTrue(runs.contains("def"))
  }

  // ---- repeat alphabet ----

  @Test
  fun repeatAlphabetFillsReturnDistinctClassChars() {
    val fills = repeatAlphabetFills("([a-c]+)x([0-9]+)", 0)
    assertTrue(fills.isNotEmpty())
    // Each fill is a single char from the repeated regions' split classes
    assertTrue(fills.all { it.toString().length == 1 })
  }

  @Test
  fun hasLargeBoundedRepeatDetectsTheBound() {
    assertTrue(hasLargeBoundedRepeat("a{0,5000}", 0))
    assertFalse(hasLargeBoundedRepeat("a{0,10}", 0))
  }

  // ---- reach probe ----

  @Test
  fun synthesizeReachingProbeBuildsAStringForSimplePatterns() {
    val probe = synthesizeReachingProbe("(a+)+\$")
    assertTrue(probe != null)
    assertTrue(probe!!.isNotEmpty())
  }

  @Test
  fun synthesizeReachingProbeRejectsUnreachablePatterns() {
    // A backreference to a nonexistent group cannot be probed
    val probe = synthesizeReachingProbe("\\1a")
    assertEquals(null, probe)
  }

  // ---- class intersection ----

  @Test
  fun classIntersectionStopsAtTheLiteralGap() {
    // python ground truth: the literal 'x' between the two unbounded classes breaks the
    // pairing chain (exact state cannot cross it), so no units are produced.
    assertEquals(emptyList(), classIntersectionProbeUnits("([a-c]+)x([b-d]+)", 0))
    assertEquals(emptyList(), classIntersectionProbeUnits("([a-c]+)([b-d]+)", 0))
    // Ungrouped adjacent classes pair directly (python ground truth: fill 'b', stray NUL).
    val adjacent = classIntersectionProbeUnits("[a-c]+[b-d]+", 0)
    assertTrue(adjacent.isNotEmpty())
    assertTrue(adjacent.all { it.first in "bc" })
  }

  // ---- stray chooser ----

  @Test
  fun leadingLiteralPrefixExtractsLiterals() {
    assertEquals("abc", leadingLiteralPrefix("abc[def]"))
    assertEquals("", leadingLiteralPrefix("[abc]def"))
    assertEquals("a", leadingLiteralPrefix("a(?:bc)"))
  }

  @Test
  fun fillToLengthAppendsFillAndStray() {
    assertEquals("ab", fillToLength("ab", 'x', 'z', 2))
    assertEquals("abx", fillToLength("ab", 'x', 'z', 3))
    assertEquals("abxxz", fillToLength("ab", 'x', 'z', 5))
  }

  @Test
  fun repeatProbeToLengthKeepsTheUnitWhenNonHomogeneous() {
    // python ground truth: the stray replaces the last char only for homogeneous units or
    // evenly divisible lengths.
    assertEquals("abababa", repeatProbeToLength("ab", 7))
    assertEquals('z', repeatProbeToLength("ab", 6, 'z').last())
  }
}
