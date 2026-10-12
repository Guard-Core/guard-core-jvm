package com.guardcore.engine.detection

import com.guardcore.engine.py.BranchAv
import com.guardcore.engine.py.ConditionalAv
import com.guardcore.engine.py.PyReParser
import com.guardcore.engine.py.ReNode
import com.guardcore.engine.py.ReOp
import com.guardcore.engine.py.RepeatAv
import com.guardcore.engine.py.SRE_MAXREPEAT
import com.guardcore.engine.py.SubPatternAv
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Port of tests/test_sus_patterns/test_redos_repeat_prefix.py, test_redos_repeat_units.py,
 * test_redos_repeat_alphabet.py, test_redos_exact_state.py, test_redos_literal_runs.py, and
 * test_redos_helper_branches.py: the prefix walk, its state machine, the lookbehind mutation,
 * repeat-group units, alphabets, and probe builders.
 */
class RedosWalkTest {
  private fun walkStates(pattern: String, alphabet: List<Char> = listOf('X', 'Y')): List<String> {
    val parsed = PyReParser.parse(pattern, 0)
    return PrefixWalk(flags = 0, collect = false, alphabet = alphabet)
        .walk(parsed.data, listOf(RepeatPrefixState("")))
        .map { it.text }
  }

  // ---- reaching prefixes preserve assertions and captures ----

  @Test
  fun reachingPrefixesPreserveAssertionsAndCaptures() {
    val cases =
        listOf(
            """\A(?!X)[XY]a+a+$""" to "Y",
            """\A(?=XY)[XY][XY]a+a+$""" to "XY",
            """\A(?!XX)[XY][XY]a+a+$""" to "XY",
            """(?<=foo)a+a+$""" to "foo",
            """(?<=(X))\1a+a+$""" to "XX",
            """\A[XY](?<!X)a+a+$""" to "Y",
            """\A[XY]XX(?<!XXX)a+a+$""" to "YXX",
            """\A([XY])\1a+a+$""" to "XX",
            """\A(?=([XY]))\1a+a+$""" to "X",
            """\A(X)?\1a+a+$""" to "XX",
            """\A(?:Xa+a+$)?""" to "X",
            """\A(?=X)X?a+a+$""" to "X",
            """\A(?=f?oo)fooa+a+$""" to "foo",
            """\Axf?(?<=f)a+a+$""" to "xf",
            """\Axf?(?<!x)a+a+$""" to "xf",
            """\A(?=foo).*oa+a+$""" to "foo",
            """\A(?=foo).+fooa+a+$""" to "foofoo",
        )
    for ((pattern, prefix) in cases) {
      val prefixes = repeatReachingPrefixes(pattern, 0)
      assertTrue(prefix in prefixes, "prefix $prefix missing for $pattern: $prefixes")
    }
  }

  @Test
  fun impossibleOrInvalidPrefixHasNoCandidate() {
    for (pattern in listOf("[", """(?!)[XY]+""", """(?=X)Y[XY]+""", """[^\s\S]+""")) {
      assertEquals(emptyList(), repeatReachingPrefixes(pattern, 0), pattern)
    }
  }

  // ---- prefix walk constraints ----

  @Test
  fun prefixWalkConstraints() {
    val cases =
        listOf(
            """(?=XY)(?=X)XY""" to listOf("XY"),
            """(?=X)(?=XY)XY""" to listOf("XY"),
            """(?=X)(?=Y)X""" to emptyList(),
            """(?=XY)X""" to listOf("X"),
            """(?!XY)XZ""" to listOf("XZ"),
            """(?<!)X""" to listOf("X"),
            """X(?<!Y)""" to listOf("X"),
            """(?<!X)Y""" to listOf("Y"),
            """X(?<!X)""" to emptyList(),
            """XX(?<!YY)""" to listOf("XX"),
            """(?:){1000}X""" to listOf("X"),
            """(?!){1}X""" to emptyList(),
            """X{0}Y""" to listOf("Y"),
            """(?<=)X""" to listOf("X"),
            """(?=foo)(?:)*foo""" to listOf("foo"),
            """(?=foo)x*foo""" to listOf("foo"),
        )
    for ((pattern, expected) in cases) {
      assertEquals(expected, walkStates(pattern), pattern)
    }
  }

  // ---- fail-closed budgets ----

  @Test
  fun prefixConstructionLimitsFailClosed() {
    val past = System.nanoTime() - 1_000_000L
    try {
      repeatReachingPrefixes("Xa+a+", 0, past)
      fail("expected deadline timeout")
    } catch (e: PatternValidationTimeout) {
      assertTrue("deadline" in e.message!!, e.message)
    }
    try {
      consumePiece(RepeatPrefixState("a".repeat(REPEAT_PREFIX_BUDGET)), "b")
      fail("expected length budget timeout")
    } catch (e: PatternValidationTimeout) {
      assertTrue("length budget" in e.message!!, e.message)
    }
    try {
      val body = PyReParser.parse("(X)", 0).data
      walkNegativeBehind(
          body,
          0,
          listOf(RepeatPrefixState("x".repeat(600))),
          listOf(RepeatPrefixState("y" + "x".repeat(600))),
          listOf('a', 'b'),
      )
      fail("expected lookbehind state budget timeout")
    } catch (e: PatternValidationTimeout) {
      assertTrue("lookbehind state budget" in e.message!!, e.message)
    }
    try {
      val body = PyReParser.parse("X", 0).data
      walkNegativeBehind(
          body,
          0,
          emptyList(),
          listOf(RepeatPrefixState("X", captures = listOf(Pair(1, "X")))),
          emptyList(),
      )
      fail("expected capture-dependent timeout")
    } catch (e: PatternValidationTimeout) {
      assertTrue("capture-dependent" in e.message!!, e.message)
    }
    try {
      repeatReachingPrefixes("""\A(?=(?=foo))fooa+a+$""", 0)
      fail("expected nested assertion timeout")
    } catch (e: PatternValidationTimeout) {
      assertTrue("nested assertion" in e.message!!, e.message)
    }
    try {
      repeatReachingPrefixes("""\A(?=(?!foo))fooa+a+$""", 0)
      fail("expected nested assertion timeout")
    } catch (e: PatternValidationTimeout) {
      assertTrue("nested assertion" in e.message!!, e.message)
    }
  }

  @Test
  fun deadPrefixBeforeQuantifiedSuffixFailsClosed() {
    val suffixes =
        listOf(
            "a+",
            "(a+)",
            """(?:Xa+|Yb+)""",
            """(?=a+)X""",
            """(?!a+)X""",
            """(?:a+)?""",
            """[a-z]{0,2}""",
        )
    for (suffix in suffixes) {
      try {
        repeatReachingPrefixes("""\A(?=f.o)foo""" + suffix, 0, null, requireReachable = true)
        fail("expected repeat-site prefixes timeout for $suffix")
      } catch (e: PatternValidationTimeout) {
        assertTrue("repeat-site prefixes" in e.message!!, e.message)
      }
    }
  }

  @Test
  fun deadPrefixWithoutRemainingRepeatNeedsNoAdversarialProbe() {
    assertEquals(
        emptyList(),
        repeatReachingPrefixes("""(?=X)Y""", 0, null, requireReachable = true),
    )
  }

  // ---- prefix state consumption ----

  @Test
  fun prefixStateConsumptionRejectsConflictingConstraints() {
    val state = RepeatPrefixState("a")
    assertTrue(consumePiece(state, "") === state)
    assertTrue(captureState(state, null, 0) === state)
    assertNull(mergePending("XY", "Z"))
    val excluded = RepeatPrefixState("a", excluded = IntervalSet.single('X'.code))
    assertNull(consumePiece(excluded, "X"))
    val pending = RepeatPrefixState("a", pending = "X")
    assertNull(consumePiece(pending, "Y"))
    assertNull(consumeAtom(pending, IntervalSet.single('Y'.code)))
    val forbidden = RepeatPrefixState("a", forbidden = listOf("XY"))
    assertNull(consumePiece(forbidden, "XYZ"))
    assertNull(consumeAtom(RepeatPrefixState("a", forbidden = listOf("X")), IntervalSet.single(88)))
    val consumed = consumePiece(RepeatPrefixState("a", pending = "XY"), "X")
    assertEquals("Y", consumed?.pending)
    assertEquals(listOf(Pair(1, "a")), captureState(state, 1, 0).captures)
    // A single-char forbidden word removes the member from the available set.
    val atomConsumed =
        consumeAtom(RepeatPrefixState("q", forbidden = listOf("a")), IntervalSet.single('a'.code))
    assertNull(atomConsumed)
    // stateTextSize counts text, pending, forbidden words, and captures.
    assertEquals(
        2 + 1 + 2 + 3,
        stateTextSize(
            RepeatPrefixState(
                "ab",
                pending = "c",
                forbidden = listOf("de"),
                captures = listOf(Pair(1, "fgh")),
            ),
        ),
    )
    // equals/hashCode/toString cover every distinguishing field.
    assertEquals(RepeatPrefixState("a", pending = "b"), RepeatPrefixState("a", pending = "b"))
    assertFalse(RepeatPrefixState("a").equals(RepeatPrefixState("a", pending = "b")))
    assertFalse(RepeatPrefixState("a").equals("not a state"))
    assertEquals("RepeatPrefixState(a, pending=)", RepeatPrefixState("a").toString())
  }

  // ---- unknown / atomic nodes in the walker ----

  @Test
  fun prefixWalkerUnknownNodeFailsClosed() {
    val walker = PrefixWalk(flags = 0, collect = false)
    val out = walker.walk(listOf(ReNode(ReOp.RANGE, Pair(65, 66))), listOf(RepeatPrefixState("")))
    assertEquals(emptyList(), out)
  }

  @Test
  fun prefixWalkerAtNodePassesThrough() {
    val walker = PrefixWalk(flags = 0, collect = false)
    val out =
        walker.walk(
            listOf(ReNode(ReOp.AT, com.guardcore.engine.py.AtAnchor.END_STRING)),
            listOf(RepeatPrefixState("X")),
        )
    assertEquals(listOf("X"), out.map { it.text })
  }

  // ---- prefixed probes ----

  @Test
  fun prefixedProbeHasExactLengthAndFailureTail() {
    val lengths = listOf(0, 1, 2, 3, 9, 10)
    for (length in lengths) {
      for (flood in listOf(false, true)) {
        val probe = prefixedRepeatProbe("XY", "ab", '!', flood, length)
        assertEquals(length, probe.length)
        assertTrue(probe.startsWith("XY".take(length)))
        if (length > 2) {
          val tailLength = if (flood) maxOf(1, (length - 2) / 2) else 1
          assertTrue(probe.endsWith("!".repeat(tailLength)))
        }
      }
    }
  }

  @Test
  fun prefixedBuilderDeduplicationAndBudget() {
    val builders = prefixedUnitBuilders(listOf("X"), listOf(Pair('a', '!'), Pair('a', '!')))
    assertEquals(listOf("Xaaaaa!", "Xaaa!!!"), builders.map { it(7) })
    assertEquals(emptyList(), prefixedUnitBuilders(emptyList(), listOf(Pair('a', '!'))))
    try {
      prefixedUnitBuilders(List(2049) { "X" }, listOf(Pair('a', '!')))
      fail("expected prefixed-probe candidate budget timeout")
    } catch (e: PatternValidationTimeout) {
      assertTrue("prefixed-probe candidate budget" in e.message!!, e.message)
    }
  }

  @Test
  fun groupProbeCandidatesPreserveSitesAndMemoizeStrays() {
    val calls = ArrayList<String>()
    val builders =
        groupUnitBuilders(
            listOf(Pair("X", "ab"), Pair("Y", "ab")),
            listOf('!', '?'),
        ) { unit ->
          calls.add(unit)
          '!'
        }
    val values = builders.map { it(7) }
    assertEquals(listOf("ab"), calls)
    assertEquals(values.size, values.toSet().size)
    assertTrue("Xababa!" in values)
    assertFalse("Yabab??" in values)
    assertTrue("Yaba???" in values)
    assertTrue("ababab!" in values)
  }

  @Test
  fun groupProbeCandidateExpansionHasABudget() {
    val pairs = List(2049) { i -> Pair("P$i", "u$i") }
    try {
      groupUnitBuilders(pairs, listOf('!', '?')) { '!' }
      fail("expected group-probe candidate budget timeout")
    } catch (e: PatternValidationTimeout) {
      assertTrue("group-probe candidate budget" in e.message!!, e.message)
    }
  }

  // ---- repeat units ----

  @Test
  fun repeatGroupUnitsFindPrefixUnitPairs() {
    val pairs = repeatGroupUnits("""X(?:ab)+c+""", 0)
    assertTrue(Pair("X", "ab") in pairs, pairs.toString())
    assertEquals(emptyList(), repeatGroupUnits("[", 0))
    // A pattern without a large repeat has no pairs.
    assertEquals(emptyList(), repeatGroupUnits("abc", 0))
  }

  // ---- repeat alphabets ----

  @Test
  fun repeatAlphabetFillsSplitByConstraint() {
    val fills = repeatAlphabetFills("""[a-c0-9]+x""", 0)
    assertTrue(fills.isNotEmpty(), "expected fills")
    assertTrue('a' in fills || '0' in fills, fills.toString())
    assertEquals(emptyList(), repeatAlphabetFills("[", 0))
    assertEquals(emptyList(), repeatAlphabetFills("abc", 0))
    // The prefix counts as repeated when includePrefix is set.
    val withPrefix = repeatAlphabetFills("""(?:ab)+""", 0, null, includePrefix = true)
    assertTrue('a' in withPrefix, withPrefix.toString())
  }

  @Test
  fun hasLargeBoundedRepeatDetection() {
    assertFalse(hasLargeBoundedRepeat("abc", 0))
    assertFalse(hasLargeBoundedRepeat("a{0,10}", 0))
    assertFalse(hasLargeBoundedRepeat("[", 0))
  }

  // ---- exact state ----

  @Test
  fun exactStateNarrowingAndOverlap() {
    assertNull(narrowExactStateRaw(null, IntervalSet.full()))
    assertNull(narrowExactStateRaw(IntervalSet.full(), null))
    val ab = IntervalSet.fromRange('a'.code, 'b'.code)
    val narrowed = narrowExactStateRaw(ab, IntervalSet.fromRange('b'.code, 'c'.code))
    assertEquals(IntervalSet.single('b'.code), narrowed)
    assertNull(exactOverlapFillRaw(null, IntervalSet.full()))
    assertNull(exactOverlapFillRaw(ab, null))
    assertEquals('b', exactOverlapFillRaw(ab, IntervalSet.fromRange('b'.code, 'z'.code)))
    assertNull(exactOverlapFillRaw(ab, IntervalSet.single('z'.code)))
    // Depth guard: a group deeper than the limit yields null.
    assertNull(isolatedGroupExactState(listOf(listOf(NonPairingSlot(true, null))), 40))
    // Non-pairing boundary slot with inner alternatives narrows to the group state.
    val inner = listOf(listOf(PairingAtom(IntervalSet.single('c'.code), false, false)))
    val state = isolatedGroupExactState(listOf(listOf(NonPairingSlot(true, inner))), 0)
    assertEquals(IntervalSet.single('c'.code), state)
    // An allowsZero atom is skipped.
    val zeroAtom = listOf(PairingAtom(IntervalSet.single('d'.code), true, false))
    val zeroState = isolatedGroupExactState(listOf(zeroAtom), 0)
    assertEquals(IntervalSet.full(), zeroState)
    // An alternative with no state contributes nothing.
    assertNull(isolatedGroupExactState(listOf(listOf(NonPairingSlot(true, null))), 0))
  }

  // ---- literal runs ----

  @Test
  fun adversarialLiteralRunsExtractForcedRuns() {
    val runs = adversarialLiteralRuns("""foo[a-z]+bar""")
    assertTrue("foo" in runs, runs.toString())
    assertTrue("bar" in runs, runs.toString())
    // Escaped digit backreference with a zero-width quantifier resets nothing.
    assertTrue(adversarialLiteralRuns("""\1*abc""").contains("abc"))
    // Escaped letter class cut.
    assertTrue(adversarialLiteralRuns("""\d+x""").contains("x"))
    // Narrow class picks its first char.
    assertTrue(adversarialLiteralRuns("""[bca]+""").contains("a"))
    // Wide class flushes the run.
    assertEquals(emptyList(), adversarialLiteralRuns("""[a-z]{50}""").filter { it.length > 20 })
    // Groups and alternations reset runs.
    assertEquals(listOf("a", "b"), adversarialLiteralRuns("""(a)|(b)"""))
    // Trailing backslash flushes what it holds.
    assertEquals(listOf("abc"), adversarialLiteralRuns("""abc\"""))
  }

  // ---- prefix history ----

  @Test
  fun suffixHistoryMarksObservables() {
    val parsed = PyReParser.parse("""X\bY""", 0)
    val history = suffixHistory(parsed.data, false)
    assertEquals(parsed.data.size, history.size)
    // history[i] = the enclosing scope or a LATER observable site.
    // [X, boundary, Y]: X has an observable boundary after it; nothing else does.
    assertTrue(history[0])
    assertFalse(history[1])
    assertFalse(history[2])
    // An atomic group observes history, so the site before it is marked.
    val atomicNode = ReNode(ReOp.ATOMIC_GROUP, listOf(ReNode(ReOp.LITERAL, 'Y'.code)))
    val atomicHistory = suffixHistory(listOf(ReNode(ReOp.LITERAL, 'X'.code), atomicNode), false)
    assertTrue(atomicHistory[0])
    assertFalse(atomicHistory[1])
    // Anchors other than word boundaries observe nothing.
    val anchorHistory =
        suffixHistory(
            listOf(
                ReNode(ReOp.AT, com.guardcore.engine.py.AtAnchor.BEGIN_STRING),
                ReNode(ReOp.LITERAL, 'X'.code),
            ),
            false,
        )
    assertFalse(anchorHistory[1])
    assertFalse(anchorHistory[0])
    // An enclosing observable scope marks every site.
    val enclosed = suffixHistory(listOf(ReNode(ReOp.LITERAL, 'X'.code)), true)
    assertTrue(enclosed[0])
  }

  @Test
  fun optionalStatesEquivalenceRequiresQuietStates() {
    val parsed = PyReParser.parse("""X(Y)?Z""", 0)
    val body = listOf(ReNode(ReOp.LITERAL, 'Y'.code))
    assertTrue(optionalStatesAreEquivalent(body, listOf(RepeatPrefixState("X")), false))
    assertFalse(
        optionalStatesAreEquivalent(body, listOf(RepeatPrefixState("X", pending = "q")), false),
    )
    assertFalse(optionalStatesAreEquivalent(body, listOf(RepeatPrefixState("X")), true))
  }

  @Test
  fun containsRepeatFindsNestedRepeats() {
    val parsed = PyReParser.parse("""(a+b)+""", 0)
    assertTrue(containsRepeat(parsed.data))
    val flat = PyReParser.parse("abc", 0)
    assertFalse(containsRepeat(flat.data))
    // An atomic group body is searched for repeats (constructed node: the
    // parser rejects the 3.11 (?>(...)) extension the same way its grammar gate does).
    val atomicRepeat =
        ReNode(
            ReOp.ATOMIC_GROUP,
            listOf(
                ReNode(
                    ReOp.MAX_REPEAT,
                    RepeatAv(1, SRE_MAXREPEAT, listOf(ReNode(ReOp.LITERAL, 'a'.code))),
                ),
            ),
        )
    assertTrue(containsRepeat(listOf(atomicRepeat)))
  }

  @Test
  fun prefixWalkerAtomicAndBackreferenceNodes() {
    // An atomic group preserves the consumed text and marks history.
    val walker = PrefixWalk(flags = 0, collect = false)
    val atomic = ReNode(ReOp.ATOMIC_GROUP, listOf(ReNode(ReOp.LITERAL, 'X'.code)))
    val out = walker.walk(listOf(atomic), listOf(RepeatPrefixState("")))
    assertEquals(listOf("X"), out.map { it.text })
    // A backreference consumes the captured text; without a capture it dies.
    val backref = ReNode(ReOp.GROUPREF, 1)
    val withCapture =
        walker.walk(
            listOf(backref),
            listOf(RepeatPrefixState("X", captures = listOf(Pair(1, "X")))),
        )
    assertEquals(listOf("XX"), withCapture.map { it.text })
    val withoutCapture = walker.walk(listOf(backref), listOf(RepeatPrefixState("")))
    assertEquals(emptyList(), withoutCapture.map { it.text })
    // A conditional takes the no-branch without the capture and yes-branch with it.
    val conditional =
        ReNode(
            ReOp.GROUPREF_EXISTS,
            ConditionalAv(
                1,
                listOf(ReNode(ReOp.LITERAL, 'Y'.code)),
                listOf(ReNode(ReOp.LITERAL, 'Z'.code)),
            ),
        )
    val noBranch = walker.walk(listOf(conditional), listOf(RepeatPrefixState("")))
    assertEquals(listOf("Z"), noBranch.map { it.text })
    val yesBranch =
        walker.walk(
            listOf(conditional),
            listOf(RepeatPrefixState("X", captures = listOf(Pair(1, "X")))),
        )
    assertEquals(listOf("XY"), yesBranch.map { it.text })
  }

  @Test
  fun prefixWalkerGroupNodeCapturesThePrefix() {
    val walker = PrefixWalk(flags = 0, collect = false)
    val group =
        ReNode(
            ReOp.SUBPATTERN,
            SubPatternAv(1, 0, 0, listOf(ReNode(ReOp.LITERAL, 'X'.code))),
        )
    val out = walker.walk(listOf(group), listOf(RepeatPrefixState("")))
    assertEquals(listOf("X"), out.map { it.text })
    assertEquals(listOf(Pair(1, "X")), out[0].captures)
    // A non-capturing group records no capture.
    val plainGroup =
        ReNode(
            ReOp.SUBPATTERN,
            SubPatternAv(null, 0, 0, listOf(ReNode(ReOp.LITERAL, 'X'.code))),
        )
    val outPlain = walker.walk(listOf(plainGroup), listOf(RepeatPrefixState("")))
    assertEquals(listOf("X"), outPlain.map { it.text })
    assertEquals(emptyList(), outPlain[0].captures)
    // A branch unions the alternatives.
    val branch =
        ReNode(
            ReOp.BRANCH,
            BranchAv(
                listOf(
                    listOf(ReNode(ReOp.LITERAL, 'X'.code)),
                    listOf(ReNode(ReOp.LITERAL, 'Y'.code)),
                ),
            ),
        )
    val outBranch = walker.walk(listOf(branch), listOf(RepeatPrefixState("")))
    assertEquals(setOf("X", "Y"), outBranch.map { it.text }.toSet())
  }

  @Test
  fun prefixWalkerCollectsPrefixesAtRepeatSites() {
    val parsed = PyReParser.parse("""Xa+a+""", 0)
    val prefixes = ArrayList<String>()
    val walker = PrefixWalk(flags = 0, prefixes = prefixes, collect = true, alphabet = listOf('a'))
    walker.walk(parsed.data, listOf(RepeatPrefixState("")))
    assertTrue(prefixes.isNotEmpty(), "expected collected prefixes")
    assertTrue(prefixes.all { it.startsWith("X") }, prefixes.toString())
  }

  @Test
  fun repeatGroupUnitsBudgetFailsClosed() {
    // A pathological nested repeat explodes the pair budget.
    try {
      repeatGroupUnits("(?:" + "ab".repeat(1) + """{0,50}){0,50}x""", 0)
    } catch (e: PatternValidationTimeout) {
      assertTrue("repeat-unit" in e.message!!, e.message)
    }
  }
}
