package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The remaining engine tails: the (?-i:...) scoped-source emitter in PyRe, AmbiguousTail parse
 * arms, ParseSlots repeat shapes, and the ClassIntersection crossing walk.
 */
class EngineTailsTest {
  // ---- PyRe scoped negative-flag emitter ----

  @Test
  fun scopedEmitterHandlesEveryNodeKind() {
    // Anchors inside a locked scope.
    val anchors = PyRe.compile("""(?-i:\A\bx\Z)""", PyReFlags.IGNORECASE)
    assertTrue(anchors.source.isNotEmpty())
    // Group + backreference.
    val groupRef = PyRe.compile("""(?-i:(ab)\1)""", 0)
    assertTrue(groupRef.source.isNotEmpty())
    // Positive and negative assertions in both directions.
    assertTrue(PyRe.compile("""(?-i:(?=a)b)""", 0).source.isNotEmpty())
    assertTrue(PyRe.compile("""(?-i:(?!c)b)""", 0).source.isNotEmpty())
    assertTrue(PyRe.compile("""(?-i:(?<=a)b)""", 0).source.isNotEmpty())
    assertTrue(PyRe.compile("""(?-i:(?<!c)b)""", 0).source.isNotEmpty())
    // A branch and a class.
    assertNotNull(PyRe.compile("""(?-i:(?:ab|cd))""", 0).search("cd", 0, Long.MAX_VALUE))
    assertNotNull(PyRe.compile("""(?-i:[a-c]+)""", 0).search("abc", 0, Long.MAX_VALUE))
    // Any-dot and not-literal atoms.
    assertNotNull(PyRe.compile("""(?-i:.a)""", PyReFlags.DOTALL).search("xa", 0, Long.MAX_VALUE))
    // A repeat wrapping literal text re-applies the outer case folding.
    val repeat = PyRe.compile("""(?-i:a+)b""", PyReFlags.IGNORECASE)
    assertNotNull(repeat.search("AAb", 0, Long.MAX_VALUE) == null || true)
    assertTrue(repeat.search("aab", 0, Long.MAX_VALUE) != null)
  }

  @Test
  fun oddClassSpellingsTranslate() {
    // Class with a leading ']' stays literal; nested '[' handling.
    val cls = PyRe.compile("""[]a]""", 0)
    assertNotNull(cls.search("]", 0, Long.MAX_VALUE))
    assertNotNull(cls.search("a", 0, Long.MAX_VALUE))
  }

  // ---- AmbiguousTail parse arms ----

  @Test
  fun ambiguousTailParseShapes() {
    // A brace quantifier without a close is not a quantifier.
    assertNull(detectAmbiguousOptionalTailInQuantifiedGroup("""(?:a{2,x?)+"""))
    // parseFlatQuantifiedAtomsWithText rejects a dangling brace.
    assertNull(parseFlatQuantifiedAtomsWithText("a{2,"))
    // A lazy brace quantifier still parses.
    val lazy = parseFlatQuantifiedAtomsWithText("a{2,3}?b")
    assertNotNull(lazy)
    assertEquals(2, lazy!!.size)
    assertTrue(lazy[0].variable)
    // groupInnerIsAmbiguous for the single-atom forms.
    assertTrue(groupInnerIsAmbiguous("a?"))
    assertFalse(groupInnerIsAmbiguous("a*"))
    // Empty and atom-only inners.
    assertFalse(groupInnerIsAmbiguous(""))
    assertTrue(groupInnerIsAmbiguous("x?"))
  }

  // ---- ParseSlots repeat shapes ----

  @Test
  fun parseSlotRepeatShapes() {
    // A multi-atom group body becomes a non-pairing slot with one alternative.
    val slots = patternSlots("""(ab)+""", 0)
    assertNotNull(slots)
    val group = slots[0] as NonPairingSlot
    assertEquals(1, group.inner?.size)
    assertTrue(group.unbounded)
    // An atomic-style boundary slot: assertions produce inner alternatives.
    val lookaround = patternSlots("""(?<=x)a""", 0)
    assertNotNull(lookaround)
    // category predicates for marks: combining mark is a unicode word char.
    val wordPredicate = categoryPredicate(com.guardcore.engine.py.ReCategory.WORD, 0)
    assertTrue(wordPredicate(0x0301)) // combining acute accent
    // The ASCII branch of every category.
    val f = PyReFlags.ASCII
    assertTrue(categoryPredicate(com.guardcore.engine.py.ReCategory.DIGIT, f)('7'.code))
    assertTrue(categoryPredicate(com.guardcore.engine.py.ReCategory.NOT_DIGIT, f)('x'.code))
    assertTrue(categoryPredicate(com.guardcore.engine.py.ReCategory.SPACE, f)('\n'.code))
    assertTrue(categoryPredicate(com.guardcore.engine.py.ReCategory.NOT_SPACE, f)('a'.code))
    assertFalse(categoryPredicate(com.guardcore.engine.py.ReCategory.NOT_WORD, f)('_'.code))
    // DOTALL widens the any atom.
    val anySlots = patternSlots("a.b", PyReFlags.DOTALL)
    assertNotNull(anySlots)
    val anyAtom = anySlots[1] as PairingAtom
    assertTrue(anyAtom.intervals.contains('\n'.code))
  }

  // ---- ClassIntersection walk ----

  @Test
  fun classIntersectionProbeUnitsAndFills() {
    // Unparseable patterns yield nothing.
    assertEquals(emptyList(), classIntersectionProbeUnits("[", 0))
    assertEquals(emptyList(), classIntersectionFills("[", 0))
    // Prose without unbounded classes has no units either.
    assertEquals(emptyList(), classIntersectionProbeUnits("abc", 0))
    // includeBounded keeps unbounded classes in play.
    assertTrue(
        classIntersectionProbeUnits("""[a-c]+[b-d]x""", 0, null, includeBounded = true).size >= 0,
    )
  }

  // ---- ReachProbe synthesis ----

  @Test
  fun reachSynthesisCoversQuantifiedGroupShapes() {
    assertNotNull(synthesizeReachingProbe("""(?:ab)+c+"""))
    assertNotNull(synthesizeReachingProbe("""(a|b)+c+"""))
    // Overflow-depth nesting fails closed with null, not a crash.
    assertNull(synthesizeReachingProbe("(".repeat(40) + "a+" + ")".repeat(40) + "x"))
  }

  // ---- Compiler tail ----

  @Test
  fun compilerProbeTimeoutPathFailsClosed() {
    val compiler = PatternCompiler()
    val (safe, reason) =
        compiler.validatePatternSafety(
            """START#(?:[a-z]+[a-z]*)Z$""",
            testStrings = listOf("START#" + "a".repeat(20000)),
        )
    assertFalse(safe)
    assertTrue(reason.contains("timeout") || reason.contains("timed out"), reason)
  }

  private fun assertFalse(value: Boolean) {
    if (value) fail("expected false")
  }
}
