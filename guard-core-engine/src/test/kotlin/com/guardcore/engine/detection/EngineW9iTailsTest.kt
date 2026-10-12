package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9i batch 7 (completing): the final engine tails to the family 100 percent line gate - the
 * batch-compile ReCompileError skip arm (a legal python pattern whose java translation fails to
 * compile), the truncation attack-budget concatenation, the class/escape terminator tokens, and
 * the class-intersection crossing arms where a non-pairing group slot follows a pairing class.
 */
class EngineW9iTailsTest {
  /** batchCompile's ReCompileError skip arm (172-173): parses as python, fails as java. */
  @Test
  fun `batch compile skips patterns that parse but fail java compilation`() {
    // A non-Latin group name is a legal python identifier, so PyReParser accepts it;
    // java.util.regex rejects the translated name at Pattern.compile.
    assertFailsWith<PyRe.ReCompileError> { PyRe.compile("(?P<café>a)(?P=café)", 0) }
    val compiler = PatternCompiler()
    val compiled =
        compiler.batchCompile(
            listOf("(?P<café>a)(?P=café)", "abc"),
            validate = false,
        )
    assertEquals(setOf("abc"), compiled.keys)
  }

  /** Truncation: the attack-length budget arm (151-154) over a small full-scan budget. */
  @Test
  fun `truncation concatenates attack regions over a small budget`() {
    val preprocessor = ContentPreprocessor(maxFullScanBytes = 64)
    val content = "eval(1);".repeat(40)
    val regions = preprocessor.extractAttackRegions(content)
    val attackLength = regions.sumOf { it.last - it.first + 1 }
    assertTrue(attackLength >= 64, "expected attack regions to exceed the budget")
    val truncated = truncateSafely(preprocessor, content)
    assertTrue(truncated.isNotEmpty())
    assertTrue(truncated.contains("eval"))
  }

  /** UnreachableTerminator: the class terminator token arms (61, 64-66). */
  @Test
  fun `unreachable terminator scans a class terminator after a negated scan`() {
    // A negated broad scan gives excluded != null, so the scan steps into
    // classTerminatorFinding and terminatorCharsAt visits the '[' token (61).
    assertNull(detectUnreachableTerminatorScan("[^a]+[xyz](?!)q"))
    // The negated inner class takes the startsWith("^") return (65).
    assertNull(detectUnreachableTerminatorScan("[^a]+[^b](?!)q"))
  }

  /** ClassIntersection: the crossing arms over class-feeding-group shapes. */
  @Test
  fun `class intersection crosses groups fed by a diverged exact state`() {
    val patterns =
        listOf(
            // exactFill pairing arm (141-142) + the empty-overlap state handoff (144-148).
            "[ab]+(?:[aq])+[zq]+",
            // A boundary group (min 1) disjoint from shared with a non-null exact fill (72).
            "[ab]+(?:[aq])+(?:[b])+",
            // An allows-zero group whose inner chain fails the crossing (74).
            "[ab]+(?:[aq])+(?:[ab][z])*",
        )
    for (pattern in patterns) {
      val builders = reachProbeCandidateBuilders(pattern, 0, null)
      builders.forEach { it(64) }
      assertTrue(builders.isNotEmpty(), pattern)
    }
    assertNotNull(classIntersectionProbeUnits("[ab]+(?:[aq])+(?:[b])+", 0))
  }
}
