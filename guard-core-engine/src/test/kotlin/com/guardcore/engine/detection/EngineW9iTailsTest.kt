package com.guardcore.engine.detection

import com.guardcore.engine.py.PyAst
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
 * compile), the truncation attack-budget concatenation, the class/escape terminator tokens, and the
 * class-intersection crossing arms where a non-pairing group slot follows a pairing class.
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
            // The pairing chain over a disjoint pairing slot (the empty-overlap verdict).
            "[ab]+(?:[aq])+[zq]+",
            // A boundary group (min 1) disjoint from shared with a non-null exact fill (72).
            "[ab]+(?:[aq])+(?:[b])+",
            // An allows-zero group whose inner chain fails the crossing (74).
            "[ab]+(?:[aq])+(?:[ab][z])*",
            // A bounded multi-atom group (non-boundary, inner atoms min 1) whose crossing
            // fails at the first inner atom (74).
            "[ab]+(?:z[b]){0,3}",
        )
    for (pattern in patterns) {
      val builders = reachProbeCandidateBuilders(pattern, 0, null)
      builders.forEach { it(64) }
      assertTrue(builders.isNotEmpty(), pattern)
    }
    assertNotNull(classIntersectionProbeUnits("[ab]+(?:[aq])+(?:[b])+", 0))
  }

  /** Base64Decode: the fragment reassembly appended beside the base decode (219). */
  @Test
  fun `base64 decode appends the fragment reassembly`() {
    // The wrapped-attack pipeline shape: over the iterated decode passes the
    // fragment pass reassembles the wrapped payload and appends it beside the
    // base with the python separator (219).
    val out =
        ContentPreprocessor()
            .decodeCommonEncodings(
                "eval(base64_decode('YWxlcnQoMSk='))",
                null,
            )
    assertTrue(out.contains("alert(1)"), out)
    assertTrue(out.contains(" "), "expected the reassembly appended beside the base: " + out)
  }

  /** PyAst: the lambda parameter list's bare-star continuation (249). */
  @Test
  fun `py ast walks a bare star lambda parameter`() {
    // "lambda a*: 1" walks the name parameter, takes the bare-star continuation,
    // then fails on the dangling colon - the arm is the parse walk itself.
    kotlin.test.assertFalse(PyAst.parsesAsExpression("lambda a*: 1"))
    assertTrue(PyAst.parsesAsExpression("lambda *a: 1"))
  }
}
