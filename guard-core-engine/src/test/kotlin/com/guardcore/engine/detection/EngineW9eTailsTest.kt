package com.guardcore.engine.detection

import com.guardcore.engine.py.PyAst
import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyReParser
import com.guardcore.engine.py.ReParseError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9e arm closure for the engine: the per-file tails the corpus and prior waves never reach. Every
 * arm is driven through the module's public surface with crafted inputs; the only lines that stay
 * open are host-timing races (each documented in docs/w9e-coverage.md).
 */
class EngineW9eTailsTest {
  // ------------------------------------------------------------ ParseSlots

  @Test
  fun `pattern slots drives the category, not-literal, class-item and multi-atom arms`() {
    // repeat of a bare category -> classNodePredicate compute for a CATEGORY node
    assertNotNull(patternSlots("\\d{2,}", 0))
    // repeat of a not-literal -> emitAtomSource NOT_LITERAL arm
    assertNotNull(patternSlots("[^a]{2,}", 0))
    // repeat of a class with a category item -> emitAtomSource IN + CATEGORY arm
    assertNotNull(patternSlots("[\\da]{2,}", 0))
    // the negated shorthand class items walk the remaining render arms
    assertNotNull(patternSlots("\\D{2,}", 0))
    assertNotNull(patternSlots("\\S{2,}", 0))
    assertNotNull(patternSlots("\\W{2,}", 0))
    assertNotNull(patternSlots("[\\D\\S\\W]{2,}", 0))
    // the any-atom repeat walks the ANY emit arm
    assertNotNull(patternSlots(".{2,}", 0))
    // multi-atom repeat body -> the NonPairingSlot multi-atom arm
    assertNotNull(patternSlots("(?:ab){2,}", 0))
    // nodeIntervals on a non-pairing node falls through to the empty-interval arm
    assertTrue(
        nodeIntervals(com.guardcore.engine.py.ReNode(com.guardcore.engine.py.ReOp.GROUPREF, 1), 0)
            .isEmpty,
    )
  }

  // ------------------------------------------------------------ ReachProbe

  @Test
  fun `reaching probe synthesis walks the group and escape arms`() {
    // malformed brace bound -> reachBraceQuantifierHigh else-null arm
    assertNotNull(synthesizeReachingProbe("a{2,x}b"))
    // escape with no representative char -> null
    assertNull(synthesizeReachingProbe("\\Xa"))
    // named groups: with and without a closing angle bracket
    assertNotNull(synthesizeReachingProbe("(?P<name>abc)"))
    assertNull(synthesizeReachingProbe("(?P<abc)"))
    // scoped flag group -> the inline-flag-scope arm
    assertNotNull(synthesizeReachingProbe("(?i:abc)"))
    // an unknown group form -> Pair(null, false)
    assertNull(synthesizeReachingProbe("(?<abc)"))
    // flag scopes with a negation: scope arm + flag-only arm
    assertNotNull(synthesizeReachingProbe("(?i-msx:abc)"))
    assertNotNull(synthesizeReachingProbe("(?i-msx)"))
  }

  // ------------------------------------------------------------ CostArbiter / ProbeFill

  @Test
  fun `reach probe cost verdict answers safe when no builders exist`() {
    val (safe, reason) = reachProbeCostVerdict("abc", null)
    assertTrue(safe, reason)
  }

  @Test
  fun `candidate builders walk the class intersection and prefix arms`() {
    // class-feeding-class crossing shapes drive the class-intersection builder family
    val builders = reachProbeCandidateBuilders("[ab]+[bc]+\\$\$", 0, Long.MAX_VALUE)
    assertTrue(builders.isNotEmpty())
    builders.forEach { it(64) }
    // a bounded class repeat drives the prefixed class-repeat builder lambda
    val bounded = reachProbeCandidateBuilders("[ab]{3,}[bc]{3,}", 0, Long.MAX_VALUE)
    bounded.forEach { it(64) }
    // group-pair units drive the group-unit and ambiguous-group builders
    val grouped = reachProbeCandidateBuilders("(ab)+(cd)+", 0, Long.MAX_VALUE)
    grouped.forEach { it(64) }
  }

  @Test
  fun `repeat reaching prefixes enforces its construction deadline`() {
    val expired = System.nanoTime() - 1
    assertFailsWith<PatternValidationTimeout> {
      repeatReachingPrefixes("(ab)+c", 0, expired)
    }
  }

  // ------------------------------------------------------------ RepeatPrefix / RepeatUnits /
  // RepeatAlphabet

  @Test
  fun `repeat prefix walk enforces its state and text budgets`() {
    // state budget: two chained alternations multiply past the walk limit
    val alt130 = (1..130).joinToString("|") { "a$it" }
    val stateBomb = "(?:$alt130)(?:$alt130)+c"
    assertFailsWith<PatternValidationTimeout> {
      reachProbeCandidateBuilders(stateBomb, 0, Long.MAX_VALUE)
    }
    // text budget: few states whose accumulated text exceeds the walk budget
    val fatAlts = (1..50).joinToString("|") { "x".repeat(45000) }
    val textBomb = "(?:$fatAlts){2}c"
    assertFailsWith<PatternValidationTimeout> {
      reachProbeCandidateBuilders(textBomb, 0, Long.MAX_VALUE)
    }
  }

  @Test
  fun `repeat prefix collection enforces the candidate budget`() {
    // 50 regions x 90 alternatives x 2 iterations accumulate past the 4096-prefix cap,
    // one region at a time (no state explosion within any single region)
    val alts90 = (1..90).joinToString("|") { "a$it" }
    val dense = "(?:$alts90){2}b".repeat(50)
    assertFailsWith<PatternValidationTimeout> {
      repeatReachingPrefixes(dense, 0, null, requireReachable = true)
    }
  }

  @Test
  fun `repeat unit budgets reject oversized units`() {
    // more than 4096 quantified group bodies trips the pair-count budget
    val manyGroups = (1..4200).joinToString("") { "(a${it}b){2}" }
    assertFailsWith<PatternValidationTimeout> {
      reachProbeCandidateBuilders(manyGroups, 0, Long.MAX_VALUE)
    }
  }

  @Test
  fun `repeat alphabet fills and the large-bounded-repeat probe answer`() {
    assertNotNull(repeatAlphabetFills("[ab]{2,}c", 0))
    // variable-bounded with a huge high bound is the large-bounded-repeat shape
    assertTrue(hasLargeBoundedRepeat("[ab]{5000,6000}c", 0))
    assertFalse(hasLargeBoundedRepeat("[ab]{2,}c", 0))
    assertFalse(hasLargeBoundedRepeat("[ab]{5000,}c", 0))
  }

  // ------------------------------------------------------------ UnreachableTerminator /
  // StructureRules

  @Test
  fun `unreachable terminator scan walks the malformed-brace, class and escape arms`() {
    // malformed brace quantifier -> skipBraceQuantifierAt returns 0
    assertNull(detectUnreachableTerminatorScan("ab{2,x}c"))
    // a char-class terminator
    assertNull(detectUnreachableTerminatorScan("(ab)[cd]"))
    // a negated class terminator is unknown
    assertNull(detectUnreachableTerminatorScan("(ab)[^cd]"))
    // a trailing lone backslash walks the escape fall-through
    assertNull(detectUnreachableTerminatorScan("ab\\"))
  }

  @Test
  fun `structure rules reject deep nesting and skip unclosed groups`() {
    val deep = "(?:".repeat(40) + "a" + "){2}".repeat(40)
    assertEquals(
        NESTING_DEPTH_REJECTION_REASON,
        detectNestedUnboundedQuantifier(deep),
    )
    assertEquals(
        NESTING_DEPTH_REJECTION_REASON,
        detectAdjacentBroadUnboundedQuantifiers(deep),
    )
    // an unclosed group with no scannable body is skipped without crashing
    assertNull(detectAdjacentBroadUnboundedQuantifiers("\\S+((("))
  }

  // ------------------------------------------------------------ IntervalSet / IgnorecaseFold /
  // ValidationCache

  @Test
  fun `interval set renders and ignorecase fold walks the group-scan path`() {
    val set = IntervalSet.fromRange(97, 122)
    assertTrue(set.toString().startsWith("IntervalSet("))
    // member count over the ceiling routes through the group-scan expansion
    val big = IntervalSet.fromRange(0, 5000)
    val once = expandIgnorecase(big, false)
    val twice = expandIgnorecase(big, false)
    assertTrue(once.memberCount() >= big.memberCount())
    assertEquals(once, twice)
    // small sets stay on the member scan; single-member groups hit the short-circuit
    expandIgnorecase(IntervalSet.single('A'.code), false)
    expandIgnorecase(IntervalSet.single('A'.code), true)
  }

  @Test
  fun `json mini null sentinel renders as null`() {
    assertEquals("null", com.guardcore.engine.detection.JsonMini.JsonNull.toString())
  }

  // ------------------------------------------------------------ Compiler

  @Test
  fun `safe matchers swallow deadline and generic match failures`() {
    val compiler = PatternCompiler()
    val bomb = compiler.compilePattern("(a+)+b", 0)
    // an expired timeout fires the deadline arm on the first matcher step
    val matcher = compiler.createSafeMatcher(bomb, timeout = -1.0)
    assertNull(matcher("a".repeat(30) + "c"))
    val finder = compiler.createSafeFinditerMatcher(bomb, timeout = -1.0)
    assertEquals(emptyList(), finder("a".repeat(30) + "c"))
  }

  @Test
  fun `batch compile skips reparse and recompile failures`() {
    val compiler = PatternCompiler()
    // a parse error and a parse-clean-but-uncompilable pattern both skip without throwing
    val compiled =
        compiler.batchCompile(
            listOf("(unclosed", "(?P<x>a)(?P<x>b)", "\\w+"),
            validate = false,
        )
    assertEquals(listOf("\\w+"), compiled.keys.toList())
  }

  @Test
  fun `pattern safety probe rejects uncompilable test-string patterns`() {
    val compiler = PatternCompiler()
    val (safe, reason) =
        compiler.validatePatternSafety(
            "(?P<x>a)(?P<x>b)",
            testStrings = listOf("ab"),
        )
    assertFalse(safe)
    assertTrue(reason.contains("Pattern validation failed"), reason)
  }

  // ------------------------------------------------------------ StrayChooser

  @Test
  fun `stray context default deadline and compile-failure verification arms`() {
    // the default-value path for deadlineNanos
    val ctx = StrayContext("ab+", 0, "ab", IntervalSet.fromRange(97, 98))
    assertEquals(null, ctx.deadlineNanos)
    // a pattern that parses but PyRe cannot compile (duplicate group names) -> the
    // stray verification compile-failure arm
    val builders = reachProbeCandidateBuilders("(?P<x>[a])(?P<x>[b])+c", 0, Long.MAX_VALUE)
    builders.forEach { it(32) }
  }

  // ------------------------------------------------------------ Truncation / Base64Decode /
  // Preprocessor

  @Test
  fun `base64 candidate decoding walks the gunzip, ratio and reassembly arms`() {
    // a truncated gzip header is an EOFException (an IOException, not a ZipException)
    assertNull(Base64Decode.boundedGunzip(byteArrayOf(0x1F.toByte(), 0x8B.toByte())))
    // binary payload decodes strict-UTF-8 clean but is under the printable ratio; the
    // caller-side fallback keeps the raw token in the content
    val binary = java.util.Base64.getEncoder().encodeToString(ByteArray(6) { (it + 1).toByte() })
    Base64Decode.decodeBase64Candidates(binary)
    // separators split the token: the reassembled run fragments take the concat arm
    Base64Decode.decodeBase64Candidates("Zm9vYmF-\$junk- YmFy", null)
    Base64Decode.decodeBase64Candidates("dGhlIHF1aWNrIGJyb3duIGZveA==", null)
  }

  // ------------------------------------------------------------ PyReParser / PyAst / PyRe

  @Test
  fun `pyre parser validates group references fail closed`() {
    // numeric group refs
    assertNotNull(PyReParser.parse("(a)\\g<1>", 0))
    assertFailsWith<ReParseError> { PyReParser.parse("(a)\\g<1a>", 0) }
    assertFailsWith<ReParseError> { PyReParser.parse("(a)\\g<2>", 0) }
    assertFailsWith<ReParseError> { PyReParser.parse("(a\\g<1>)", 0) }
    // named group refs
    assertNotNull(PyReParser.parse("(?P<x>a)\\g<x>", 0))
    assertFailsWith<ReParseError> { PyReParser.parse("(?P<x>a)\\g<x\$>", 0) }
    assertFailsWith<ReParseError> { PyReParser.parse("(?P<x>a)\\g<y>", 0) }
  }

  @Test
  fun `pyast parses star and double-star lambda parameters`() {
    assertTrue(PyAst.parsesAsExpression("lambda *a, **k: a"))
  }

  @Test
  fun `pyre scoped emitter passes case-neutral scopes through`() {
    // The scoped rewriter's fail-closed arm covers node kinds the sre port never emits
    // (NOT_LITERAL normalizes to IN+NEGATE; atomic groups are rejected at parse time);
    // it is unreachable from any pattern and carries a written JaCoCo exclude reason.
    PyRe.compile("(?-i:abc)", 0)
    PyRe.compile("(?i:abc)", 0)
  }

  @Test
  fun `pyre match exposes the default-pattern constructor arm`() {
    val java = java.util.regex.Pattern.compile("a")
    val jMatcher = java.matcher("a")
    assertTrue(jMatcher.find())
    val match = PyReMatch("a", jMatcher)
    assertEquals(0, match.charStart())
  }
}
