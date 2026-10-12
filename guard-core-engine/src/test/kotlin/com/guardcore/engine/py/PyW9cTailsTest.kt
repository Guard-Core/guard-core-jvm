package com.guardcore.engine.py

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9c arm closure for the engine py package: the PyAst expression-grammar corners, the PyUnicode
 * helpers, the PyRe source-translation tails (group-ref escapes, the scoped-emitter arms), the
 * PyReParser escape/inline-flag arms, and the RegexWorkers worker-loop surface.
 */
class PyAstW9cTest {
  @Test
  fun testStackOverflowDepthFailsClosed() {
    // parseAst catches StackOverflowError and rejects (the CPython recursion-limit analog).
    val deep = "(".repeat(30000) + "1" + ")".repeat(30000)
    assertFalse(PyAst.parsesAsExpression(deep))
  }

  @Test
  fun testCommentTokenization() {
    assertTrue(PyAst.parsesAsExpression("1 # trailing comment"))
    assertTrue(PyAst.parsesAsExpression("# only a comment\n1"))
  }

  @Test
  fun testAugmentedAssignmentOpsReject() {
    // The three-char aug ops tokenize as parts; eval mode rejects the statement.
    assertFalse(PyAst.parsesAsExpression("a **= 1"))
    assertFalse(PyAst.parsesAsExpression("a //= 2"))
    assertFalse(PyAst.parsesAsExpression("a >>= 1"))
    assertFalse(PyAst.parsesAsExpression("a <<= 1"))
  }

  @Test
  fun testStringEscapesAndTriples() {
    assertTrue(PyAst.parsesAsExpression("\"a\\nb\""))
    assertTrue(PyAst.parsesAsExpression("'it\\'s'"))
    assertTrue(PyAst.parsesAsExpression("\"\"\"triple\nstring\"\"\""))
    assertFalse(PyAst.parsesAsExpression("\"unterminated"))
  }

  @Test
  fun testLambdaParamShapes() {
    assertTrue(PyAst.parsesAsExpression("lambda x=1: x"))
    assertTrue(PyAst.parsesAsExpression("lambda x=1, y=2: x + y"))
    assertTrue(PyAst.parsesAsExpression("lambda *args: args"))
    assertTrue(PyAst.parsesAsExpression("lambda x, *rest: rest"))
    assertFalse(PyAst.parsesAsExpression("lambda x ): x"))
    assertFalse(PyAst.parsesAsExpression("lambda +: x"))
  }

  @Test
  fun testAwaitAndAttributeArms() {
    assertTrue(PyAst.parsesAsExpression("await x"))
    assertTrue(PyAst.parsesAsExpression("x.None"))
    assertTrue(PyAst.parsesAsExpression("x.True"))
    assertFalse(PyAst.parsesAsExpression("x.and"))
    assertFalse(PyAst.parsesAsExpression("x.3"))
  }

  @Test
  fun testCallArgShapes() {
    assertTrue(PyAst.parsesAsExpression("f()"))
    assertTrue(PyAst.parsesAsExpression("f(x,)"))
    assertTrue(PyAst.parsesAsExpression("f(x:=1)"))
    assertTrue(PyAst.parsesAsExpression("f(*args, **kwargs)"))
    assertFalse(PyAst.parsesAsExpression("f(x: int)"))
  }

  @Test
  fun testSubscriptShapes() {
    assertTrue(PyAst.parsesAsExpression("x[*a]"))
    assertTrue(PyAst.parsesAsExpression("x[a:b:c]"))
    assertTrue(PyAst.parsesAsExpression("x[a, *b]"))
    assertTrue(PyAst.parsesAsExpression("x[1, 2:3]"))
    assertTrue(PyAst.parsesAsExpression("x[1, 2:3:4]"))
  }

  @Test
  fun testParenBodyShapes() {
    assertTrue(PyAst.parsesAsExpression("(lambda x: x)"))
    assertTrue(PyAst.parsesAsExpression("(*a,)"))
    assertTrue(PyAst.parsesAsExpression("(x := 5)"))
    assertTrue(PyAst.parsesAsExpression("(1, *a)"))
    assertTrue(PyAst.parsesAsExpression("(x := 1, y := 2)"))
  }

  @Test
  fun testListBodyShapes() {
    assertTrue(PyAst.parsesAsExpression("[*a]"))
    assertTrue(PyAst.parsesAsExpression("[x for x in y if x]"))
  }

  @Test
  fun testBraceBodyShapes() {
    assertTrue(PyAst.parsesAsExpression("{**a}"))
    assertTrue(PyAst.parsesAsExpression("{k: v for k in x}"))
    assertTrue(PyAst.parsesAsExpression("{**a, **b}"))
    assertTrue(PyAst.parsesAsExpression("{a, b for b in c}"))
  }

  @Test
  fun testComprehensionContinuationAndTargets() {
    assertTrue(PyAst.parsesAsExpression("[x for x in y if a for z in w if b]"))
    assertTrue(PyAst.parsesAsExpression("[y for (a, b) in x]"))
    assertTrue(PyAst.parsesAsExpression("[y for [a, b] in x]"))
    assertTrue(PyAst.parsesAsExpression("[y for *a in x]"))
    assertTrue(PyAst.parsesAsExpression("[z for a.b in x]"))
    assertFalse(PyAst.parsesAsExpression("[y for 1 in x]"))
    assertTrue(PyAst.parsesAsExpression("{k: v for (a, b) in x}"))
  }
}

class PyUnicodeW9cTest {
  @Test
  fun testAllPrintableArms() {
    assertTrue(PyUnicode.allPrintable("abc XYZ 123"))
    assertTrue(PyUnicode.allPrintable(""))
    assertFalse(PyUnicode.allPrintable("a\u0000b"))
    assertFalse(PyUnicode.allPrintable("\u00A0"))
  }

  @Test
  fun testPerCodePointCaseMappings() {
    assertEquals("a", PyUnicode.lowerCp('A'.code))
    assertEquals("A", PyUnicode.upperCp('a'.code))
    assertEquals("a", PyUnicode.casefoldCp('A'.code))
    assertEquals("\u00DF", PyUnicode.casefoldCp(0x00DF))
  }

  @Test
  fun testCharToCpIndex() {
    assertEquals(0, PyUnicode.charToCpIndex("abc", 0))
    assertEquals(1, PyUnicode.charToCpIndex("abc", 1))
    assertEquals(3, PyUnicode.charToCpIndex("abc", 99))
    assertEquals(0, PyUnicode.charToCpIndex("abc", -5))
    // Astral plane: char index 2 (past the surrogate pair) is code point index 2.
    val astral = "a\uD83D\uDE00b"
    assertEquals(2, PyUnicode.charToCpIndex(astral, 3))
  }
}

class PyReW9cTailsTest {
  @Test
  fun testTranslateGroupRefShapesDirectly() {
    // \g<number> -> \number; \g<name> -> \k<name>; unterminated forms pass through verbatim.
    assertEquals("a\\1b", PyRe.translateSource("a\\g<1>b"))
    assertEquals("a\\k<nm>b", PyRe.translateSource("a\\g<nm>b"))
    assertEquals("a\\g<1b", PyRe.translateSource("a\\g<1b"))
    assertEquals("a(?P<nm", PyRe.translateSource("a(?P<nm"))
    assertEquals("a(?P=nmx", PyRe.translateSource("a(?P=nmx"))
    assertEquals("a\\k<nm>b", PyRe.translateSource("a(?P=nm)b"))
    assertEquals("a(?<nm>x)", PyRe.translateSource("a(?P<nm>x)"))
    // \Z is the absolute-end anchor on java (\\z).
    assertEquals("a\\z", PyRe.translateSource("a\\Z"))
  }

  @Test
  fun testCompileNamedGroupAndBackrefPattern() {
    val p = PyRe.compile("(?P<year>\\d{4})-\\g<year>", 0)
    val m = p.search("2020-2020", 0, Long.MAX_VALUE)
    assertTrue(m != null)
    assertEquals("2020", m!!.groupOrNull(1))
  }

  @Test
  fun testScopedEmitterArms() {
    // Non-locked segments inside a (?-i:...) pattern re-apply the stripped flags per segment.
    val ci = PyReFlags.IGNORECASE
    val p1 = PyRe.compile("(?-i:a)b", ci)
    assertTrue(p1.matchesFull("ab", Long.MAX_VALUE) != null)
    assertTrue(p1.matchesFull("aB", Long.MAX_VALUE) != null)
    assertTrue(p1.matchesFull("Ab", Long.MAX_VALUE) == null)
    // Class, dot, and category atoms inside and outside the locked scope.
    val p2 = PyRe.compile("(?-i:[^x]).", ci)
    assertTrue(p2.matchesFull("ay", Long.MAX_VALUE) != null)
    val p3 = PyRe.compile("(?-i:a)\\d", ci)
    assertTrue(p3.matchesFull("a5", Long.MAX_VALUE) != null)
    // Anchors and groups inside the locked scope.
    val p4 = PyRe.compile("(?-i:^a$)", ci)
    assertTrue(p4.matchesFull("a", Long.MAX_VALUE) != null)
    val p5 = PyRe.compile("(?-i:(a))\\1", ci)
    assertTrue(p5.matchesFull("aa", Long.MAX_VALUE) != null)
    // Branches, lookahead, lookbehind, negative lookahead inside the scope.
    val p6 = PyRe.compile("(?-i:a|b)c", ci)
    assertTrue(p6.matchesFull("ac", Long.MAX_VALUE) != null)
    val p7 = PyRe.compile("(?-i:(?=a))a", ci)
    assertTrue(p7.matchesFull("a", Long.MAX_VALUE) != null)
    val p8 = PyRe.compile("(?-i:(?<=a))b", ci)
    assertTrue(p8.search("ab", 0, Long.MAX_VALUE) != null)
    val p9 = PyRe.compile("(?-i:(?!x))a", ci)
    assertTrue(p9.matchesFull("a", Long.MAX_VALUE) != null)
    // Quantifier spellings emitted inside scopes: ?, {n}, {n,}, {n,m} and lazy forms.
    val p10 = PyRe.compile("(?-i:ab?)c", ci)
    assertTrue(p10.matchesFull("abc", Long.MAX_VALUE) != null)
    val p11 = PyRe.compile("(?-i:ab{2})c", ci)
    assertTrue(p11.matchesFull("abbc", Long.MAX_VALUE) != null)
    val p12 = PyRe.compile("(?-i:ab{1,})c", ci)
    assertTrue(p12.matchesFull("abc", Long.MAX_VALUE) != null)
    val p13 = PyRe.compile("(?-i:ab{1,2}?)c", ci)
    assertTrue(p13.matchesFull("abc", Long.MAX_VALUE) != null)
    val p14 = PyRe.compile("(?-i:a*?b)", ci)
    assertTrue(p14.matchesFull("aab", Long.MAX_VALUE) != null)
    // Control-character literals inside the scope.
    val p15 = PyRe.compile("(?-i:a\\nb)", ci)
    assertTrue(p15.matchesFull("a\nb", Long.MAX_VALUE) != null)
    val p16 = PyRe.compile("(?-i:a\\rb)", ci)
    assertTrue(p16.matchesFull("a\rb", Long.MAX_VALUE) != null)
    val p17 = PyRe.compile("(?-i:a\\tb)", ci)
    assertTrue(p17.matchesFull("a\tb", Long.MAX_VALUE) != null)
    val p18 = PyRe.compile("(?-i:a\\fb)", ci)
    assertTrue(p18.matchesFull("ab", Long.MAX_VALUE) != null)
    val p19 = PyRe.compile("(?-i:a\\vb)", ci)
    assertTrue(p19.matchesFull("ab", Long.MAX_VALUE) != null)
    val p20 = PyRe.compile("(?-i:a\\ab)", ci)
    assertTrue(p20.matchesFull("ab", Long.MAX_VALUE) != null)
    // Non-ASCII literal inside the scope hits the final appendCodePoint arm.
    val p21 = PyRe.compile("(?-i:\\u00e9)x", ci)
    assertTrue(p21.matchesFull("\u00E9x", Long.MAX_VALUE) != null)
    // Negative-flag scope under a repeat and a word-boundary anchor outside it.
    val p22 = PyRe.compile("(?-i:ab)+z", ci)
    assertTrue(p22.matchesFull("ababz", Long.MAX_VALUE) != null)
    val p23 = PyRe.compile("\\b(?-i:ab)\\b", ci)
    assertTrue(p23.matchesFull("ab", Long.MAX_VALUE) != null)
  }

  @Test
  fun testDeadlineCharSequenceWithTimeout() {
    // timeout <= 0 returns the original sequence; a positive timeout wraps.
    val text = "abcdef"
    assertTrue(PyRe.DeadlineCharSequence.withTimeout(text, 0.0) === text)
    assertTrue(PyRe.DeadlineCharSequence.withTimeout(text, -1.0) === text)
    val wrapped = PyRe.DeadlineCharSequence.withTimeout(text, 5.0)
    assertEquals('a', wrapped[0])
    assertEquals(text.length, wrapped.length)
    assertEquals(text, wrapped.toString())
    assertEquals("bcd", wrapped.subSequence(1, 4).toString())
    // The no-deadline sentinel never throws.
    val absolute = PyRe.DeadlineCharSequence.absolute(text, Long.MAX_VALUE)
    assertEquals("abcdef", absolute.toString())
  }

  @Test
  fun testPatternToStringAndMatchOnAstralText() {
    val p = PyRe.compile("b", 0)
    assertEquals("b", p.toString())
    // toCp takes the code-point table path on astral text.
    val m = p.search("a\uD83D\uDE00b", 0, Long.MAX_VALUE)!!
    assertEquals(2, m.start())
    assertEquals(3, m.end())
    assertEquals("b", m.group())
    assertEquals("a\uD83D\uDE00b", m.subject())
    assertEquals(3, m.charStart())
    assertEquals(4, m.charEnd())
  }

  @Test
  fun testSearchArmsWithEndposAndRegions() {
    val p = PyRe.compile("b", 0)
    assertNull(p.search("ab", 5, Long.MAX_VALUE))
    assertNull(p.search("ab", 0, 0, Long.MAX_VALUE))
    assertNull(p.matchAt("ab", -1, 2, Long.MAX_VALUE))
    assertNull(p.matchSubstring("ab", 3, 1, Long.MAX_VALUE))
    assertNull(p.fullmatchAt("ab", 5, 2, Long.MAX_VALUE))
    val region = p.search("ab", 0, 1, Long.MAX_VALUE)
    assertNull(region)
    val at1 = p.matchAt("ab", 1, 2, Long.MAX_VALUE)
    assertTrue(at1 != null)
    assertEquals("b", at1!!.group())
    // matchSubstring treats the region as the whole string (python pattern.match(slice)).
    val sub = p.matchSubstring("b", 0, 1, Long.MAX_VALUE)
    assertTrue(sub != null)
    assertNull(p.matchSubstring("ab", 0, 2, Long.MAX_VALUE))
    val full = p.fullmatchAt("b", 0, 1, Long.MAX_VALUE)
    assertTrue(full != null)
  }

  @Test
  fun testFinditerAccumulatesMatches() {
    val p = PyRe.compile("a", 0)
    val matches = p.finditer("banana", Long.MAX_VALUE)
    assertEquals(3, matches.size)
    assertEquals(listOf(1, 3, 5), matches.map { it.start() })
  }
}

class PyReParserW9cTailsTest {
  private fun parse(pattern: String, flags: Int = 0): ParsedPattern = PyReParser.parse(pattern, flags)

  private fun classItems(parsed: ParsedPattern): List<ReNode> = parsed.data[0].av as List<ReNode>

  @Test
  fun testMultipleRepeatRejects() {
    assertParseError("a**", "multiple repeat")
    assertParseError("a{1}{2}", "multiple repeat")
    assertParseError("a*+", "multiple repeat")
  }

  @Test
  fun testBraceFormsParseOrStayLiteral() {
    // Three-part brace is a literal (python behavior): every atom stays literal.
    val literal = parse("a{1,2,3}")
    assertTrue(literal.data.all { it.op == ReOp.LITERAL })
    // Unterminated brace is a literal.
    val unterminated = parse("a{2")
    assertEquals(ReOp.LITERAL, unterminated.data[0].op)
  }

  @Test
  fun testUnbalancedParenAndLoneRparen() {
    assertParseError("a)", "unbalanced")
    assertParseError("(a", "unterminated subpattern")
  }

  @Test
  fun testTopLevelEscapeArms() {
    assertEquals(ReOp.AT, parse("\\B").data[0].op)
    assertEquals(ReOp.IN, parse("\\D").data[0].op)
    assertEquals(ReOp.IN, parse("\\W").data[0].op)
    assertEquals(ReOp.LITERAL, parse("\\a").data[0].op)
    assertEquals(ReOp.LITERAL, parse("\\f").data[0].op)
    assertEquals(ReOp.LITERAL, parse("\\r").data[0].op)
    assertEquals(ReOp.LITERAL, parse("\\t").data[0].op)
    assertEquals(ReOp.LITERAL, parse("\\v").data[0].op)
    assertEquals('A'.code, parse("\\u0041").data[0].av as Int)
    assertEquals('A'.code, parse("\\U00000041").data[0].av as Int)
    classItems(parse("[\\U00000041]"))
    classItems(parse("[\\a]"))
    classItems(parse("[\\b]"))
    classItems(parse("[\\f]"))
    classItems(parse("[\\v]"))
    assertEquals(ReCategory.NOT_DIGIT, classItems(parse("[\\D]")).single().av)
    assertEquals(ReCategory.NOT_WORD, classItems(parse("[\\W]")).single().av)
    assertEquals('A'.code, classItems(parse("[\\x41]")).single().av)
  }

  @Test
  fun testInlineFlagLetters() {
    parse("(?m)^x$")
    parse("(?s).")
    parse("(?a)\\w")
    parse("(?x) a b # comment\n")
    // Negative inline flags: the (?-i:...) scope + the double-negative rejection.
    parse("(?i-m:x)")
    assertParseError("(?i--x)", "global flags not at the start")
  }

  @Test
  fun testVerboseTrailingWhitespaceAndComment() {
    // Trailing whitespace/comments at end-of-pattern exercise the skipVerbose loop exits.
    parse("(?x)a ")
    parse("(?x)a # trailing comment without newline")
    parse("(?x)a#x\nb")
  }

  private fun assertParseError(pattern: String, fragment: String) {
    try {
      parse(pattern)
      throw AssertionError("expected ReParseError for $pattern")
    } catch (e: ReParseError) {
      assertTrue(
          e.messageText.contains(fragment),
          "pattern $pattern: '${e.messageText}' lacks $fragment",
      )
    }
  }
}
