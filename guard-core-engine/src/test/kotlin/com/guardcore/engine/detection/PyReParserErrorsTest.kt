package com.guardcore.engine.detection

import com.guardcore.engine.py.PyReParser
import com.guardcore.engine.py.ReNode
import com.guardcore.engine.py.ReOp
import com.guardcore.engine.py.ReParseError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Ports the python-grammar fail-closed arms of sre_parse that the corpus and the pattern tables
 * never reach: tests/test_sus_patterns/test_compiler.py error-message cases plus the reference
 * error strings.
 */
class PyReParserErrorsTest {
  private fun expectError(pattern: String, messagePart: String) {
    try {
      PyReParser.parse(pattern, 0)
      fail("expected ReParseError for $pattern")
    } catch (e: ReParseError) {
      assertTrue(
          messagePart in e.messageText,
          "pattern $pattern: expected '$messagePart' in '${e.messageText}'",
      )
    }
  }

  @Test
  fun nothingToRepeat() {
    for (pattern in listOf("*x", "+x", "?x", "{2}x")) {
      expectError(pattern, "nothing to repeat")
    }
  }

  @Test
  fun multipleRepeat() {
    for (pattern in listOf("x**", "x*+", "x{2}{3}", "x*{2}", "x++")) {
      expectError(pattern, "multiple repeat")
    }
  }

  @Test
  fun repetitionNumberTooLarge() {
    expectError("x{99999999999}", "the repetition number is too large")
  }

  @Test
  fun malformedBraceIsALiteral() {
    val parsed = PyReParser.parse("x{a}", 0)
    assertEquals(ReOp.LITERAL, parsed.data[1].op)
    assertEquals('{'.code, parsed.data[1].av)
    val parsed2 = PyReParser.parse("x{,}", 0)
    assertEquals('{'.code, parsed2.data[1].av)
  }

  @Test
  fun unterminatedCharacterSets() {
    for (pattern in listOf("[abc", "[", "[^", "[a-", "[]")) {
      expectError(pattern, "unterminated character set")
    }
  }

  @Test
  fun badCharacterRanges() {
    expectError("[z-a]", "bad character range")
    expectError("[\\d-z]", "bad character range")
    expectError("[a-\\d]", "bad character range")
  }

  @Test
  fun incompleteEscapes() {
    expectError("""\x""", "incomplete escape")
    expectError("""\x4""", "incomplete escape")
    expectError("""\u12""", "incomplete escape")
    expectError("""\U1234567""", "incomplete escape")
    expectError("[\\x]", "incomplete escape")
    expectError("\\", "bad escape (end of pattern)")
    expectError("[\\", "bad escape (end of pattern)")
  }

  @Test
  fun namedEscapeFailsClosed() {
    expectError("""\N{DASH}""", """bad escape \N""")
    expectError("[\\N{DASH}]", """bad escape \N""")
  }

  @Test
  fun octalEscapes() {
    // In range.
    val parsed = PyReParser.parse("""\101""", 0)
    assertEquals(ReOp.LITERAL, parsed.data[0].op)
    assertEquals(0x41, parsed.data[0].av)
    val nul = PyReParser.parse("""\0""", 0)
    assertEquals(0, nul.data[0].av)
    val inClass = PyReParser.parse("""[\101]""", 0)
    val classItems = inClass.data[0].av as List<ReNode>
    assertEquals(ReOp.LITERAL, classItems[0].op)
    assertEquals(65, classItems[0].av)
    // Out of range (both the atom and the class spellings).
    expectError("""\777""", "octal escape value")
    expectError("[\\777]", "octal escape value")
  }

  @Test
  fun groupReferences() {
    // Valid reference.
    val parsed = PyReParser.parse("(x)\\1", 0)
    assertEquals(ReOp.GROUPREF, parsed.data[1].op)
    // Missing group.
    expectError("""\1""", "invalid group reference")
    // Group still open.
    expectError("(a\\1)", "cannot refer to an open group")
    // A reference past the group count fails.
    expectError("(a)(b)\\3", "invalid group reference")
    // Two digits that are not all octal extend the reference number.
    expectError("(a)(b)\\89", "invalid group reference")
  }

  @Test
  fun namedGroupsAndReferences() {
    val parsed = PyReParser.parse("(?P<name>x)(?P=name)", 0)
    assertEquals(2, parsed.groups)
    assertEquals(mapOf("name" to 1), parsed.groupNames)
    expectError("(?P=x)", "unknown group name")
    expectError("(?P<a", "missing >, unterminated name")
    expectError("(?P=a", "missing ), unterminated name")
    expectError("(?P<a>x)(?P<a>y)", "redefinition of group name")
    expectError("(?Pz)", "unknown extension ?P")
    // Python 3.11 spellings stay rejected (the corpus grammar is 3.10).
    expectError("(?<name>x)", "unknown extension ?<")
  }

  @Test
  fun unterminatedSubpatterns() {
    for (pattern in listOf("(abc", "((a)", "(?:ab", "(?=", "(?!a", "(?<=a", "(?<!a")) {
      expectError(pattern, "missing ), unterminated subpattern")
    }
    // A stray closing paren at top level.
    expectError("abc)", "unbalanced parenthesis")
  }

  @Test
  fun unknownExtensions() {
    expectError("(?", "unknown extension")
    expectError("(?>a)", "unknown extension ?>")
    expectError("(?(1)a|b)", "unknown extension ?(")
  }

  @Test
  fun commentGroups() {
    val parsed = PyReParser.parse("x(?#note)y", 0)
    assertEquals(2, parsed.data.size)
    expectError("(?#note", "missing ), unterminated comment")
  }

  @Test
  fun inlineFlags() {
    expectError("(?z)", "unknown flag")
    expectError("(?z:x)", "unknown flag")
    expectError("(a(?i))", "global flags not at the start of the expression")
    expectError("(?i", "unknown flag")
    // Scoped and global flags parse.
    val scoped = PyReParser.parse("(?i:x)y", 0)
    assertEquals(2, scoped.data.size)
    // (?i-x) without a colon is a global flags declaration (dropped from the AST).
    val removeScope = PyReParser.parse("(?i-x)y", 0)
    assertEquals(1, removeScope.data.size)
    val global = PyReParser.parse("(?i)x", 0)
    assertEquals(1, global.data.size)
  }

  @Test
  fun groupNestingDepthFailsClosed() {
    expectError("(".repeat(21) + "x" + ")".repeat(21), "only supports 20 nested parentheses")
  }

  @Test
  fun verboseModeSkipsWhitespaceAndComments() {
    val parsed = PyReParser.parse("(?x) a # comment\n b\t#c2", 0)
    assertEquals(2, parsed.data.size)
    // A comment that never ends consumes the rest.
    val parsed2 = PyReParser.parse("(?x) a # comment", 0)
    assertEquals(1, parsed2.data.size)
  }

  @Test
  fun lookaroundsParseWithDirection() {
    val ahead = PyReParser.parse("(?=a)(?!b)", 0)
    assertEquals(2, ahead.data.size)
    val behind = PyReParser.parse("(?<=a)(?<!b)", 0)
    assertEquals(2, behind.data.size)
  }
}
