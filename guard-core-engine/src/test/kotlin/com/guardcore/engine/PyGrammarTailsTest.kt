package com.guardcore.engine

import com.guardcore.engine.py.PyAst
import com.guardcore.engine.py.PyUnicode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Ports the python-grammar surface the semantic analyzer's AST-risk ladder needs:
 * tests/test_sus_patterns/test_semantic.py (the ast arms) and the PyUnicode tails
 * (tests/test_sus_patterns/test_base64_view.py helpers).
 */
class PyGrammarTailsTest {
  private fun parses(text: String): Boolean = PyAst.parsesAsExpression(text)

  @Test
  fun coreExpressionFormsParse() {
    for (expr in
        listOf(
            "1",
            "-1",
            "+1",
            "~1",
            "1 + 2",
            "1 - 2 * 3",
            "2 ** 3 ** 2",
            "1 << 2 >> 3",
            "1 & 2 | 3 ^ 4",
            "not x",
            "x and y or z",
            "a < b <= c",
            "a != b",
            "a in b",
            "a not in b",
            "a is b",
            "a is not b",
            "x if y else z",
            "lambda x: x",
            "lambda x, y=2, *args, **kw: x",
            "f(1, 2, key=3, *args, **kwargs)",
            "a.b.c",
            "a[1]",
            "a[1:2]",
            "(a, b)",
            "(c,)",
            "[1, 2, [3]]",
            "{1: 'x', 2: 'y'}",
            "{'k'}",
            "()",
            "'single' + \"double\"",
            "f'{x + 1}'",
            "f'''raw {y!r:>{w}}'''",
            "True and False or None",
            "3.14",
            "1_000",
            "0x1F",
            "10 if True else 20",
            "x @ y",
        )) {
      assertTrue(parses(expr), expr)
    }
  }

  @Test
  fun malformedExpressionsReject() {
    for (expr in
        listOf(
            "",
            "1 +",
            "*",
            "x ~",
            "(1,",
            "[1,",
            "{1:",
            "lambda:",
            "x if y",
            "1 2",
            "@",
            ")",
            "(",
            "x := 1",
            "a ?? b",
            "'unterminated",
            "del x",
            "import os",
            "b'bytes'",
            "...",
            "(yield x)",
            "0o17",
        )) {
      assertFalse(parses(expr), expr)
    }
  }

  @Test
  fun parseRejectsNonExpressions() {
    // Statements and junk parse to false without throwing.
    assertFalse(parses("def f(): pass"))
    assertFalse(parses("class A: pass"))
  }

  // ---- PyUnicode tails ----

  @Test
  fun pyUnicodeCodePointHelpers() {
    // A surrogate pair is one code point.
    assertEquals(1, PyUnicode.cpLength("\uD83D\uDE00"))
    assertEquals(2, PyUnicode.cpLength("ab"))
    assertEquals("\uD83D\uDE00", PyUnicode.cpSlice("\uD83D\uDE00x", 0, 1))
    assertEquals("", PyUnicode.cpSlice("", 0, 1))
    assertEquals("bc", PyUnicode.cpSliceFrom("abc", 1))
    assertEquals("ab", PyUnicode.cpSliceTo("abc", 2))
    // isPrintable covers the control, surrogate, and format ranges.
    assertTrue(PyUnicode.isPrintable('a'))
    assertTrue(PyUnicode.isPrintable('\u00A1'))
    assertFalse(PyUnicode.isPrintable('\u001d'))
    assertFalse(PyUnicode.isPrintable('\u000c'))
    assertFalse(PyUnicode.isPrintable('\u007f'))
  }
}
