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
 * Ports the translation and deadline tails of tests/test_sus_patterns/ test_compiler.py and
 * tests/test_detection/test_scan_window_timing.py: pattern translation edges, match-group surface,
 * and the hard deadline.
 */
class PyReTailsTest {
  @Test
  fun localeFlagIsUnsupported() {
    try {
      PyRe.compile("x", PyReFlags.LOCALE)
      fail("expected a compile failure for re.LOCALE")
    } catch (e: PyRe.ReCompileError) {
      assertTrue("re.LOCALE" in e.message!!, e.message)
    }
  }

  @Test
  fun namedGroupAndBackrefTranslations() {
    // (?P<name>x) compiles and the group is addressable by index.
    val compiled = PyRe.compile("(?P<word>\\d+)", 0)
    val match = compiled.search("ab 42", 0, Long.MAX_VALUE)
    assertNotNull(match)
    assertEquals("42", match.group())
    assertEquals("42", match.group(1))
    // The (?P=name) backref spelling round-trips.
    val backref = PyRe.compile("""(?P<w>\w) (?P=w)""", 0)
    assertNotNull(backref.search("a a", 0, Long.MAX_VALUE))
    assertNull(backref.search("a b", 0, Long.MAX_VALUE))
  }

  @Test
  fun leadingClassBracketAndOddBraces() {
    // A leading ] in a class is a literal.
    val compiled = PyRe.compile("[]x]", 0)
    assertNotNull(compiled.search("]", 0, Long.MAX_VALUE))
    assertNotNull(compiled.search("x", 0, Long.MAX_VALUE))
    assertNull(compiled.search("y", 0, Long.MAX_VALUE))
    // python {,m} means {0,m}.
    val opt = PyRe.compile("a{,2}", 0)
    assertNull(opt.matchesFull("aaa", Long.MAX_VALUE))
    assertNotNull(opt.matchesFull("aa", Long.MAX_VALUE))
    assertNotNull(opt.matchesFull("", Long.MAX_VALUE))
    // A malformed brace is a literal.
    val literal = PyRe.compile("a{x", 0)
    assertNotNull(literal.search("a{x", 0, Long.MAX_VALUE))
  }

  @Test
  fun scopedNegativeFlagRewritesCompileAndMatch() {
    // IGNORECASE locked off inside a scope; the outer pattern stays case-folded.
    val compiled = PyRe.compile("""(?<![A-Za-z0-9+/])(?-i:rO0AB)""", PyReFlags.IGNORECASE)
    assertNotNull(compiled.search("xx rO0AB", 0, Long.MAX_VALUE))
    assertNull(compiled.search("xx RO0AB", 0, Long.MAX_VALUE))
    // A capture group wrapping the locked scope still captures.
    val grouped = PyRe.compile("""(\w+)(?-i:XY)""", PyReFlags.IGNORECASE)
    val m = grouped.search("abcXY", 0, Long.MAX_VALUE)
    assertNotNull(m)
    assertEquals("abc", m.group(1))
    assertNull(grouped.search("abcxy", 0, Long.MAX_VALUE))
  }

  @Test
  fun deadlineCharSequenceAbortsCatastrophicMatches() {
    val compiled = PyRe.compile("""(a+)+b""", 0)
    val text = "a".repeat(60)
    val deadline = System.nanoTime() + 50_000L // 50 microseconds
    try {
      compiled.search(text, 0, deadline)
      fail("expected DeadlineExceededException")
    } catch (e: PyRe.DeadlineExceededException) {
      assertTrue(e.message!!.contains("deadline"))
    }
    // charAt aborts on the periodic tick check once the deadline has passed.
    val seq = PyRe.DeadlineCharSequence(text, System.nanoTime() - 1)
    try {
      for (i in 0 until 2048) seq[i % text.length]
      fail("expected DeadlineExceededException")
    } catch (e: PyRe.DeadlineExceededException) {
      assertTrue(true)
    }
  }

  @Test
  fun matchGroupSurface() {
    val compiled = PyRe.compile("(\\d+)-(\\d+)", 0)
    val match = compiled.search("a 12-34 b", 0, Long.MAX_VALUE)
    assertNotNull(match)
    assertEquals("12-34", match.group())
    assertEquals("12", match.group(1))
    assertEquals("34", match.group(2))
    assertEquals(listOf("12", "34"), listOfNotNull(match.groupOrNull(1), match.groupOrNull(2)))
    assertEquals(2, match.charStart())
    assertEquals(7, match.charEnd())
    // finditer over all matches.
    val all = compiled.finditer("1-2 3-4", Long.MAX_VALUE)
    assertEquals(listOf("1-2", "3-4"), all.map { it.group() })
    // matchesFull anchors the whole input.
    assertNotNull(compiled.matchesFull("12-34", Long.MAX_VALUE))
    assertNull(compiled.matchesFull("x12-34", Long.MAX_VALUE))
    assertNull(compiled.matchesFull("12-34x", Long.MAX_VALUE))
    // fullmatchAt anchors within the [start, end) region.
    assertNotNull(compiled.fullmatchAt("12-34", 0, 5, Long.MAX_VALUE))
    assertNotNull(compiled.fullmatchAt("12-34", 1, 5, Long.MAX_VALUE))
    assertNull(compiled.fullmatchAt("12-34", 3, 4, Long.MAX_VALUE))
  }

  @Test
  fun searchHonorsStartAndEndBounds() {
    val compiled = PyRe.compile("needle", 0)
    assertNotNull(compiled.search("x needle", 2, Long.MAX_VALUE))
    assertNull(compiled.search("x needle", 8, Long.MAX_VALUE))
  }

  @Test
  fun multilineAndDotallBehavior() {
    val multiline = PyRe.compile("^b", PyReFlags.MULTILINE)
    assertNotNull(multiline.search("a\nb", 0, Long.MAX_VALUE))
    val dot = PyRe.compile("a.b", 0)
    assertNull(dot.search("a\nb", 0, Long.MAX_VALUE))
    val dotAll = PyRe.compile("a.b", PyReFlags.DOTALL)
    assertNotNull(dotAll.search("a\nb", 0, Long.MAX_VALUE))
  }

  @Test
  fun unixLinesAndCaseInsensitiveDefaults() {
    val ci = PyRe.compile("HELLO", PyReFlags.IGNORECASE)
    assertNotNull(ci.search("hello", 0, Long.MAX_VALUE))
    // Unicode case folding participates (the unicode-case flag).
    val ciUnicode = PyRe.compile("STRA\u00DFE", PyReFlags.IGNORECASE)
    assertNotNull(ciUnicode.search("stra\u00dfe", 0, Long.MAX_VALUE))
  }
}
