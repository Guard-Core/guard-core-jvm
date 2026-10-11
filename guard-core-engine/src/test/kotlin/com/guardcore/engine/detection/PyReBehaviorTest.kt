package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyReParser
import com.guardcore.engine.py.ReParseError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Behavioral core of the python-re compatibility layer (test_compiler.py grammar cases). */
class PyReBehaviorTest {
  @Test
  fun compileAndSearchBasics() {
    val p = PyRe.compile("<script[^>]*>[^<]*<\\/script\\s*>", PyReFlags.IGNORECASE)
    assertTrue(p.search("<script>alert(1)</script>", 0, Long.MAX_VALUE) != null)
    assertTrue(p.search("<SCRIPT >x</script >", 0, Long.MAX_VALUE) != null)
    assertTrue(p.search("<script>x</div>", 0, Long.MAX_VALUE) == null)
  }

  @Test
  fun endZTranslatesToAbsoluteEnd() {
    val p = PyRe.compile("\\A/etc/passwd\\Z", 0)
    assertTrue(p.search("/etc/passwd", 0, Long.MAX_VALUE) != null)
    assertTrue(p.search("/etc/passwdx", 0, Long.MAX_VALUE) == null)
    assertEquals("\\A/etc/passwd\\z", p.javaSource)
  }

  @Test
  fun negativeFlagScopeHoists() {
    val p = PyRe.compile("(?<![A-Za-z0-9+/])(?-i:rO0AB)", PyReFlags.DEFAULT)
    assertTrue(p.search("xx rO0AB", 0, Long.MAX_VALUE) != null)
    assertTrue(p.search("xx RO0AB", 0, Long.MAX_VALUE) == null)
  }

  @Test
  fun pythonNamedGroupsTranslateToJavaSpelling() {
    // python (?P<name>...) compiles; java needs (?<name>...). The safety_gates corpus uses the
    // python spelling (W5 regression: the verbatim translator skipped it and java rejected the
    // source with "Unknown inline modifier" before the structural checks could classify).
    val p = PyRe.compile("(?P<year>\\d{4})-(?P<day>\\d\\d)", 0)
    assertTrue(p.search("2026-10-10", 0, Long.MAX_VALUE) != null)
    assertTrue(p.search("20-1010", 0, Long.MAX_VALUE) == null)
    val named = PyRe.compile("(?P<a>ab)+c", 0)
    val m = named.search("ababc", 0, Long.MAX_VALUE)
    assertTrue(m != null)
    assertEquals("ab", m!!.group(1))
    // (?P=name) backreference -> \k<name>.
    val ref = PyRe.compile("(?P<x>\\w)\\1", 0)
    assertEquals(2, ref.groups) // 1 group + the initial sre counter
    assertTrue(ref.search("aa", 0, Long.MAX_VALUE) != null)
    assertTrue(ref.search("aA", 0, Long.MAX_VALUE) == null)
    val namedRef = PyRe.compile("(?P<w>\\w)(?P=w)", 0)
    assertTrue(namedRef.search("zz", 0, Long.MAX_VALUE) != null)
    assertTrue(namedRef.search("zx", 0, Long.MAX_VALUE) == null)
    // Inside a char class the (?P< spelling is literal text (python behavior).
    val inClass = PyRe.compile("[(?P<a>]", 0)
    assertTrue(inClass.search("P", 0, Long.MAX_VALUE) != null)
    assertTrue(inClass.search("a", 0, Long.MAX_VALUE) != null)
  }

  @Test
  fun pythonGrammarRejectsFailClosed() {
    val rejected =
        listOf(
            "(?>a)", // atomic group: python 3.10 rejects
            "a*+", // possessive: multiple repeat
            "\\1", // undefined group reference
            "(?P<name>a)(?P<name>b)", // duplicate group name
        )
    val expected =
        listOf("unknown extension", "multiple repeat", "invalid group reference", "redefinition")
    for ((index, pattern) in rejected.withIndex()) {
      try {
        PyRe.compile(pattern, 0)
        throw AssertionError("expected rejection: $pattern")
      } catch (e: ReParseError) {
        val want = expected[index]
        if (want != null) {
          assertTrue(e.messageText.contains(want), "$pattern: ${e.messageText}")
        }
      }
    }
  }

  @Test
  fun multipleRepeatIsRejected() {
    try {
      PyReParser.parse("a**", 0)
      throw AssertionError("expected multiple repeat")
    } catch (e: ReParseError) {
      assertTrue(e.messageText.contains("multiple repeat"))
    }
  }

  @Test
  fun nestedGroupCounting() {
    val parsed = PyReParser.parse("(a)(b)(c)", 0)
    assertEquals(4, parsed.groups) // 3 groups + the initial counter
  }

  @Test
  fun inlineFlagsScopeToTheGroup() {
    val p = PyRe.compile("(?i:abc)d", 0)
    assertTrue(p.search("ABCd", 0, Long.MAX_VALUE) != null)
    assertTrue(p.search("ABCD", 0, Long.MAX_VALUE) == null)
  }

  @Test
  fun finditerYieldsAllMatches() {
    val p = PyRe.compile("\\d+", 0)
    val matches = p.finditer("a1b22c333", Long.MAX_VALUE)
    assertEquals(3, matches.size)
    assertEquals("1", matches[0].group())
    assertEquals("22", matches[1].group())
    assertEquals("333", matches[2].group())
  }

  @Test
  fun matchAtAnchorsAtPosition() {
    val p = PyRe.compile("b", 0)
    assertNotNull(p.matchAt("ab", 1, 2, Long.MAX_VALUE))
    assertEquals(null, p.matchAt("ab", 0, 2, Long.MAX_VALUE))
  }

  @Test
  fun lookbehindSeesBeforePosition() {
    // CPython behavior: lookbehind at pos can inspect characters before pos.
    val p = PyRe.compile("(?<=x)a", 0)
    assertNotNull(p.matchAt("xa", 1, 2, Long.MAX_VALUE))
  }

  @Test
  fun wordBoundaryAnchors() {
    val p = PyRe.compile("\\bcat\\b", 0)
    assertTrue(p.search("a cat here", 0, Long.MAX_VALUE) != null)
    assertTrue(p.search("catalog", 0, Long.MAX_VALUE) == null)
  }

  @Test
  fun unicodeWordChars() {
    // python \w is unicode-aware by default; UNICODE_CHARACTER_CLASS mirrors it.
    val p = PyRe.compile("\\w+", PyReFlags.DEFAULT)
    assertTrue(p.search("héllo", 0, Long.MAX_VALUE) != null)
  }

  @Test
  fun dotExcludesOnlyNewline() {
    // UNIX_LINES makes java's dot python-exact (newline only, not CR).
    val p = PyRe.compile("a.b", 0)
    assertTrue(p.search("a\rb", 0, Long.MAX_VALUE) != null)
    assertTrue(p.search("a\nb", 0, Long.MAX_VALUE) == null)
  }
}
