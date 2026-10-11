package com.guardcore.util.py

import com.guardcore.util.IpExtraction
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of the stdlib-faithful tail behaviors: unicodedata lookup (PyUnicode), the difflib
 * SequenceMatcher internals (PyDiffLib via getCloseMatches and direct), the python ipaddress edge
 * arms (PyIp), json escapes/literals/errors (PyJson), and urllib parse arms (PyUrllib).
 */
class PyUnicodeTailTest {
  @Test
  fun testIsSpaceCodePoint() {
    assertTrue(PyUnicode.isSpaceCodePoint(0x09))
    assertTrue(PyUnicode.isSpaceCodePoint(0x2028))
    assertTrue(PyUnicode.isSpaceCodePoint(0x3000))
    assertEquals(false, PyUnicode.isSpaceCodePoint('a'.code))
  }

  @Test
  fun testLookupNamedCodepoint() {
    // Exact alias hits.
    assertEquals('\t', PyUnicode.lookupNamedCodepoint("TAB"))
    assertEquals('\n', PyUnicode.lookupNamedCodepoint("LF"))
    assertEquals(' ', PyUnicode.lookupNamedCodepoint("SPACE"))
    // Formal JVM name carries the "(COMMENT)" suffix; the prefix scan resolves it.
    assertEquals('\n', PyUnicode.lookupNamedCodepoint("LINE FEED"))
    assertEquals('\u00A0', PyUnicode.lookupNamedCodepoint("NBSP"))
    // Failed lookups return null (no gap, pair grammar outcome identical).
    assertNull(PyUnicode.lookupNamedCodepoint("NO SUCH NAME"))
    assertNull(PyUnicode.lookupNamedCodepoint("LATIN SMALL LETTER A"))
  }
}

class PyDiffLibTailTest {
  @Test
  fun testGetCloseMatchesMatchesAndMisses() {
    val matches = PyDiffLib.getCloseMatches("pasword", listOf("password", "passwd", "unrelated"))
    assertTrue("password" in matches, matches.toString())
    assertEquals(emptyList(), PyDiffLib.getCloseMatches("zzzz", listOf("aaaa", "bbbb")))
    assertEquals(emptyList(), PyDiffLib.getCloseMatches("", listOf("x", "y")))
  }

  @Test
  fun testGetCloseMatchesArgumentGuards() {
    assertFailsWith<IllegalArgumentException> {
      PyDiffLib.getCloseMatches("w", listOf("a"), n = 0)
    }
    assertFailsWith<IllegalArgumentException> {
      PyDiffLib.getCloseMatches("w", listOf("a"), cutoff = 1.5)
    }
  }

  @Test
  fun testSequenceMatcherAutojunkPopularElement() {
    // b >= 200 with a very popular element exercises the autojunk removal arm.
    val b = "a".repeat(250) + "b".repeat(3)
    val matcher = SequenceMatcher(a = "ab", b = b)
    val blocks = matcher.getMatchingBlocks()
    assertTrue(blocks.isNotEmpty())
    assertTrue(matcher.ratio() > 0.0)
  }

  @Test
  fun testSequenceMatcherSetSeq2CacheAndSameValue() {
    val matcher = SequenceMatcher(a = "abcd", b = "abcdef")
    val first = matcher.getMatchingBlocks()
    matcher.setSeq2("abcdef") // same value: cached, no recompute
    assertEquals(first, matcher.getMatchingBlocks())
    matcher.setSeq2("abcdefg")
    val second = matcher.getMatchingBlocks()
    assertTrue(second != first || first.isEmpty())
  }

  @Test
  fun testRatioAndQuickRatioArms() {
    val matcher = SequenceMatcher(a = "abcdef", b = "abXdef")
    assertTrue(matcher.realQuickRatio() >= matcher.quickRatio())
    assertTrue(matcher.quickRatio() >= matcher.ratio())
    assertTrue(matcher.ratio() > 0.0)
  }
}

class PyIpTailTest {
  @Test
  fun testIpv4MappedV6CanonicalText() {
    assertEquals("1.2.3.4", IpExtraction.canonicalizeIp("::ffff:0102:0304"))
    assertEquals("1.2.3.4", IpExtraction.canonicalizeIp("::ffff:1.2.3.4"))
  }

  @Test
  fun testScopeIdAddress() {
    val addr = parseAddress("fe80::1%eth0")
    assertTrue(addr is IPv6Address)
    assertEquals("fe80::1%eth0", addr.text)
    assertEquals("fe80::1%eth0", IpExtraction.canonicalizeIp("fe80::1%eth0"))
  }

  @Test
  fun testV6ParseErrorArms() {
    // ip_address() collapses every inner failure into the generic ValueError text; the
    // specific inner messages surface through parseV6NetworkValue (PyIp.kt:157), so drive
    // that entry directly.
    for ((bad, fragment) in
        listOf(
            "1:2:3/128" to "Exactly 8 parts",
            "1:2:3:4:5:6:7/128" to "Exactly 8 parts",
            "::1::2/128" to "At most one '::'",
            "1::2:3:4:5:6:7:8/128" to "Expected at most 8 other parts",
            ":1::2:3:4:5:6:7:8/128" to "Leading ':'",
            "1::2:3:4:5:6:/128" to "Trailing ':'",
            "12345::/128" to "1 to 4 hex digits",
            "::2:3:4:5:6:7:8:9/128" to "Only hex digits permitted",
        )) {
      val error =
          try {
            IPv6Address.parseV6NetworkValue(bad)
            null
          } catch (e: com.guardcore.errors.ConfigValidationError) {
            e
          }
      assertTrue(error != null, "$bad must be rejected")
      assertTrue(error!!.message?.contains(fragment) == true, "${error.message} for $bad")
    }
    // ip_address() itself collapses all of these into the generic python ValueError text.
    for (bad in listOf("1:2:3", "1:2:3:4:5:6:7:8:9", "::1::2", "12345::")) {
      val error =
          try {
            parseAddress(bad)
            null
          } catch (e: com.guardcore.errors.ConfigValidationError) {
            e
          }
      assertTrue(
          error!!.message?.contains("does not appear to be an IPv4 or IPv6 address") == true,
          "${error.message} for $bad",
      )
    }
  }

  @Test
  fun testEmbeddedIpv4ErrorRewrap() {
    val error =
        try {
          parseAddress("::ffff:1.2.3.999")
          null
        } catch (e: com.guardcore.errors.ConfigValidationError) {
          e
        }
    assertTrue(error != null)
    assertTrue(
        error!!.message?.contains("'::ffff:1.2.3.999'") == true,
        error.message,
    )
  }

  @Test
  fun testNetworkPrefixBounds() {
    assertFailsWith<com.guardcore.errors.ConfigValidationError> {
      IpNetwork.parse("1.2.3.4/33")
    }
    assertFailsWith<com.guardcore.errors.ConfigValidationError> {
      IpNetwork.parse("::1/129")
    }
    assertFailsWith<com.guardcore.errors.ConfigValidationError> {
      IpNetwork.parse("1.2.3.4/-1")
    }
  }

  @Test
  fun testAddressClassificationAndEquality() {
    val v4 = parseAddress("10.0.0.1")
    assertTrue(v4.isPrivate)
    assertEquals(4, v4.version)
    val v6 = parseAddress("fe80::1")
    assertTrue(v6.isLinkLocal)
    assertEquals(6, v6.version)
    assertEquals(v4, parseAddress("10.0.0.1"))
    assertTrue(v4.hashCode() != 0)
    assertTrue(v6.hashCode() != 0)
    assertEquals("10.0.0.1", v4.toString())
  }
}

class PyJsonTailTest {
  @Test
  fun testStringEscapeArms() {
    assertEquals("a\b", PyJson.loads("\"a\\b\""))
    assertEquals("a\u000C", PyJson.loads("\"a\\f\""))
    assertEquals("a\n", PyJson.loads("\"a\\n\""))
    assertEquals("a\r", PyJson.loads("\"a\\r\""))
    assertEquals("a\t", PyJson.loads("\"a\\t\""))
    assertEquals("a/c", PyJson.loads("\"a\\/c\""))
    assertEquals("é", PyJson.loads("\"\\u00e9\""))
    // Surrogate pair escape renders the astral character.
    assertEquals("😀", PyJson.loads("\"\\ud83d\\ude00\""))
  }

  @Test
  fun testLiteralsAndNumbers() {
    assertEquals(true, PyJson.loads("true"))
    assertEquals(false, PyJson.loads("false"))
    assertEquals(null, PyJson.loads("null"))
    assertTrue(PyJson.loads("NaN") is Double)
    assertEquals(Double.POSITIVE_INFINITY, PyJson.loads("Infinity") as Double)
    // Big integers beyond Long range take the BigInteger arm.
    assertEquals("123456789012345678901234567890", PyJson.loads("123456789012345678901234567890").toString())
  }

  @Test
  fun testErrorPositions() {
    val error =
        assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("{\n  bad}") }
    assertTrue(error.message?.contains("line 2") == true, error.message)
    assertTrue(error.message?.contains("(char ") == true, error.message)
    assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("\"unterminated") }
    assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("{} extra") }
  }
}

class PyUrllibTailTest {
  @Test
  fun testUnquotePlus() {
    assertEquals("a b", PyUrllib.unquotePlus("a+b"))
    assertEquals("a b", PyUrllib.unquotePlus("a%20b"))
    assertEquals("plain", PyUrllib.unquotePlus("plain"))
  }

  @Test
  fun testParseQsArms() {
    assertEquals(
        linkedMapOf("a" to listOf("1"), "b" to listOf("2")),
        PyUrllib.parseQs("a=1&b=2"),
    )
    // Blank pairs and value-less pairs are skipped; blank names kept.
    assertEquals(
        linkedMapOf("a" to listOf("1"), "" to listOf("x")),
        PyUrllib.parseQs("a=1&&=x&c"),
    )
  }

  @Test
  fun testUrlsplitCleansTabAndNewline() {
    val parts = PyUrllib.urlsplit("ht\ttp://a\nb/c")
    assertEquals("http", parts.scheme)
    assertEquals("ab", parts.netloc)
    assertEquals("/c", parts.path)
  }

  @Test
  fun testSplitResultToStringRoundtrip() {
    val parts = PyUrllib.urlsplit("https://user:pass@host:8080/p?q=1#f")
    assertEquals("https", parts.scheme)
    assertEquals("user:pass@host:8080", parts.netloc)
    assertEquals("/p", parts.path)
    assertEquals("q=1", parts.query)
    assertEquals("f", parts.fragment)
    assertEquals("https://user:pass@host:8080/p?q=1#f", parts.toString())
    assertEquals("q=1", PyUrllib.urlsplit("?q=1").query)
  }
}
