package com.guardcore.util

import com.guardcore.util.py.PyDiffLib
import com.guardcore.util.py.PyJson
import com.guardcore.util.py.PyUrllib
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Ports of the CPython urllib / json / difflib probe behaviors. */
class PyStdlibTest {
  // ---------------------------------------------------------- unquote

  @Test
  fun testUnquote() {
    assertEquals("a%zz", PyUrllib.unquote("a%zz"))
    assertEquals("a%2zb", PyUrllib.unquote("a%2zb"))
    assertEquals("AB", PyUrllib.unquote("%41%42"))
    assertEquals("é", PyUrllib.unquote("%C3%A9"))
    assertEquals("\uFFFD", PyUrllib.unquote("%FF"))
    assertEquals("%4", PyUrllib.unquote("%4"))
    assertEquals("a+b", PyUrllib.unquote("a+b"))
    assertEquals("a b c", PyUrllib.unquotePlus("a+b%20c"))
    assertEquals("", PyUrllib.unquote(""))
    assertEquals("100% loaded", PyUrllib.unquote("100% loaded"))
    assertEquals("%A", PyUrllib.unquote("%%41"))
    assertEquals("%", PyUrllib.unquote("%"))
    assertEquals("%%", PyUrllib.unquote("%%"))
    assertEquals("é\uFFFDA", PyUrllib.unquote("%C3%A9%FF%41"))
    assertEquals("++", PyUrllib.unquote("+%2B"))
  }

  @Test
  fun testQuote() {
    assertEquals("a%20b%2Fc%3Fd%3De", PyUrllib.quote("a b/c?d=e", safe = ""))
    assertEquals("abc/~_.-", PyUrllib.quote("abc/~_.-"))
    assertEquals("%C3%A9", PyUrllib.quote("é", safe = ""))
    assertEquals("a%2Bb", PyUrllib.quote("a+b", safe = ""))
    assertEquals("a%2Bb", PyUrllib.quote("a+b"))
  }

  @Test
  fun testUrlSplitRoundTrip() {
    val split = PyUrllib.urlsplit("https://user:pw@host:8080/p/q?x=1#frag")
    assertEquals("https", split.scheme)
    assertEquals("user:pw@host:8080", split.netloc)
    assertEquals("/p/q", split.path)
    assertEquals("x=1", split.query)
    assertEquals("frag", split.fragment)
    assertEquals(
        "/path/only?a=1",
        PyUrllib.urlsplit("/path/only?a=1").let {
          PyUrllib.urlunsplit(it.scheme, it.netloc, it.path, it.query, it.fragment)
        },
    )
    assertEquals("host", PyUrllib.urlsplit("//host/path").netloc)
    assertEquals("x@y", PyUrllib.urlsplit("mailto:x@y").path)
    assertEquals("https://host/p?a=1#f", PyUrllib.urlunsplit("https", "host", "/p", "a=1", "f"))
    assertEquals("/p", PyUrllib.urlunsplit("", "", "/p", "", ""))
    assertEquals("https:///p", PyUrllib.urlunsplit("https", "", "/p", "", ""))
    // Tab/newline removal mirrors CPython.
    assertEquals("/abc", PyUrllib.urlsplit("/a\tb\nc").path)
  }

  // ------------------------------------------------------------- json

  @Test
  fun testJsonLoads() {
    assertEquals(1L, PyJson.loads("1"))
    assertEquals(0L, PyJson.loads("-0"))
    assertEquals(100000.0, PyJson.loads("1e5"))
    assertEquals(Double.POSITIVE_INFINITY, PyJson.loads("1e999"))
    assertTrue(PyJson.loads("NaN") is Double && (PyJson.loads("NaN") as Double).isNaN())
    assertTrue(PyJson.loads("null") == null)
    assertEquals(true, PyJson.loads("true"))
    assertEquals("a", PyJson.loads("\"a\""))
    assertEquals("\uD83D\uDE00", PyJson.loads("\"\\ud83d\\ude00\""))
    assertEquals("\uD83D", PyJson.loads("\"\\ud83d\""))
    assertEquals(emptyMap<Any?, Any?>(), PyJson.loads("{}"))
    assertEquals(emptyList<Any?>(), PyJson.loads("[]"))
    assertEquals(linkedMapOf("a" to 2L), PyJson.loads("{\"a\":1,\"a\":2}"))
    assertEquals(listOf(1L), PyJson.loads("  [1]  "))
    // BigInteger passthrough for huge integers.
    assertEquals("100000000000000000000", PyJson.loads("100000000000000000000").toString())
    assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("{\"a\": 1,}") }
    assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("[1, 2") }
    assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("01") }
    assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("1.") }
    assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("[1,2,]") }
    assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("[1] x") }
  }

  @Test
  fun testJsonDumps() {
    assertEquals(
        "{\"a\":1,\"b\":[1.0,2.5,\"x\",null,true]}",
        PyJson.dumps(linkedMapOf("a" to 1L, "b" to listOf(1.0, 2.5, "x", null, true))),
    )
    assertEquals("\"é\"", PyJson.dumps("é", ensureAscii = false))
    assertEquals("\"\\u00e9\"", PyJson.dumps("é", ensureAscii = true))
    assertEquals("1e+30", PyJson.dumps(1e30))
    assertEquals("0.1", PyJson.dumps(0.1))
    assertEquals("100.0", PyJson.dumps(100.0))
    assertEquals("1e+16", PyJson.dumps(1e16))
    assertEquals("1000000000000000.0", PyJson.dumps(1e15))
    assertEquals("0.0001", PyJson.dumps(0.0001))
    assertEquals("1e-05", PyJson.dumps(0.00001))
    assertEquals("0.0", PyJson.dumps(0.0))
    assertEquals("-0.0", PyJson.dumps(-0.0))
    assertEquals("NaN", PyJson.dumps(Double.NaN))
    assertEquals("Infinity", PyJson.dumps(Double.POSITIVE_INFINITY))
    assertEquals("\"tab\\there\"", PyJson.dumps("tab\there"))
    assertEquals("\"\\u0000\"", PyJson.dumps("\u0000", ensureAscii = false))
    // ensure_ascii=True escapes non-ASCII, False does not.
    assertEquals("\"\\u2028\"", PyJson.dumps("\u2028", ensureAscii = true))
    assertEquals("\"\u2028\"", PyJson.dumps("\u2028", ensureAscii = false))
    // Sorted keys mirror sort_keys=True.
    assertEquals(
        "{\"a\":2,\"b\":1}",
        PyJson.dumps(linkedMapOf("b" to 1L, "a" to 2L), sortKeys = true),
    )
  }

  // ---------------------------------------------------------- difflib

  @Test
  fun testGetCloseMatchesFieldNames() {
    val known = listOf("trusted_proxies", "trust_x_forwarded_proto", "trusted_proxy_depth")
    assertEquals(
        listOf("trusted_proxies"),
        PyDiffLib.getCloseMatches("truste_proxies", known, n = 1),
    )
    assertTrue(PyDiffLib.getCloseMatches("zzzz", known, n = 1).isEmpty())
  }
}
