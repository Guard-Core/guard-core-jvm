package com.guardcore.util

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Ports of tests/test_utils/test_logging.py core sanitizing/redaction traversal cases. */
class LoggingUtilsTest {
  @Test
  fun testSanitizeForLogControlChars() {
    // logging_utils.py:20-40.
    assertEquals("a\\nb", LoggingUtils.sanitizeForLog("a\nb"))
    assertEquals("line\\r", LoggingUtils.sanitizeForLog("line\r"))
    assertEquals("tab\\t", LoggingUtils.sanitizeForLog("tab\t"))
    assertEquals("x\\u0000", LoggingUtils.sanitizeForLog("x\\u0000"))
    // Non-ASCII becomes \uXXXX of the code point.
    assertEquals("\\u00e9", LoggingUtils.sanitizeForLog("é"))
    assertEquals("\\u1f600", LoggingUtils.sanitizeForLog("😀"))
  }

  @Test
  fun testSanitizeForReportingAsciiStays() {
    assertEquals("plain", LoggingUtils.sanitizeForReporting("plain"))
  }

  @Test
  fun testRedactSensitiveJsonKeyRedaction() {
    val parsed =
        linkedMapOf<String, Any?>(
            "password" to "hunter2",
            "user" to "alice",
            "nested" to linkedMapOf<String, Any?>("api_key" to "xyz", "keep" to 1),
        )
    val redacted =
        LoggingUtils.redactSensitiveJson(parsed, emptySet(), setOf("password", "api_key"), 32)
    assertEquals("[REDACTED]", (redacted as Map<*, *>)["password"])
    assertEquals("alice", redacted["user"])
    val nested = redacted["nested"] as Map<*, *>
    assertEquals("[REDACTED]", nested["api_key"])
    assertEquals(1, nested["keep"])
    // Source map untouched (iterative copy).
    assertEquals("hunter2", parsed["password"])
  }

  @Test
  fun testRedactSensitiveJsonDepthCap() {
    val deep: MutableMap<String, Any?> =
        linkedMapOf("a" to linkedMapOf<String, Any?>("b" to linkedMapOf<String, Any?>("c" to "d")))
    LoggingUtils.jsonDepthCapHit.set(false)
    val redacted = LoggingUtils.redactSensitiveJson(deep, emptySet(), emptySet(), 3) as Map<*, *>
    // Depth cap collapses the level-3 container and raises the hit flag.
    assertTrue(LoggingUtils.jsonDepthCapHit.get())
    val level2 = redacted["a"] as Map<*, *>
    assertEquals("[REDACTED]", level2["b"])
  }

  @Test
  fun testRedactSensitiveJsonScalarPassthrough() {
    assertEquals("str", LoggingUtils.redactSensitiveJson("str", emptySet(), emptySet(), 32))
    assertEquals(5L, LoggingUtils.redactSensitiveJson(5L, emptySet(), emptySet(), 32))
  }

  @Test
  fun testRedactSensitiveJsonMaxDepthOneCollapsesAll() {
    // logging_utils.py:135: max_depth <= 1 redacts the whole value.
    val parsed = linkedMapOf<String, Any?>("a" to "b")
    assertEquals("[REDACTED]", LoggingUtils.redactSensitiveJson(parsed, emptySet(), emptySet(), 1))
  }

  @Test
  fun testJsonStringLeafNestedJson() {
    // _redact_json_string_leaf: a leaf whose value is itself JSON gets the
    // nested traversal.
    val inner = com.guardcore.util.py.PyJson.dumps(linkedMapOf("token" to "abc"))
    val outer = com.guardcore.util.py.PyJson.dumps(linkedMapOf("leaf" to inner))
    val redacted = RequestLogging.redactBlobForDisplay(outer, null, null)
    assertTrue("abc" !in redacted, redacted)
  }
}
