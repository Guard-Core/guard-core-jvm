package com.guardcore.engine.detection

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_pattern_validation_cache.py: the disk-backed cache for the pattern-safety
 * validator's empirical cost-verdict outcomes, plus the minimal JSON reader/writer it persists
 * through.
 */
class ValidationCacheTest {
  private fun newCache(path: Path): PatternValidationCache = PatternValidationCache(path, "4.3.2")

  @Test
  fun putThenGetRoundTrips() {
    val dir = Files.createTempDirectory("w9b-cache")
    val cache = newCache(dir.resolve("cache.json"))
    cache.put("a+", 0, true, "Pattern appears safe")
    assertEquals(Pair(true, "Pattern appears safe"), cache.get("a+", 0))
    assertEquals(1, cache.size)
  }

  @Test
  fun persistedFileSurvivesANewInstance() {
    val dir = Files.createTempDirectory("w9b-cache")
    val path = dir.resolve("cache.json")
    newCache(path).put("(x+x+)+y", 0, false, "over budget")
    val reopened = newCache(path)
    assertEquals(Pair(false, "over budget"), reopened.get("(x+x+)+y", 0))
  }

  @Test
  fun getMissReturnsNull() {
    val dir = Files.createTempDirectory("w9b-cache")
    val cache = newCache(dir.resolve("cache.json"))
    assertNull(cache.get("never-seen", 0))
  }

  @Test
  fun flagsArePartOfTheKey() {
    val dir = Files.createTempDirectory("w9b-cache")
    val cache = newCache(dir.resolve("cache.json"))
    cache.put("x", 0, true, "safe under flag 0")
    assertNull(cache.get("x", 8))
  }

  @Test
  fun versionMismatchEntriesAreDropped() {
    val dir = Files.createTempDirectory("w9b-cache")
    val path = dir.resolve("cache.json")
    Files.writeString(path, """{"k": {"safe": true, "reason": "stale", "version": "0.0.1"}}""")
    val cache = newCache(path)
    assertEquals(0, cache.size)
    assertNull(cache.get("anything", 0))
  }

  @Test
  fun corruptCacheStartsEmptyAndRecovers() {
    val dir = Files.createTempDirectory("w9b-cache")
    val path = dir.resolve("cache.json")
    Files.writeString(path, "{not json")
    val cache = newCache(path)
    assertEquals(0, cache.size)
    cache.put("b+", 0, true, "ok")
    assertEquals(Pair(true, "ok"), cache.get("b+", 0))
    assertEquals(Pair(true, "ok"), newCache(path).get("b+", 0))
  }

  @Test
  fun writeIsAtomicNoTmpLeftovers() {
    val dir = Files.createTempDirectory("w9b-cache")
    val path = dir.resolve("cache.json")
    val cache = newCache(path)
    cache.put("c+", 0, true, "ok")
    val leftovers = Files.list(dir).use { it.map { p -> p.fileName.toString() }.toList() }
    assertEquals(listOf("cache.json"), leftovers)
    assertTrue(Files.readString(path).contains("\"safe\":true"))
  }

  @Test
  fun missingEntryShapeIsRejected() {
    val dir = Files.createTempDirectory("w9b-cache")
    val path = dir.resolve("cache.json")
    Files.writeString(path, """{"k": {"version": "4.3.2", "safe": "yes"}}""")
    assertEquals(0, newCache(path).size)
  }

  @Test
  fun unreadableCachePathStartsEmpty() {
    val dir = Files.createTempDirectory("w9b-cache")
    val cache = newCache(dir.resolve("cache-dir").also { Files.createDirectory(it) })
    assertEquals(0, cache.size)
    cache.put("d+", 0, true, "ok")
    assertEquals(Pair(true, "ok"), cache.get("d+", 0))
  }

  @Test
  fun nonObjectCacheRootStartsEmpty() {
    val dir = Files.createTempDirectory("w9b-cache")
    val path = dir.resolve("cache.json")
    Files.writeString(path, "[1, 2, 3]")
    assertEquals(0, newCache(path).size)
  }

  @Test
  fun nonObjectCacheEntryRejectsTheWholeFile() {
    val dir = Files.createTempDirectory("w9b-cache")
    val path = dir.resolve("cache.json")
    Files.writeString(path, """{"k": "not-a-dict"}""")
    assertEquals(0, newCache(path).size)
  }

  @Test
  fun entryWithoutABooleanVerdictRejectsTheFile() {
    val dir = Files.createTempDirectory("w9b-cache")
    val path = dir.resolve("cache.json")
    Files.writeString(path, """{"k": {"version": "4.3.2", "reason": "x"}}""")
    assertEquals(0, newCache(path).size)
  }

  @Test
  fun entryWithoutAStringReasonRejectsTheFile() {
    val dir = Files.createTempDirectory("w9b-cache")
    val path = dir.resolve("cache.json")
    Files.writeString(path, """{"k": {"version": "4.3.2", "safe": true}}""")
    assertEquals(0, newCache(path).size)
  }

  @Test
  fun emptyCacheFileParsesToNothing() {
    val dir = Files.createTempDirectory("w9b-cache")
    val path = dir.resolve("cache.json")
    Files.writeString(path, "")
    assertEquals(0, newCache(path).size)
  }

  // ---- JsonMini (the python json.loads/json.dumps analog) ----

  @Test
  fun jsonMiniParsesNestedStructures() {
    val raw =
        """{"a": 1, "b": -2, "c": 1.5, "d": [true, false, null, "s", []], "e": {}, "f": 1e3}"""
    val parsed = JsonMini.parseObject(raw)
    assertNotNull(parsed)
    assertEquals(1L, parsed["a"])
    assertEquals(-2L, parsed["b"])
    assertEquals(1.5, parsed["c"])
    // JSON null parses to the sentinel (python json.loads yields None there).
    assertEquals(
        listOf<Any?>(true, false, JsonMini.JsonNull, "s", emptyList<Any>()),
        parsed["d"],
    )
    assertEquals(emptyMap<String, Any>(), parsed["e"])
    assertEquals(1000.0, parsed["f"])
  }

  @Test
  fun jsonMiniParsesStringEscapes() {
    val parsed = JsonMini.parseObject("""{"k": "a\nb\rc\td\\e\"f\u0041"}""")
    assertNotNull(parsed)
    assertEquals("a\nb\rc\td\\e\"fA", parsed["k"])
  }

  @Test
  fun jsonMiniRejectsNonObjectRootsAndBlankInput() {
    assertNull(JsonMini.parseObject("[1,2]"))
    assertNull(JsonMini.parseObject("\"scalar\""))
    assertNull(JsonMini.parseObject(""))
    assertNull(JsonMini.parseObject("   "))
  }

  @Test
  fun jsonMiniAppendsEveryValueKind() {
    val sb = StringBuilder()
    JsonMini.appendValue(sb, null)
    JsonMini.appendValue(sb, "q\"r")
    JsonMini.appendValue(sb, true)
    JsonMini.appendValue(sb, false)
    JsonMini.appendValue(sb, 7)
    JsonMini.appendValue(sb, 9L)
    JsonMini.appendValue(sb, 2.5)
    JsonMini.appendValue(sb, linkedMapOf("k" to 1))
    JsonMini.appendValue(sb, listOf(1, "two"))
    JsonMini.appendValue(sb, "ctrl\u0000x")
    assertEquals(
        """null"q\"r"truefalse792.5{"k":1}[1,"two"]"ctrl\u0000x"""",
        sb.toString(),
    )
  }

  @Test
  fun jsonMiniEscapesControlCharactersAsUnicode() {
    val sb = StringBuilder()
    JsonMini.appendValue(sb, "\u0001\u0006")
    assertEquals("\"\\u0001\\u0006\"", sb.toString())
  }

  @Test
  fun jsonMiniObjectToStringRoundTripsThroughTheParser() {
    val entries = linkedMapOf<String, HashMap<String, Any>>()
    entries["p"] =
        hashMapOf<String, Any>(
            "safe" to true,
            "reason" to "multi\nline",
            "version" to "4.3.2",
        )
    val rendered = JsonMini.objectToString(entries)
    val parsed = JsonMini.parseObject(rendered)
    assertNotNull(parsed)
    val entry = parsed["p"] as Map<*, *>
    assertEquals(true, entry["safe"])
    assertEquals("multi\nline", entry["reason"])
    assertEquals("4.3.2", entry["version"])
    assertFalse(rendered.isEmpty())
  }
}
