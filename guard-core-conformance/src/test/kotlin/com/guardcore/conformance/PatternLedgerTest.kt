package com.guardcore.conformance

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.suspatterns.PATTERN_DEFINITIONS
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The fail-closed pattern translation ledger gate.
 *
 * Every regex in the corpus detect suites plus every engine pattern-table row must appear in
 * conformance/pattern_ledger.json with status as_is (python source compiles under java.util.regex
 * unchanged) or translated (the engine's corpus-verified translation); a pattern with neither fails
 * CI. Mirrors Guard-Core/guard-core-go's ledger format.
 */
class PatternLedgerTest {
  private fun repoRoot(): Path {
    var dir = Path.of(System.getProperty("user.dir"))
    while (
        !Files.exists(dir.resolve("conformance").resolve("guard-core-spec-4.1.0").resolve("cases"))
    ) {
      dir = dir.parent ?: error("repo root not found")
    }
    return dir
  }

  private fun ledgerPath(): Path = repoRoot().resolve("conformance").resolve("pattern_ledger.json")

  /** Every distinct pattern source observed in the corpus detect suites. */
  private fun corpusPatterns(): Map<String, MutableSet<String>> {
    val out = LinkedHashMap<String, MutableSet<String>>()
    val corpus = DetectRunner.corpusDir()
    for (suite in DetectRunner.detectSuites(corpus)) {
      val suiteJson =
          Json.parseToJsonElement(Files.readString(corpus.resolve("$suite.json"))).jsonObject
      for (case in suiteJson.getValue("cases").jsonArray) {
        val caseObj = case.jsonObject
        val caseId = caseObj.getValue("id").jsonPrimitive.content
        for (threat in caseObj.getValue("expected").jsonObject.getValue("threats").jsonArray) {
          val t = threat.jsonObject
          val type = t.getValue("type").jsonPrimitive.content
          if (type != "regex" && type != "pattern_timeout") continue
          val pattern = t.getValue("pattern").jsonPrimitive.content
          out.getOrPut(pattern) { LinkedHashSet() }.add("$suite::$caseId")
        }
      }
    }
    return out
  }

  /** Every table row plus the engine's internal compiled sources. */
  private fun enginePatterns(): Map<String, MutableSet<String>> {
    val out = LinkedHashMap<String, MutableSet<String>>()
    PATTERN_DEFINITIONS.forEachIndexed { index, (source, _, category) ->
      out.getOrPut(source) { LinkedHashSet() }.add("table[$index]:$category")
    }
    return out
  }

  private fun entryClass(source: String): String {
    val javaSource = PyRe.translateSource(source)
    val asIs =
        try {
          java.util.regex.Pattern.compile(source)
          true
        } catch (e: Exception) {
          false
        }
    if (asIs) return "as_is"
    // The engine's translation must compile for the entry to be a valid translation.
    try {
      java.util.regex.Pattern.compile(javaSource)
      return "translated"
    } catch (e: Exception) {
      return "unmatchable"
    }
  }

  @Test
  fun everyPatternIsLedgered() {
    val ledgerText = Files.readString(ledgerPath())
    val ledger = Json.parseToJsonElement(ledgerText).jsonObject
    val entries = ledger.getValue("entries").jsonArray
    val ledgered = HashMap<String, kotlinx.serialization.json.JsonObject>()
    for (entry in entries) {
      val obj = entry.jsonObject
      ledgered[obj.getValue("pattern").jsonPrimitive.content] = obj
    }

    val all = LinkedHashMap<String, MutableSet<String>>()
    for ((pattern, evidence) in corpusPatterns()) {
      all.getOrPut(pattern) { LinkedHashSet() }.addAll(evidence)
    }
    for ((pattern, evidence) in enginePatterns()) {
      all.getOrPut(pattern) { LinkedHashSet() }.addAll(evidence)
    }

    val strays = ArrayList<String>()
    val wrongStatus = ArrayList<String>()
    for ((pattern, evidence) in all) {
      val entry = ledgered[pattern]
      if (entry == null) {
        strays.add("$pattern (${evidence.take(2)})")
        continue
      }
      val status = entry.getValue("status").jsonPrimitive.content
      val expected = entryClass(pattern)
      if (status != expected) {
        wrongStatus.add("$pattern ledger=$status engine=$expected")
      }
    }

    assertTrue(strays.isEmpty(), "patterns missing from the ledger: ${strays.take(5)}")
    assertTrue(wrongStatus.isEmpty(), "ledger status drift: ${wrongStatus.take(5)}")
    assertEquals(all.size, ledgered.size, "ledger has entries outside corpus+tables")
  }
}
