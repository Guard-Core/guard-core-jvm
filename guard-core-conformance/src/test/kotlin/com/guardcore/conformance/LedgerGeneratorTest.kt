package com.guardcore.conformance

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.suspatterns.PATTERN_DEFINITIONS
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import kotlin.test.Test
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Emits conformance/pattern_ledger.json when guardcore.update.ledger=1; a no-op otherwise. */
class LedgerGeneratorTest {
  private fun repoRoot(): Path {
    var dir = Path.of(System.getProperty("user.dir"))
    while (
        !Files.exists(dir.resolve("conformance").resolve("guard-core-spec-4.1.0").resolve("cases"))
    ) {
      dir = dir.parent ?: error("repo root not found")
    }
    return dir
  }

  private fun escape(s: String): String {
    val sb = StringBuilder()
    for (c in s) {
      when (c) {
        '"' -> sb.append("\\\"")
        '\\' -> sb.append("\\\\")
        '\n' -> sb.append("\\n")
        '\r' -> sb.append("\\r")
        '\t' -> sb.append("\\t")
        else -> if (c.code < 0x20) sb.append("\\u%04x".format(c.code)) else sb.append(c)
      }
    }
    return sb.toString()
  }

  private fun classify(source: String): Pair<String, String?> {
    val javaSource = PyRe.translateSource(source)
    val asIs =
        try {
          java.util.regex.Pattern.compile(source)
          true
        } catch (e: Exception) {
          false
        }
    if (asIs) return Pair("as_is", null)
    try {
      java.util.regex.Pattern.compile(javaSource)
      return Pair("translated", javaSource)
    } catch (e: Exception) {
      return Pair("unmatchable", null)
    }
  }

  @Test
  fun updateLedger() {
    if (System.getProperty("guardcore.update.ledger") != "1") return
    val corpus = DetectRunner.corpusDir(repoRoot())
    val patterns = LinkedHashMap<String, MutableSet<String>>()
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
          patterns.getOrPut(pattern) { LinkedHashSet() }.add("$suite::$caseId")
        }
      }
    }
    PATTERN_DEFINITIONS.forEachIndexed { index, (source, _, category) ->
      patterns.getOrPut(source) { LinkedHashSet() }.add("table[$index]:$category")
    }

    // Sort for a deterministic file: table rows in table order, then corpus-only patterns
    // sorted by their first evidence string.
    val tableOrder = LinkedHashMap<String, Int>()
    PATTERN_DEFINITIONS.forEachIndexed { index, (source, _, _) -> tableOrder[source] = index }
    val ordered =
        patterns.entries
            .sortedWith(
                compareBy(
                    { tableOrder[it.key] ?: Int.MAX_VALUE },
                    { it.value.sorted().firstOrNull() ?: "" },
                ),
            )
            .map { it.key }

    val sb = StringBuilder()
    sb.append("{\n")
    sb.append(" \"spec_version\": \"4.1.0\",\n")
    val engineNote =
        "java.util.regex (JDK 17) behind com.guardcore.engine.py.PyRe: python-grammar " +
            "fail-closed parse, then translateSource (\\Z to \\z, (?P< to (?<, {,n} to " +
            "{0,n}, python-literal braces escaped, (?-i:...) flag hoisting) with the flag " +
            "mapping UNIX_LINES|UNICODE_CHARACTER_CLASS(+CI/ML/DOTALL/COMMENTS); match " +
            "execution on the 512 MiB-stack scan pool under the DeadlineCharSequence hard " +
            "deadline"
    sb.append(" \"engine\": \"${escape(engineNote)}\",\n")
    sb.append(
        " \"how_to_regenerate\": \"GUARD_UPDATE_LEDGER=1 ./gradlew :guard-core-conformance:test --tests com.guardcore.conformance.LedgerGeneratorTest --rerun-tasks\"\n",
    )
    val asIs = ordered.count { classify(it).first == "as_is" }
    val translated = ordered.count { classify(it).first == "translated" }
    val unmatchable = ordered.count { classify(it).first == "unmatchable" }
    sb.append(
        ",\"counts\": {\"total\": ${ordered.size}, \"as_is\": $asIs, \"translated\": $translated, \"unmatchable\": $unmatchable}",
    )
    sb.append(",\n \"entries\": [\n")
    ordered.forEachIndexed { index, pattern ->
      val (status, translation) = classify(pattern)
      val evidence = patterns[pattern]!!.sorted()
      sb.append("  {\n")
      sb.append("   \"pattern\": \"${escape(pattern)}\",\n")
      sb.append("   \"category\": \"${escape(evidence.first().substringBefore("::"))}\",\n")
      if (translation != null) {
        sb.append("   \"translated_source\": \"${escape(translation)}\",\n")
      }
      sb.append("   \"status\": \"$status\",\n")
      sb.append(
          "   \"evidence_cases\": [" + evidence.joinToString(", ") { "\"${escape(it)}\"" } + "]\n",
      )
      sb.append("  }" + if (index == ordered.size - 1) "\n" else ",\n")
    }
    sb.append(" ]\n}\n")

    val target = repoRoot().resolve("conformance").resolve("pattern_ledger.json")
    val tmp = Files.createTempFile(target.parent, ".ledger-", ".tmp")
    Files.writeString(tmp, sb.toString())
    Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    println("ledger written: ${ordered.size} entries")
  }
}
