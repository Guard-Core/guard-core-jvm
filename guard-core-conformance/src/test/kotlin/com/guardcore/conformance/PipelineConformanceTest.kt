package com.guardcore.conformance

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The W4a pipeline gate: pipeline_detection_response (8), pipeline_ip_control (12),
 * pipeline_rate_limits (5), pipeline_headers_cors (7), pipeline_behavior_rules (3) = 35 cases,
 * compared under the index.json contract.
 *
 * Contract (conformance/guard-core-spec-4.1.0/cases/index.json):
 * - pipeline_records: "compare only the keys present in each expected record; a runner that cannot
 *   observe the engine event bus skips the events key instead of failing it"
 * - float_precision 6 (no floats compared in pipeline records)
 * - execution_time dropped (not part of pipeline records)
 */
public class PipelineConformanceTest {
  public data class CaseFailure(
      val suite: String,
      val caseId: String,
      val reason: String,
  )

  public companion object {
    /** The five pipeline suites from the index (kind == "pipeline"). */
    public fun pipelineSuites(): List<String> {
      val idx = DetectRunner.index()
      val suites = idx.getValue("suites").jsonObject
      return suites.entries
          .filter { it.value.jsonObject.getValue("kind").jsonPrimitive.content == "pipeline" }
          .map { it.key }
          .sorted()
    }

    /** Deep-equality per the records rule: only keys present in expected are compared. */
    public fun recordsMatch(expected: Any?, actual: Any?): Boolean {
      return when {
        expected is Map<*, *> && actual is Map<*, *> ->
            expected.entries.all { (key, value) ->
              actual.containsKey(key) && recordsMatch(value, actual[key])
            }
        expected is List<*> && actual is List<*> ->
            expected.size == actual.size &&
                expected.zip(actual).all { (e, a) -> recordsMatch(e, a) }
        else -> expected == actual
      }
    }

    public fun render(value: Any?): String =
        when (value) {
          null -> "null"
          is Map<*, *> -> value.entries.joinToString(",", "{", "}") { (k, v) -> "$k: ${render(v)}" }
          is List<*> -> value.joinToString(",", "[", "]") { render(it) }
          else -> value.toString()
        }

    /** Runs every pipeline suite; returns per-case failures (empty = all 35 match). */
    public fun runAll(): List<CaseFailure> {
      val corpus = DetectRunner.corpusDir()
      val failures = ArrayList<CaseFailure>()
      for (suite in pipelineSuites()) {
        val suiteJson =
            Json.parseToJsonElement(
                    java.nio.file.Files.readString(corpus.resolve("$suite.json")),
                )
                .jsonObject
        for (case in suiteJson.getValue("cases").jsonArray) {
          val caseObj = case.jsonObject
          val caseId = caseObj.getValue("id").jsonPrimitive.content
          val caseMap = JsonElementCaseAdapter.toMap(caseObj)
          try {
            val actual = PipelineHarness.runCase(caseMap)
            val expected = caseObj.getValue("expected").jsonArray
            if (actual.size != expected.size) {
              failures.add(
                  CaseFailure(
                      suite,
                      caseId,
                      "drive count: expected ${expected.size} got ${actual.size}",
                  ),
              )
              continue
            }
            var mismatch: String? = null
            for ((i, exp) in expected.withIndex()) {
              val expRecord = JsonElementCaseAdapter.toMap(exp)
              val actRecord = actual[i]
              if (!recordsMatch(expRecord, actRecord)) {
                mismatch = "drive[$i]: expected ${render(expRecord)} got ${render(actRecord)}"
                break
              }
            }
            mismatch?.let { failures.add(CaseFailure(suite, caseId, it)) }
          } catch (e: Throwable) {
            var root: Throwable = e
            while (root.cause != null && root.cause !== root) root = root.cause!!
            val frames =
                root.stackTrace.take(6).joinToString(" | ") {
                  it.className.substringAfterLast(".") + "." + it.methodName
                }
            failures.add(
                CaseFailure(
                    suite,
                    caseId,
                    "threw ${e::class.simpleName}: ${e.message} | root " +
                        "${root::class.simpleName}: ${root.message} @ $frames",
                ),
            )
          }
        }
      }
      return failures
    }
  }

  @Test
  fun pipelineSuitesMatchCorpus() {
    val failures = runAll()
    val count =
        pipelineSuites().sumOf { suite ->
          val corpus = DetectRunner.corpusDir()
          Json.parseToJsonElement(java.nio.file.Files.readString(corpus.resolve("$suite.json")))
              .jsonObject
              .getValue("cases")
              .jsonArray
              .size
        }
    if (failures.isNotEmpty()) {
      fail(
          "${failures.size}/$count pipeline cases failed:\n" +
              failures.joinToString("\n") { "  ${it.suite}/${it.caseId}: ${it.reason}" },
      )
    }
    assertEquals(35, count, "pipeline suite case count drift")
  }
}

/** kotlinx-serialization to plain Kotlin map adapter for the harness. */
internal object JsonElementCaseAdapter {
  public fun toMap(element: kotlinx.serialization.json.JsonElement): Map<String, Any?> =
      when (element) {
        is kotlinx.serialization.json.JsonObject -> element.mapValues { (_, v) -> convert(v) }
        else -> error("expected object")
      }

  public fun convert(element: kotlinx.serialization.json.JsonElement): Any? =
      when (element) {
        is kotlinx.serialization.json.JsonObject -> element.mapValues { (_, v) -> convert(v) }
        is kotlinx.serialization.json.JsonArray -> element.map { convert(it) }
        is kotlinx.serialization.json.JsonPrimitive ->
            when {
              element.isString -> element.content
              element.content == "null" -> null
              element.content == "true" -> true
              element.content == "false" -> false
              else ->
                  element.content.toLongOrNull()?.let {
                    if (it in Int.MIN_VALUE..Int.MAX_VALUE) it.toInt() else it
                  } ?: element.content.toDoubleOrNull() ?: element.content
            }
      }
}
