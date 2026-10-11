package com.guardcore.conformance

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The W4b events gate: event_stream (39 cases, 38 pinning 47 envelopes + 1 xfail advisory),
 * compared under the index.json contract.
 *
 * Contract (conformance/guard-core-spec-4.1.0/cases/index.json):
 * - events_envelopes: only the keys present in each expected envelope are compared; volatile fields
 *   dropped recursively (events_volatile_fields); xfail cases advisory.
 * - float_precision 6.
 *
 * Documented divergences live in conformance/jvm_events_xfail.json with the fail-closed drift
 * semantics of the TS family ledger: failing-not-listed is red, listed-but-passing is red (stale
 * entry), and an entry whose recorded diff no longer matches the mechanical diff is red. The two
 * entries are reason-string shapes (a Python exception class name and Python redis-driver error
 * text embedded in reference reason strings), the same divergence class the TS family ledger
 * carries - not missing emitters.
 */
public class EventsConformanceTest {
  public data class CaseFailure(
      val suite: String,
      val caseId: String,
      val reason: String,
  )

  public companion object {
    private const val LEDGER_RESOURCE = "/jvm_events_xfail.json"

    /** The single events-kind suite from the index. */
    public fun eventsSuites(): List<String> {
      val idx = DetectRunner.index()
      val suites = idx.getValue("suites").jsonObject
      return suites.entries
          .filter { it.value.jsonObject.getValue("kind").jsonPrimitive.content == "events" }
          .map { it.key }
          .sorted()
    }

    @Suppress("UNCHECKED_CAST")
    public fun loadLedger(): Map<String, String> {
      val text =
          EventsConformanceTest::class
              .java
              .getResourceAsStream(LEDGER_RESOURCE)
              ?.bufferedReader()
              ?.readText() ?: error("missing $LEDGER_RESOURCE")
      val obj = Json.parseToJsonElement(text).jsonObject
      val cases = obj.getValue("cases").jsonObject
      return cases.entries.associate { it.key to it.value.jsonPrimitive.content }
    }

    /** Runs every events suite; returns per-case failures (empty = all match or ledgered). */
    public fun runAll(): List<CaseFailure> {
      val corpus = DetectRunner.corpusDir()
      val ledger = loadLedger()
      val recorded = HashMap<String, String>()
      val failures = ArrayList<CaseFailure>()
      var ran = 0
      for (suite in eventsSuites()) {
        val suiteJson =
            Json.parseToJsonElement(Files.readString(corpus.resolve("$suite.json"))).jsonObject
        for (case in suiteJson.getValue("cases").jsonArray) {
          val caseObj = case.jsonObject
          val caseId = caseObj.getValue("id").jsonPrimitive.content
          val key = "$suite/$caseId"
          val advisory = caseObj["xfail"]?.let { it.jsonPrimitive.content == "true" } ?: false
          ran += 1
          val expected = caseObj.getValue("expected").jsonArray
          val observed =
              try {
                EventsHarness.runCase(JsonElementCaseAdapter.toMap(caseObj))
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
                continue
              }
          if (advisory) {
            // Advisory cases carry no expectations (index.json events_envelopes rule).
            continue
          }
          val expectedMaps = expected.map { JsonElementCaseAdapter.toMap(it) }
          val diffs = EventsComparison.streamDiffs(expectedMaps, observed)
          if (diffs.isEmpty()) {
            if (ledger.containsKey(key)) {
              failures.add(
                  CaseFailure(suite, caseId, "listed in the xfail ledger but now passes (stale)"),
              )
            }
            continue
          }
          val mechanical = diffs.joinToString("; ")
          recorded[key] = mechanical
          val ledgered = ledger[key]
          when {
            ledgered == null -> failures.add(CaseFailure(suite, caseId, mechanical))
            ledgered != mechanical ->
                failures.add(
                    CaseFailure(
                        suite,
                        caseId,
                        "ledgered diff drifted; ledger says: $ledgered; observed: $mechanical",
                    ),
                )
          }
        }
      }
      for (key in ledger.keys) {
        if (!recorded.containsKey(key) && !key.startsWith("run-ok:")) {
          val suite = key.substringBefore("/")
          val caseId = key.substringAfter("/")
          failures.add(
              CaseFailure(suite, caseId, "ledger entry never ran against a failing stream (stale)"),
          )
        }
      }
      return failures
    }

    public fun caseCount(): Int {
      val corpus = DetectRunner.corpusDir()
      return eventsSuites().sumOf { suite ->
        Json.parseToJsonElement(Files.readString(corpus.resolve("$suite.json")))
            .jsonObject
            .getValue("cases")
            .jsonArray
            .size
      }
    }
  }

  @Test
  fun eventsStreamsMatchCorpus() {
    val failures = runAll()
    val count = caseCount()
    if (failures.isNotEmpty()) {
      fail(
          "${failures.size}/$count events cases failed:\n" +
              failures.joinToString("\n") { "  ${it.suite}/${it.caseId}: ${it.reason}" },
      )
    }
    assertEquals(39, count, "events suite case count drift")
  }
}
