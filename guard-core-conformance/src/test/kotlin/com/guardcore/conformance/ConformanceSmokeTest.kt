package com.guardcore.conformance

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * W0 smoke test over the vendored spec 4.1.0 corpus.
 *
 * The corpus lives at the repo root under `conformance/guard-core-spec-4.1.0/cases/` and is
 * vendored byte-identical from the guard-core specs/fixtures; it is read via a relative path (the
 * repo root is located by walking up from the working directory). Never hand-edit the corpus:
 * regenerate it from the reference engine.
 *
 * The full runner, cost budgets, and xfail manifests land in W5.
 */
class ConformanceSmokeTest {

  private fun corpusDir(): Path {
    var dir: Path = Path.of(System.getProperty("user.dir"))
    while (true) {
      val candidate = dir.resolve("conformance").resolve("guard-core-spec-4.1.0").resolve("cases")
      if (Files.exists(candidate.resolve("index.json"))) {
        return candidate
      }
      val parent = dir.parent ?: error("corpus index.json not found relative to $dir")
      dir = parent
    }
  }

  private fun index(): JsonObject {
    val text = Files.readString(corpusDir().resolve("index.json"))
    return Json.parseToJsonElement(text).jsonObject
  }

  @Test
  fun indexPinsSpecAndEngineVersions() {
    val index = index()
    assertEquals("4.1.0", index.getValue("spec_version").jsonPrimitive.content)
    assertEquals("4.3.2", index.getValue("engine_version").jsonPrimitive.content)
    assertEquals(
        "adbdccd402ed0fdb0c26023f11c6acc534344521",
        index.getValue("engine_commit").jsonPrimitive.content,
    )
  }

  @Test
  fun indexListsAllTwentyOneSuites() {
    assertEquals(21, index().getValue("suites").jsonObject.size)
  }

  @Test
  fun costBudgetPinsKFactor() {
    val costBudgets = index().getValue("cost_budgets").jsonObject
    assertEquals(5, costBudgets.getValue("k").jsonPrimitive.content.toInt())
  }

  @Test
  fun indexPinsTheFixedIp() {
    assertEquals("203.0.113.7", index().getValue("fixed_ip").jsonPrimitive.content)
  }
}
