package com.guardcore.conformance

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * W9c arm closure for the conformance runners: the case-failure arms (verdict mismatch fields, the
 * thrown-case root-cause walk) driven over a scratch corpus deliberately seeded with wrong
 * expectations. The pinned corpus under conformance/guard-core-spec-4.1.0/ is never touched.
 */
class RunnerErrorArmsW9cTest {
  private fun writeCorpus(root: Path, cases: String, suiteName: String = "w9c_seeded") {
    root
        .resolve("index.json")
        .writeText(
            """{"suites": {"$suiteName": {"kind": "detect", "description": "seeded"}},
           "config_knobs": {},
           "fixed_ip": "203.0.113.1"}""",
        )
    root.resolve("$suiteName.json").writeText("""{"cases": $cases}""")
  }

  @Test
  fun `seeded wrong expectations populate every mismatch arm`() {
    val root = Files.createTempDirectory("w9c-corpus")
    val cases =
        """
        [
          {"id": "flag-mismatch",
           "input": {"content": "<script>alert(1)</script>", "context": "body"},
           "expected": {"is_threat": false, "threat_score": 0.0, "threats": []}},
          {"id": "score-mismatch",
           "input": {"content": "<script>alert(1)</script>", "context": "body"},
           "expected": {"is_threat": true, "threat_score": 0.123456, "threats": []}},
          {"id": "count-mismatch",
           "input": {"content": "<script>alert(1)</script>", "context": "body"},
           "expected": {"is_threat": true, "threat_score": 1.0, "threats": [{}, {}, {}]}},
          {"id": "field-mismatch",
           "input": {"content": "<script>alert(1)</script>", "context": "body"},
           "expected": {"is_threat": true, "threat_score": 1.0,
                        "threats": [{"type": "regex", "pattern": "definitely-not-a-pattern", "match": "x", "position": 0, "category": "cat", "weight": 9.9}]}},
          {"id": "throws",
           "input": {"content": "<script>alert(1)</script>", "context": "body"},
           "expected": {"is_threat": true, "threat_score": 1.0,
                        "threats": [{"no_pattern_key": 1}]}}
        ]
        """
            .trimIndent()
    writeCorpus(root, cases)
    assertEquals(listOf("w9c_seeded"), DetectRunner.detectSuites(root))
    val failures =
        try {
          DetectRunner.runAll(root)
        } finally {
          // Restore the shared manager: the seeded corpus configured a scratch view.
          com.guardcore.engine.suspatterns.SusPatternsManager.shared().configure(null)
        }
    val ids = failures.map { it.caseId }
    assertTrue("flag-mismatch" in ids, ids.toString())
    assertTrue("score-mismatch" in ids, ids.toString())
    assertTrue("count-mismatch" in ids, ids.toString())
    assertTrue("field-mismatch" in ids, ids.toString())
    assertTrue("throws" in ids, ids.toString())
    val flag = failures.first { it.caseId == "flag-mismatch" }
    assertTrue(flag.reason.startsWith("is_threat"), flag.reason)
    val score = failures.first { it.caseId == "score-mismatch" }
    assertTrue(score.reason.startsWith("threat_score"), score.reason)
    val count = failures.first { it.caseId == "count-mismatch" }
    assertTrue(
        count.reason.startsWith("threat count") || count.reason.startsWith("threw "),
        count.reason,
    )
    val field = failures.first { it.caseId == "field-mismatch" }
    assertTrue(field.reason.startsWith("threat") || field.reason.contains("pattern"), field.reason)
    val thrown = failures.first { it.caseId == "throws" }
    assertTrue(thrown.reason.startsWith("threw "), thrown.reason)
  }

  @Test
  fun `round6 mirrors python banker rounding`() {
    assertEquals(0.123456, DetectRunner.round6(0.1234565))
    assertEquals(1.0, DetectRunner.round6(1.0000004))
    assertEquals(0.5, DetectRunner.round6(0.5))
  }
}
