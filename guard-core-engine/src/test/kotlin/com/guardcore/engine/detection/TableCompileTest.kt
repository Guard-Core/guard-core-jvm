package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.suspatterns.PATTERN_DEFINITIONS
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Table integrity: every row compiles under the python-grammar oracle; sets stay in sync. */
class TableCompileTest {
  @Test
  fun everyTableRowCompilesUnderPythonGrammar() {
    assertEquals(157, PATTERN_DEFINITIONS.size)
    for ((index, row) in PATTERN_DEFINITIONS.withIndex()) {
      val (source, contexts, category) = row
      try {
        PyRe.compile(source, PyReFlags.IGNORECASE)
      } catch (e: Exception) {
        throw AssertionError("row $index ($category) failed: ${e.message}")
      }
      assertTrue(contexts.isNotEmpty(), "row $index has no contexts")
    }
  }

  @Test
  fun noiseProneAndReconSetsAreSubsetsOfTable() {
    val sources = PATTERN_DEFINITIONS.map { it.first }.toSet()
    for (source in com.guardcore.engine.suspatterns.NOISE_PRONE_PATTERN_SOURCES) {
      assertTrue(sources.contains(source), "noise-prone source not in table")
    }
    for (source in com.guardcore.engine.suspatterns.DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES) {
      assertTrue(sources.contains(source), "recon raw-view source not in table")
    }
  }
}
