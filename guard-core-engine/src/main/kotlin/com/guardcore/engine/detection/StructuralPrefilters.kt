package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyRePattern

/**
 * Fail-closed structural safety checks, run before any empirical probe.
 *
 * Port of guard_core/detection_engine/_redos_structural_prefilters.py. The dangerous-construct
 * regexes here search the PATTERN SOURCE text (python re over the pattern string), so they run
 * through PyRe with plain re semantics.
 */
private val dangerousConstructChecks: List<Pair<String, String>> = buildList {
  add(
      Pair(
          "\\(\\.(?:\\*|\\+|\\{[0-9]+,\\})\\)(?:\\+|\\{[0-9]+,\\})",
          "Pattern contains dangerous construct: \\(.(?:\\*|\\+|\\{[0-9]+,\\})\\)(?:\\+|\\{[0-9]+,\\})",
      ),
  )
  add(
      Pair(
          "\\([^)]*(?:\\*|\\+|\\{[0-9]+,\\})\\)(?:\\+|\\{[0-9]+,\\})",
          "Pattern contains dangerous construct: \\([^)]*(?:\\*|\\+|\\{[0-9]+,\\})\\)(?:\\+|\\{[0-9]+,\\})",
      ),
  )
  add(
      Pair(
          "(?:\\.(?:\\*|\\+|\\{[0-9]+,\\})){2,}",
          "Pattern contains dangerous construct: (?:\\.(?:\\*|\\+|\\{[0-9]+,\\})){2,}",
      ),
  )
}

private val structuralChecks: List<Pair<(String) -> String?, String>> =
    listOf(
        Pair(
            { detectNestedUnboundedQuantifier(it) },
            "Pattern contains nested unbounded quantifier: ",
        ),
        Pair(
            { detectAdjacentBroadUnboundedQuantifiers(it) },
            "Pattern contains adjacent broad unbounded quantifiers: ",
        ),
        Pair(
            { detectUnreachableTerminatorScan(it) },
            "Pattern contains a broad scan whose terminator cannot be reached by " +
                "repeating its own prefix: ",
        ),
        Pair(
            { detectAmbiguousLiteralBoundary(it) },
            "Pattern contains a quantified class that can absorb the mandatory " +
                "literal immediately following it: ",
        ),
        Pair(
            { detectAmbiguousOptionalTailInQuantifiedGroup(it) },
            "Pattern contains an ambiguous optional tail inside an unbounded " +
                "quantified group: ",
        ),
    )

/** _first_structural_safety_violation: the first check's finding with its message prefix. */
public fun firstStructuralSafetyViolation(pattern: String): String? {
  for ((check, message) in structuralChecks) {
    val finding = check(pattern) ?: continue
    return message + finding
  }
  return null
}

private val dangerousCompiled: List<Pair<PyRePattern, String>> =
    dangerousConstructChecks.map { (source, message) ->
      Pair(PyRe.compile(source, 0), message)
    }

/** _dangerous_construct_violation: rejects the classic (.*)+ family outright. */
public fun dangerousConstructViolation(pattern: String): String? {
  for ((compiled, message) in dangerousCompiled) {
    if (compiled.search(pattern, 0, Long.MAX_VALUE) != null) return message
  }
  return null
}
