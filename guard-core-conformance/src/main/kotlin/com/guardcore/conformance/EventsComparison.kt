package com.guardcore.conformance

/**
 * The events_envelopes comparison (index.json comparison.events_envelopes): "compare only the keys
 * present in each expected envelope (envelopes from different emitter seams carry different key
 * sets); volatile fields are dropped recursively and listed in events_volatile_fields; xfail cases
 * are advisory and carry no expectations". Floats compare at 6-decimal precision.
 */
public object EventsComparison {
  /** index.json comparison.float_precision. */
  public fun round6(value: Double): Double =
      java.math.BigDecimal(value).setScale(6, java.math.RoundingMode.HALF_UP).toDouble()

  /** Numeric-aware deep comparison (Int vs Long vs Double). */
  public fun valuesEqual(expected: Any?, actual: Any?): Boolean =
      when {
        expected is Number && actual is Number ->
            round6(expected.toDouble()) == round6(actual.toDouble())
        expected is Map<*, *> && actual is Map<*, *> ->
            expected.entries.all { (k, v) -> actual.containsKey(k) && valuesEqual(v, actual[k]) }
        expected is List<*> && actual is List<*> ->
            expected.size == actual.size && expected.zip(actual).all { (e, a) -> valuesEqual(e, a) }
        else -> expected == actual
      }

  /**
   * Compares one expected envelope against the observed envelope; returns the mechanical diff lines
   * (empty = match). Absence of an observed key diverges only against a non-null expected value (a
   * runner that cannot observe a field records its absence, it does not fail).
   */
  public fun envelopeDiffs(index: Int, expected: Map<*, *>, observed: Map<*, *>?): List<String> {
    if (observed == null) {
      return listOf("event $index: no observed envelope")
    }
    val diffs = ArrayList<String>()
    for ((key, expectedValue) in expected) {
      val keyText = key.toString()
      if (!observed.containsKey(keyText)) {
        if (expectedValue != null) {
          diffs.add(
              "event $index field $keyText: want ${render(expectedValue)}, got <absent>",
          )
        }
        continue
      }
      val actualValue = observed[keyText]
      if (!valuesEqual(expectedValue, actualValue)) {
        diffs.add(
            "event $index field $keyText: want ${render(expectedValue)}, got ${render(actualValue)}",
        )
      }
    }
    return diffs
  }

  /** Compares the full expected stream against the observed stream. */
  public fun streamDiffs(expected: List<Map<*, *>>, observed: List<Map<*, *>>): List<String> {
    if (expected.size != observed.size) {
      return listOf("event count: want ${expected.size}, got ${observed.size}")
    }
    val diffs = ArrayList<String>()
    for ((i, exp) in expected.withIndex()) {
      diffs.addAll(envelopeDiffs(i, exp, observed[i]))
    }
    return diffs
  }

  public fun render(value: Any?): String =
      when (value) {
        null -> "null"
        is Map<*, *> -> value.entries.joinToString(",", "{", "}") { (k, v) -> "$k: ${render(v)}" }
        is List<*> -> value.joinToString(",", "[", "]") { render(it) }
        is String -> "\"$value\""
        else -> value.toString()
      }
}
