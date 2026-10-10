package com.guardcore.engine.detection

/**
 * Adversarial literal runs: contiguous runs of chars a pattern can match at fixed positions.
 *
 * Port of guard_core/detection_engine/_redos_literal_runs.py.
 */
private fun skipLazyMarker(text: String, k: Int): Int =
    if (k < text.length && text[k] == '?') k + 1 else k

private fun braceQuantifierSpanAllowsZero(text: String, k: Int): Pair<Int, Boolean> {
  val endBrace = text.indexOf('}', k)
  if (endBrace == -1) return Pair(k, false)
  val parts = text.substring(k + 1, endBrace).split(",")
  val low = parts[0]
  if (low.isNotEmpty() && !low.all { it.isDigitInternal() }) return Pair(k, false)
  val end = skipLazyMarker(text, endBrace + 1)
  return Pair(end, low.isEmpty() || low == "0")
}

private fun quantifierSpanAllowsZero(text: String, k: Int): Pair<Int, Boolean> {
  if (k >= text.length) return Pair(k, false)
  return when (val c = text[k]) {
    '*',
    '?' -> Pair(skipLazyMarker(text, k + 1), true)
    '+' -> Pair(skipLazyMarker(text, k + 1), false)
    '{' -> braceQuantifierSpanAllowsZero(text, k)
    else -> Pair(k, false)
  }
}

private val HARD_RESET_CHARS = "|^$.".toSet()
private const val NARROW_CLASS_MAX_CHARS = 10

private class RunCollector {
  val runs = ArrayList<String>()
  val current = StringBuilder()

  fun flush() {
    if (current.isNotEmpty()) {
      runs.add(current.toString())
      current.setLength(0)
    }
  }
}

/** _adversarial_literal_runs: literal runs the pattern forces, longest-ish first by layout. */
public fun adversarialLiteralRuns(pattern: String): List<String> {
  val state = RunCollector()
  val stack = ArrayList<Boolean>()
  var i = 0
  val n = pattern.length
  while (i < n) {
    i = adversarialRunStep(pattern, i, n, state, stack)
  }
  state.flush()
  return state.runs.filter { it.isNotEmpty() }
}

private fun adversarialRunStep(
    pattern: String,
    i: Int,
    n: Int,
    state: RunCollector,
    stack: ArrayList<Boolean>,
): Int {
  when (val c = pattern[i]) {
    '[' -> {
      val end = skipCharClass(pattern, i)
      val chars = atomCharSet(pattern.substring(i, end))
      if (chars.isNotEmpty() && chars.size <= NARROW_CLASS_MAX_CHARS) {
        state.current.append(chars.sorted()[0])
      } else {
        state.flush()
      }
      return end
    }
    '(' -> {
      if (i + 2 < n && pattern[i + 1] == '?' && pattern[i + 2] == ':') {
        stack.add(true)
        return i + 3
      }
      if (i + 1 < n && pattern[i + 1] == '?') {
        state.flush()
        val endParen = findGroupEnd(pattern, i)
        return endParen ?: (i + 1)
      }
      stack.add(false)
      state.flush()
      return i + 1
    }
    ')' -> {
      val transparent = if (stack.isNotEmpty()) stack.removeAt(stack.size - 1) else false
      if (!transparent) state.flush()
      return i + 1
    }
    in HARD_RESET_CHARS -> {
      state.flush()
      return i + 1
    }
    '*',
    '+',
    '?' -> return i + 1
    '{' -> {
      val endBrace = pattern.indexOf('}', i)
      return if (endBrace != -1) endBrace + 1 else i + 1
    }
    '\\' -> {
      if (i + 1 < n) {
        val next = pattern[i + 1]
        val tokenEnd = i + 2
        if (next.isDigitInternal() || next.isAsciiLetterInternal()) {
          val (qend, allowsZero) = quantifierSpanAllowsZero(pattern, tokenEnd)
          if (allowsZero) return qend
          state.flush()
          return if (qend > tokenEnd) qend else tokenEnd
        }
        state.current.append(next)
        return tokenEnd
      }
      state.flush()
      return i + 1
    }
    else -> {
      state.current.append(c)
      return i + 1
    }
  }
}
