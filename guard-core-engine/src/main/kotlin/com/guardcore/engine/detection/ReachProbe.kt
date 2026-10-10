package com.guardcore.engine.detection

/**
 * Reaching probe synthesis: construct a literal string that reaches every quantified region of a
 * pattern, under a total construction budget.
 *
 * Port of guard_core/detection_engine/_redos_reach_probe.py.
 */
private const val PROBE_REACH_STRESS_LEN = 4000
private const val PROBE_REACH_BOUNDED_CAP = 4000
private const val PROBE_REACH_TOTAL_BUDGET = 12000
private const val PROBE_REACH_MAX_LENGTH = 2 * PROBE_REACH_TOTAL_BUDGET
private const val PROBE_REACH_GROUP_REPEAT_CAP = 3
private const val PROBE_REACH_BREAK_CHAR_CANDIDATES =
    "\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008"
private val PROBE_REACH_ZERO_WIDTH_ESCAPES = "AZbB".toSet()
private val PROBE_REACH_LOOKAROUND_PREFIXES = listOf("?=", "?!", "?<=", "?<!")

private class Budget(var remaining: Int)

private class ReachSynthesizer(
    val charsSeen: MutableSet<Char>,
    val budget: Budget,
    val groupTexts: MutableMap<Int, String>,
    val groupCounter: IntArray,
) {
  fun reachBudgetClampedCount(unitLen: Int, low: Int, high: Int): Int {
    if (unitLen <= 0) return high
    if (low > PROBE_REACH_MAX_LENGTH / unitLen) {
      throw OverflowError("Mandatory repeat exceeds the probe construction budget")
    }
    val affordable = maxOf(0, budget.remaining) / unitLen
    return maxOf(low, minOf(high, affordable))
  }

  fun reachSymbolQuantifierRange(text: String, k: Int, c: Char): Triple<Int, Int, Int> {
    var end = k + 1
    if (end < text.length && text[end] == '?') end++
    return when (c) {
      '*' -> Triple(0, PROBE_REACH_STRESS_LEN, end)
      '+' -> Triple(1, PROBE_REACH_STRESS_LEN, end)
      else -> Triple(0, 1, end)
    }
  }

  private fun reachBraceQuantifierHigh(parts: List<String>): Int? =
      when {
        parts.size == 1 -> parts[0].toInt()
        parts[1].isEmpty() -> PROBE_REACH_STRESS_LEN
        parts[1].all { it.isDigitInternal() } -> parts[1].toInt()
        else -> null
      }

  fun reachBraceQuantifierRange(text: String, k: Int): Triple<Int, Int, Int>? {
    val endBrace = text.indexOf('}', k)
    if (endBrace == -1) return null
    val parts = text.substring(k + 1, endBrace).split(",")
    if (parts[0].isEmpty() || !parts[0].all { it.isDigitInternal() }) return null
    val low = parts[0].toInt()
    val high = reachBraceQuantifierHigh(parts) ?: return null
    var end = endBrace + 1
    if (end < text.length && text[end] == '?') end++
    return Triple(low, maxOf(low, minOf(high, PROBE_REACH_BOUNDED_CAP)), end)
  }

  fun reachQuantifierRepeatRange(text: String, k: Int): Triple<Int, Int, Int> {
    if (k >= text.length) return Triple(1, 1, k)
    val c = text[k]
    if (c == '*' || c == '+' || c == '?') return reachSymbolQuantifierRange(text, k, c)
    if (c != '{') return Triple(1, 1, k)
    return reachBraceQuantifierRange(text, k) ?: Triple(1, 1, k)
  }

  fun stressFill(text: String, tokenEnd: Int, rep: String): Pair<String, Int> {
    val (low, high, nextI) = reachQuantifierRepeatRange(text, tokenEnd)
    val count = reachBudgetClampedCount(rep.length, low, high)
    budget.remaining -= rep.length * count
    if (rep.length == 1) charsSeen.add(rep[0])
    return Pair(rep.repeat(count), nextI)
  }

  fun reachHexEscapeSpan(text: String, i: Int): Boolean {
    val n = text.length
    return text[i + 1] == 'x' && i + 3 < n && isHexDigit(text[i + 2]) && isHexDigit(text[i + 3])
  }

  fun synthEscapeAtom(text: String, i: Int): Pair<String, Int>? {
    if (i + 1 >= text.length) return null
    val letter = text[i + 1]
    val isHexEscape = reachHexEscapeSpan(text, i)
    val tokenEnd = if (isHexEscape) i + 4 else i + 2
    if (letter in PROBE_REACH_ZERO_WIDTH_ESCAPES) return Pair("", tokenEnd)
    if (letter.isDigitInternal()) {
      val backref = groupTexts[letter - '0'] ?: return null
      return stressFill(text, tokenEnd, backref)
    }
    val rep =
        if (isHexEscape) {
          Character.toChars(text.substring(i + 2, i + 4).toInt(16))[0]
        } else {
          representativeCharForAtom(text.substring(i, tokenEnd))
        } ?: return null
    return stressFill(text, tokenEnd, rep.toString())
  }

  fun synthCharClassAtom(text: String, i: Int): Pair<String, Int>? {
    val end = skipCharClass(text, i)
    val rep = representativeCharForAtom(text.substring(i, end)) ?: return null
    return stressFill(text, end, rep.toString())
  }

  fun synthDotAtom(text: String, i: Int): Pair<String, Int> = stressFill(text, i + 1, "a")

  fun reachGroupWalkTarget(rawInner: String): Pair<String?, Boolean> {
    if (!rawInner.startsWith("?")) return Pair(rawInner, false)
    if (rawInner.startsWith("?:")) return Pair(rawInner.substring(2), false)
    if (rawInner.startsWith("?P<")) {
      val close = rawInner.indexOf('>')
      return Pair(if (close != -1) rawInner.substring(close + 1) else null, false)
    }
    if (PROBE_REACH_LOOKAROUND_PREFIXES.any { rawInner.startsWith(it) }) {
      return Pair(null, true)
    }
    if (rawInner.startsWith("?#")) return Pair(null, true)
    val scopedLength = inlineFlagScopeLength(rawInner)
    if (scopedLength != null) {
      return Pair(rawInner.substring(scopedLength), false)
    }
    if (isInlineFlagOnlyGroup(rawInner)) return Pair(null, true)
    return Pair(null, false)
  }

  fun synthGroupAtom(text: String, i: Int, depth: Int): Pair<String, Int>? {
    val groupEnd = findGroupEnd(text, i) ?: return null
    val rawInner = text.substring(i + 1, groupEnd - 1)
    var reservedNumber: Int? = null
    if (!rawInner.startsWith("?") || rawInner.startsWith("?P<")) {
      groupCounter[0] += 1
      reservedNumber = groupCounter[0]
    }
    val (walkInner, skip) = reachGroupWalkTarget(rawInner)
    if (skip) return Pair("", groupEnd)
    if (walkInner == null) return null
    val firstBranch = splitTopLevelAlternations(walkInner)[0]
    val (subText, subOk) =
        synthesizeReachingProbeSegment(
            firstBranch,
            charsSeen,
            budget,
            depth + 1,
            groupTexts,
            groupCounter,
        )
    if (!subOk) return null
    if (reservedNumber != null) {
      groupTexts[reservedNumber] = subText
    }
    val (low, high0, nextI) = reachQuantifierRepeatRange(text, groupEnd)
    val high = maxOf(low, minOf(high0, PROBE_REACH_GROUP_REPEAT_CAP))
    val count = reachBudgetClampedCount(subText.length, low, high)
    budget.remaining -= subText.length * count
    return Pair(subText.repeat(count), nextI)
  }

  fun synthNextAtom(text: String, i: Int, depth: Int): Pair<String, Int>? {
    when (val c = text[i]) {
      '\\' -> return synthEscapeAtom(text, i)
      '[' -> return synthCharClassAtom(text, i)
      '.' -> return synthDotAtom(text, i)
      '(' -> return synthGroupAtom(text, i, depth)
      else -> return stressFill(text, i + 1, c.toString())
    }
  }
}

private class OverflowError(message: String) : RuntimeException(message)

private fun synthesizeReachingProbeSegment(
    text: String,
    charsSeen: MutableSet<Char>,
    budget: Budget,
    depth: Int,
    groupTexts: MutableMap<Int, String>,
    groupCounter: IntArray,
): Pair<String, Boolean> {
  if (depth > MAX_GROUP_NESTING_DEPTH) return Pair("", false)
  val synth = ReachSynthesizer(charsSeen, budget, groupTexts, groupCounter)
  val out = StringBuilder()
  var length = 0
  var i = 0
  val n = text.length
  while (i < n) {
    if (text[i] == '^' || text[i] == '$') {
      i++
      continue
    }
    val result =
        try {
          synth.synthNextAtom(text, i, depth)
        } catch (e: OverflowError) {
          return Pair("", false)
        }
    if (result == null) return Pair("", false)
    val (piece, nextI) = result
    i = nextI
    length += piece.length
    if (length > PROBE_REACH_MAX_LENGTH) return Pair("", false)
    out.append(piece)
  }
  return Pair(out.toString(), true)
}

/** _synthesize_reaching_probe: a concrete string reaching every quantified region, or null. */
public fun synthesizeReachingProbe(pattern: String): String? {
  val charsSeen = HashSet<Char>()
  val budget = Budget(PROBE_REACH_TOTAL_BUDGET)
  val groupTexts = HashMap<Int, String>()
  val groupCounter = intArrayOf(0)
  val (body, ok) =
      synthesizeReachingProbeSegment(
          pattern,
          charsSeen,
          budget,
          0,
          groupTexts,
          groupCounter,
      )
  if (!ok) return null
  val breaking = PROBE_REACH_BREAK_CHAR_CANDIDATES.firstOrNull { it !in charsSeen } ?: return null
  return body + breaking
}

/** Matches python's \\?[aiLmsux]*(?:-[aiLmsux]+)?: prefix; returns the prefix length. */
private fun inlineFlagScopeLength(rawInner: String): Int? {
  var i = 1
  while (i < rawInner.length && rawInner[i] in "aiLmsux") i++
  if (i < rawInner.length && rawInner[i] == '-') {
    i++
    var any = false
    while (i < rawInner.length && rawInner[i] in "aiLmsux") {
      i++
      any = true
    }
    if (!any) return null
  }
  if (i < rawInner.length && rawInner[i] == ':') return i + 1
  return null
}

/** Matches python's \\?[aiLmsux]*(?:-[aiLmsux]+)?\\Z (flag-only group: skipped). */
private fun isInlineFlagOnlyGroup(rawInner: String): Boolean {
  var i = 1
  while (i < rawInner.length && rawInner[i] in "aiLmsux") i++
  if (i < rawInner.length && rawInner[i] == '-') {
    i++
    var any = false
    while (i < rawInner.length && rawInner[i] in "aiLmsux") {
      i++
      any = true
    }
    if (!any) return false
  }
  return i == rawInner.length
}

private fun isHexDigit(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
