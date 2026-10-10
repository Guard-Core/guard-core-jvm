package com.guardcore.engine.detection

/**
 * Raw-string walking primitives for the ReDoS structural analyzers.
 *
 * Port of guard_core/detection_engine/_redos_structure_primitives.py. Every function walks the
 * python pattern source text directly (the structural layer never needs the parse tree).
 */

/** Skip to just past a character class starting at [i]. */
public fun skipCharClass(text: String, i: Int): Int {
  var j = i + 1
  while (j < text.length && text[j] != ']') {
    if (text[j] == '\\' && j + 1 < text.length) {
      j += 2
      continue
    }
    j++
  }
  if (j < text.length) j++
  return j
}

/** Replace escapes and char classes with X, so structural shape checks see bare metachars. */
public fun stripEscapesAndCharClasses(pattern: String): String {
  val result = StringBuilder()
  var i = 0
  while (i < pattern.length) {
    val c = pattern[i]
    if (c == '\\' && i + 1 < pattern.length) {
      result.append('X')
      i += 2
      continue
    }
    if (c == '[') {
      i = skipCharClass(pattern, i)
      result.append('X')
      continue
    }
    result.append(c)
    i++
  }
  return result.toString()
}

private val unboundedSingleStarPlus = Regex(".[*+]")
private val unboundedSingleBrace = Regex(".\\{[0-9]+,\\}")

/** A branch that is a single broad atom with an unbounded quantifier (".*" etc). */
public fun branchIsUnboundedSingle(branch: String): Boolean =
    unboundedSingleStarPlus.fullmatches(branch) || unboundedSingleBrace.fullmatches(branch)

private fun Regex.fullmatches(s: String): Boolean = matchEntire(s) != null

/** Advance past an escape pair or a whole character class; null for any other char. */
public fun advancePastEscapeOrCharClass(text: String, i: Int): Int? {
  if (text[i] == '\\' && i + 1 < text.length) return i + 2
  if (text[i] == '[') return skipCharClass(text, i)
  return null
}

/** End index (exclusive) of the group opening at [start]; null when unbalanced. */
public fun findGroupEnd(text: String, start: Int): Int? {
  var depth = 1
  var j = start + 1
  while (j < text.length && depth > 0) {
    val skipTo = advancePastEscapeOrCharClass(text, j)
    if (skipTo != null) {
      j = skipTo
      continue
    }
    when (text[j]) {
      '(' -> depth++
      ')' -> depth--
    }
    j++
  }
  if (depth != 0) return null
  return j
}

/** Normalize a group's inner text: strip (?:, named headers; null for backrefs. */
public fun normalizeGroupInner(inner: String): String? =
    when {
      inner.startsWith("?:") -> inner.substring(2)
      inner.startsWith("?P=") -> null
      inner.startsWith("?P<") -> {
        val endName = inner.indexOf('>')
        if (endName == -1) null else inner.substring(endName + 1)
      }
      else -> inner
    }

/** Unwrap nested transparent (?:...) wrappers around the whole text. */
public fun unwrapTransparentWrapper(text: String): String {
  var t = text
  while (t.startsWith("(")) {
    val end = findGroupEnd(t, 0) ?: break
    if (end != t.length) break
    val candidate = normalizeGroupInner(t.substring(1, end - 1)) ?: break
    t = candidate
  }
  return t
}

/** Length of the unbounded quantifier at index [k] (*, + or {n,}), else 0. */
public fun outerQuantifierLen(text: String, k: Int): Int {
  if (k < text.length && (text[k] == '*' || text[k] == '+')) return 1
  if (k < text.length && text[k] == '{') {
    val endBrace = text.indexOf('}', k)
    if (endBrace != -1) {
      val braceInner = text.substring(k + 1, endBrace)
      if (braceInner.contains(",") && braceInner.split(",")[1].isEmpty()) {
        return endBrace - k + 1
      }
    }
  }
  return 0
}

/** Whether any two literal branches overlap by prefix. */
public fun branchesOverlap(branches: List<String>): Boolean {
  val n = branches.size
  for (a in 0 until n) {
    for (b in a + 1 until n) {
      val x = branches[a]
      val y = branches[b]
      if (x == y || x.startsWith(y) || y.startsWith(x)) return true
    }
  }
  return false
}

private val META_BRANCH_CHARS = "()[]{}.*+?^$|\\".toSet()

public fun isPureLiteralBranch(branch: String): Boolean =
    branch.isNotEmpty() && branch.all { it !in META_BRANCH_CHARS }

/** Split alternations at the top level of [inner]. */
public fun splitTopLevelAlternations(inner: String): List<String> {
  val branches = ArrayList<String>()
  var depth = 0
  var start = 0
  var k = 0
  while (k < inner.length) {
    val skipTo = advancePastEscapeOrCharClass(inner, k)
    if (skipTo != null) {
      k = skipTo
      continue
    }
    when (inner[k]) {
      '(' -> depth++
      ')' -> depth--
      '|' ->
          if (depth == 0) {
            branches.add(inner.substring(start, k))
            start = k + 1
          }
    }
    k++
  }
  branches.add(inner.substring(start))
  return branches
}

public fun overlappingLiteralBranches(inner: String): Boolean {
  val literalBranches = splitTopLevelAlternations(inner).filter { isPureLiteralBranch(it) }
  return literalBranches.size >= 2 && branchesOverlap(literalBranches)
}

public const val MAX_GROUP_NESTING_DEPTH: Int = 20

/** Raised when a pattern exceeds the group nesting depth the analyzer supports. */
public class GroupNestingTooDeep(public val depth: Int) :
    RuntimeException("GroupNestingTooDeep($depth)")

/** (start, end, inner) over every quantified group body, recursively. */
public fun iterQuantifiedGroupBodiesAt(
    pattern: String,
    base: Int,
    depth: Int,
): List<Triple<Int, Int, String>> {
  if (depth > MAX_GROUP_NESTING_DEPTH) throw GroupNestingTooDeep(MAX_GROUP_NESTING_DEPTH)
  val out = ArrayList<Triple<Int, Int, String>>()
  var i = 0
  while (i < pattern.length) {
    if (pattern[i] != '(') {
      i++
      continue
    }
    val j = findGroupEnd(pattern, i)
    if (j == null) {
      i++
      continue
    }
    val rawInner = pattern.substring(i + 1, j - 1)
    out.addAll(iterQuantifiedGroupBodiesAt(rawInner, base + i + 1, depth + 1))
    var inner = normalizeGroupInner(rawInner)
    if (inner != null) {
      inner = unwrapTransparentWrapper(inner)
      val qlen = outerQuantifierLen(pattern, j)
      if (qlen > 0) out.add(Triple(base + i, base + j + qlen, inner))
    }
    i = j
  }
  return out
}

public fun iterQuantifiedGroupBodies(pattern: String): List<Triple<Int, Int, String>> =
    iterQuantifiedGroupBodiesAt(pattern, 0, 0)
