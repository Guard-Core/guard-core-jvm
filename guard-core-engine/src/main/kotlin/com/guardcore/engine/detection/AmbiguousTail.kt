package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyRePattern

/**
 * Ambiguous optional tail inside an unbounded quantified group, and the atom character-set probes
 * shared with the literal-boundary detector and probe builders.
 *
 * Port of guard_core/detection_engine/_redos_ambiguous_tail.py.
 */
private const val OVERLAP_PROBE_ALPHABET =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\u000B\u000C"

private data class ParsedQuant(val optional: Boolean, val unbounded: Boolean, val next: Int)

public data class AtomText(
    public val text: String,
    public val optional: Boolean,
    public val unbounded: Boolean,
    public val variable: Boolean,
)

private fun parseSymbolQuantifier(inner: String, i: Int): ParsedQuant {
  val symbol = inner[i]
  val optional = symbol == '*' || symbol == '?'
  val unbounded = symbol == '*' || symbol == '+'
  var j = i + 1
  if (j < inner.length && inner[j] == '?') j++
  return ParsedQuant(optional, unbounded, j)
}

private fun parseBraceQuantifier(inner: String, i: Int): ParsedQuant? {
  val endBrace = inner.indexOf('}', i)
  if (endBrace == -1) return null
  val parts = inner.substring(i + 1, endBrace).split(",")
  if (parts[0].isEmpty() || !parts[0].all { it.isDigitInternal() }) return null
  val optional = parts[0].toInt() == 0
  val unbounded = parts.size > 1 && parts[1].isEmpty()
  var j = endBrace + 1
  if (j < inner.length && inner[j] == '?') j++
  return ParsedQuant(optional, unbounded, j)
}

private fun parseFlatQuantifiedAtoms(inner: String): List<Pair<Boolean, Boolean>>? {
  if (inner.contains('(') || inner.contains('|')) return null
  val atoms = ArrayList<Pair<Boolean, Boolean>>()
  var i = 0
  val n = inner.length
  while (i < n) {
    i++
    var optional = false
    var unbounded = false
    if (i < n && inner[i] in "*+?") {
      val parsed = parseSymbolQuantifier(inner, i)
      optional = parsed.optional
      unbounded = parsed.unbounded
      i = parsed.next
    } else if (i < n && inner[i] == '{') {
      val parsed = parseBraceQuantifier(inner, i) ?: return null
      optional = parsed.optional
      unbounded = parsed.unbounded
      i = parsed.next
    }
    atoms.add(Pair(optional, unbounded))
  }
  return atoms
}

private fun atomsHaveAmbiguousPair(atoms: List<Pair<Boolean, Boolean>>): Boolean {
  for (a in atoms.indices) {
    for (b in atoms.indices) {
      if (atoms[a].second && atoms[b].first && a != b) return true
    }
  }
  return false
}

private val compiledAtomCache: HashMap<Pair<String, Int>, PyRePattern?> = HashMap()

private fun compileAtom(atomText: String): PyRePattern? {
  val key = Pair(atomText, PyReFlags.DOTALL)
  synchronized(compiledAtomCache) {
    return compiledAtomCache.getOrPut(key) { compileAtomUncached(atomText) }
  }
}

private fun compileAtomUncached(atomText: String): PyRePattern? =
    try {
      PyRe.compile(atomText, PyReFlags.DOTALL)
    } catch (e: Exception) {
      null
    }

/** _atom_char_set: the printable chars the atom can match (python: fullmatch per probe char). */
public fun atomCharSet(atomText: String): Set<Char> {
  val compiled = compileAtom(atomText) ?: return emptySet()
  val out = LinkedHashSet<Char>()
  for (ch in OVERLAP_PROBE_ALPHABET) {
    if (compiled.fullmatchAt(ch.toString(), 0, 1, Long.MAX_VALUE) != null) out.add(ch)
  }
  return out
}

private fun atomsOverlap(textA: String, textB: String): Boolean =
    atomCharSet(textA).intersect(atomCharSet(textB)).isNotEmpty()

private fun firstAcceptedChar(compiled: PyRePattern, candidates: Iterable<Char>): Char? {
  for (ch in candidates) {
    if (compiled.fullmatchAt(ch.toString(), 0, 1, Long.MAX_VALUE) != null) return ch
  }
  return null
}

/** _representative_char_for_atom: a printable char the atom matches, else any candidate char. */
public fun representativeCharForAtom(atomText: String): Char? {
  val compiled = compileAtom(atomText) ?: return null
  val printableMatch = firstAcceptedChar(compiled, OVERLAP_PROBE_ALPHABET.toList())
  if (printableMatch != null) return printableMatch
  return firstAcceptedChar(
      compiled,
      candidateCharsForAtomText(atomText, PyReFlags.DOTALL).sorted(),
  )
}

private fun rawAtomSpan(inner: String, i: Int): Int =
    when {
      inner[i] == '\\' && i + 1 < inner.length -> i + 2
      inner[i] == '[' -> skipCharClass(inner, i)
      else -> i + 1
    }

private fun parseBraceQuantifierWithVariability(
    inner: String,
    i: Int,
): ParsedVariability? {
  val endBrace = inner.indexOf('}', i)
  if (endBrace == -1) return null
  val parts = inner.substring(i + 1, endBrace).split(",")
  if (parts[0].isEmpty() || !parts[0].all { it.isDigitInternal() }) return null
  val optional = parts[0].toInt() == 0
  val unbounded = parts.size > 1 && parts[1].isEmpty()
  val variable = unbounded || (parts.size > 1 && parts[1] != parts[0])
  var j = endBrace + 1
  if (j < inner.length && inner[j] == '?') j++
  return ParsedVariability(optional, unbounded, variable, j)
}

private data class ParsedVariability(
    val optional: Boolean,
    val unbounded: Boolean,
    val variable: Boolean,
    val next: Int,
)

public fun parseFlatQuantifiedAtomsWithText(inner: String): List<AtomText>? {
  val atoms = ArrayList<AtomText>()
  var i = 0
  val n = inner.length
  while (i < n) {
    if (inner[i] == '(' || inner[i] == '|') return null
    val atomEnd = rawAtomSpan(inner, i)
    val atomText = inner.substring(i, atomEnd)
    i = atomEnd
    var optional = false
    var unbounded = false
    var variable = false
    if (i < n && inner[i] in "*+?") {
      val parsed = parseSymbolQuantifier(inner, i)
      optional = parsed.optional
      unbounded = parsed.unbounded
      i = parsed.next
      variable = true
    } else if (i < n && inner[i] == '{') {
      val parsed = parseBraceQuantifierWithVariability(inner, i) ?: return null
      optional = parsed.optional
      unbounded = parsed.unbounded
      variable = parsed.variable
      i = parsed.next
    }
    atoms.add(AtomText(atomText, optional, unbounded, variable))
  }
  return atoms
}

private fun hasOverlappingCyclicNeighbor(atoms: List<AtomText>): Boolean {
  val n = atoms.size
  for (k in atoms.indices) {
    val atom = atoms[k]
    if (!atom.variable) continue
    val nextText = atoms[(k + 1) % n].text
    if (atomsOverlap(atom.text, nextText)) return true
  }
  return false
}

public fun groupInnerIsAmbiguous(inner: String): Boolean {
  val rawAtoms = parseFlatQuantifiedAtomsWithText(inner) ?: return false
  if (rawAtoms.size == 1) {
    val atom = rawAtoms[0]
    return atom.variable && !atom.unbounded
  }
  val shapeOnly = rawAtoms.map { Pair(it.optional, it.unbounded) }
  if (atomsHaveAmbiguousPair(shapeOnly)) return true
  return hasOverlappingCyclicNeighbor(rawAtoms)
}

/** _detect_ambiguous_optional_tail_in_quantified_group: the offending span, or null. */
public fun detectAmbiguousOptionalTailInQuantifiedGroup(pattern: String): String? {
  return try {
    for ((start, end, inner) in iterQuantifiedGroupBodies(pattern)) {
      if (groupInnerIsAmbiguous(inner)) return pattern.substring(start, end)
    }
    null
  } catch (e: GroupNestingTooDeep) {
    NESTING_DEPTH_REJECTION_REASON
  }
}

/** Representative char and atom end for an escape or class at [i]; null for other chars. */
public fun representativeCharAndEndForEscapeOrClass(
    pattern: String,
    i: Int,
): Pair<Int, Char?>? =
    when {
      pattern[i] == '\\' && i + 1 < pattern.length -> {
        val atomEnd = i + 2
        Pair(atomEnd, representativeCharForAtom(pattern.substring(i, atomEnd)))
      }
      pattern[i] == '[' -> {
        val atomEnd = skipCharClass(pattern, i)
        Pair(atomEnd, representativeCharForAtom(pattern.substring(i, atomEnd)))
      }
      else -> null
    }

/** _extract_literal_chars: representative chars of the pattern's literal/class atoms. */
public fun extractLiteralChars(pattern: String): List<Char> {
  val chars = ArrayList<Char>()
  var i = 0
  val n = pattern.length
  while (i < n) {
    val result = representativeCharAndEndForEscapeOrClass(pattern, i)
    if (result != null) {
      val (nextI, rep) = result
      i = nextI
      if (rep != null) chars.add(rep)
      continue
    }
    val c = pattern[i]
    if (c.isAsciiLetterInternal() || c.isDigitInternal() || c in "_-./:@~ ") {
      chars.add(c)
    }
    i++
  }
  return chars
}
