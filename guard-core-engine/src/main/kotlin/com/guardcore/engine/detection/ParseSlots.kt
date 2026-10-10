package com.guardcore.engine.detection

import com.guardcore.engine.py.AssertAv
import com.guardcore.engine.py.BranchAv
import com.guardcore.engine.py.ParsedPattern
import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyReParser
import com.guardcore.engine.py.ReCategory
import com.guardcore.engine.py.ReNode
import com.guardcore.engine.py.ReOp
import com.guardcore.engine.py.ReParseError
import com.guardcore.engine.py.RepeatAv
import com.guardcore.engine.py.SRE_MAXREPEAT
import com.guardcore.engine.py.SubPatternAv

/**
 * Slot extraction from a parsed pattern: the pairing-atom / non-pairing-slot model the
 * class-interaction, alphabet, and repeat-prefix analyzers consume.
 *
 * Port of guard_core/detection_engine/_redos_parse_slots.py: a pairing atom carries member
 * intervals plus a per-code-point predicate; non-pairing slots carry group alternatives or boundary
 * markers. Repeat bounds become allows_zero / unbounded / max_repeat / variable_bounded exactly
 * like the reference.
 */
public class PairingAtom(
    public val intervals: IntervalSet,
    public val allowsZero: Boolean,
    override val unbounded: Boolean,
    public val predicate: ((Int) -> Boolean)? = null,
    override val maxRepeat: Int? = null,
    override val variableBounded: Boolean = false,
) : Slot {
  public fun copy(
      intervals: IntervalSet = this.intervals,
      allowsZero: Boolean = this.allowsZero,
      unbounded: Boolean = this.unbounded,
      predicate: ((Int) -> Boolean)? = this.predicate,
      maxRepeat: Int? = this.maxRepeat,
      variableBounded: Boolean = this.variableBounded,
  ): PairingAtom =
      PairingAtom(intervals, allowsZero, unbounded, predicate, maxRepeat, variableBounded)

  override fun equals(other: Any?): Boolean =
      other is PairingAtom &&
          other.intervals == intervals &&
          other.allowsZero == allowsZero &&
          other.unbounded == unbounded

  override fun hashCode(): Int =
      (intervals.hashCode() * 31 + allowsZero.hashCode()) * 31 + unbounded.hashCode()
}

public class NonPairingSlot(
    public val isBoundary: Boolean,
    public val inner: List<List<Slot>>?,
    override val unbounded: Boolean = false,
    override val maxRepeat: Int? = null,
    override val variableBounded: Boolean = false,
) : Slot {
  public fun copy(
      isBoundary: Boolean = this.isBoundary,
      inner: List<List<Slot>>? = this.inner,
      unbounded: Boolean = this.unbounded,
      maxRepeat: Int? = this.maxRepeat,
      variableBounded: Boolean = this.variableBounded,
  ): NonPairingSlot = NonPairingSlot(isBoundary, inner, unbounded, maxRepeat, variableBounded)
}

/** _Slot: a pairing atom or a non-pairing slot. */
public sealed interface Slot {
  public val unbounded: Boolean
  public val maxRepeat: Int?
  public val variableBounded: Boolean
}

private val pairingOps = setOf(ReOp.LITERAL, ReOp.NOT_LITERAL, ReOp.IN, ReOp.ANY, ReOp.CATEGORY)
private val repeatOps = setOf(ReOp.MAX_REPEAT, ReOp.MIN_REPEAT)
private val assertOps = setOf(ReOp.ASSERT, ReOp.ASSERT_NOT)

/** python re predicate for a category shorthand, honoring ASCII mode. */
public fun categoryPredicate(category: ReCategory, flags: Int): (Int) -> Boolean {
  val asciiOnly = flags and PyReFlags.ASCII != 0
  return predicate@{ codePoint: Int ->
    if (asciiOnly) {
      if (codePoint > 0x7F) return@predicate false
      when (category) {
        ReCategory.DIGIT -> codePoint in 0x30..0x39
        ReCategory.NOT_DIGIT -> codePoint !in 0x30..0x39
        ReCategory.SPACE -> codePoint == ' '.code || codePoint in 0x09..0x0D
        ReCategory.NOT_SPACE -> !(codePoint == ' '.code || codePoint in 0x09..0x0D)
        ReCategory.WORD ->
            codePoint == 0x5F ||
                codePoint in 0x30..0x39 ||
                codePoint in 0x41..0x5A ||
                codePoint in 0x61..0x7A
        ReCategory.NOT_WORD ->
            !(codePoint == 0x5F ||
                codePoint in 0x30..0x39 ||
                codePoint in 0x41..0x5A ||
                codePoint in 0x61..0x7A)
      }
    } else {
      when (category) {
        ReCategory.DIGIT -> Character.isDigit(codePoint)
        ReCategory.NOT_DIGIT -> !Character.isDigit(codePoint)
        ReCategory.SPACE -> Character.isWhitespace(codePoint) || Character.isSpaceChar(codePoint)
        ReCategory.NOT_SPACE ->
            !(Character.isWhitespace(codePoint) || Character.isSpaceChar(codePoint))
        ReCategory.WORD ->
            codePoint == '_'.code ||
                Character.isLetterOrDigit(codePoint) ||
                isMarkCodePoint(codePoint)
        ReCategory.NOT_WORD ->
            !(codePoint == '_'.code ||
                Character.isLetterOrDigit(codePoint) ||
                isMarkCodePoint(codePoint))
      }
    }
  }
}

/** Python alnum includes combining marks (Mn, Me, Mc); java isLetterOrDigit does not. */
private fun isMarkCodePoint(codePoint: Int): Boolean {
  val type = Character.getType(codePoint).toInt()
  return type == Character.NON_SPACING_MARK.toInt() ||
      type == Character.ENCLOSING_MARK.toInt() ||
      type == Character.COMBINING_SPACING_MARK.toInt()
}

private val classNodePredicateCache: HashMap<Any, (Int) -> Boolean> = HashMap()

private fun classNodePredicate(node: ReNode, flags: Int): (Int) -> Boolean {
  val key: Any =
      when (node.op) {
        ReOp.IN -> Triple(ReOp.IN, classItemsKey(node.av as List<ReNode>), flags)
        else -> Triple(node.op, node.av, flags)
      }
  synchronized(classNodePredicateCache) {
    classNodePredicateCache[key]?.let {
      return it
    }
  }
  val predicate =
      if (node.op == ReOp.CATEGORY) {
        categoryPredicate(node.av as ReCategory, flags)
      } else {
        compiledNodePredicate(emitAtomSource(node), flags)
      }
  synchronized(classNodePredicateCache) { classNodePredicateCache[key] = predicate }
  return predicate
}

/** Predicate for a compiled IN node (a character class), via java fullmatch. */
private fun compiledNodePredicate(patternSource: String, flags: Int): (Int) -> Boolean {
  val compiled =
      try {
        PyRe.compile(patternSource, flags and PyReFlags.IGNORECASE.inv())
      } catch (e: Exception) {
        return { true }
      }
  return { codePoint: Int ->
    val text = String(Character.toChars(codePoint))
    compiled.fullmatchAt(text, 0, text.length, Long.MAX_VALUE) != null
  }
}

private fun classItemsKey(items: List<ReNode>): List<Any> = items.map { item ->
  when (item.op) {
    ReOp.RANGE -> Triple(ReOp.RANGE, (item.av as Pair<*, *>).first, item.av)
    else -> Pair(item.op, item.av)
  }
}

/** Emits a single atom's java source for predicate compilation. */
private fun emitAtomSource(node: ReNode): String {
  val sb = StringBuilder()
  when (node.op) {
    ReOp.LITERAL -> sb.appendCodePoint(node.av as Int)
    ReOp.NOT_LITERAL -> sb.append("[^").appendCodePoint(node.av as Int).append(']')
    ReOp.ANY -> sb.append('.')
    ReOp.IN -> {
      sb.append('[')
      for (item in node.av as List<ReNode>) {
        when (item.op) {
          ReOp.NEGATE -> sb.append('^')
          ReOp.LITERAL -> sb.appendCodePoint(item.av as Int)
          ReOp.RANGE -> {
            val (lo, hi) = item.av as Pair<Int, Int>
            sb.appendCodePoint(lo).append('-').appendCodePoint(hi)
          }
          ReOp.CATEGORY ->
              sb.append(
                  when (item.av as ReCategory) {
                    ReCategory.DIGIT -> "\\d"
                    ReCategory.NOT_DIGIT -> "\\D"
                    ReCategory.SPACE -> "\\s"
                    ReCategory.NOT_SPACE -> "\\S"
                    ReCategory.WORD -> "\\w"
                    ReCategory.NOT_WORD -> "\\W"
                  },
              )
          else -> {}
        }
      }
      sb.append(']')
    }
    ReOp.CATEGORY ->
        sb.append(
            when (node.av as ReCategory) {
              ReCategory.DIGIT -> "\\d"
              ReCategory.NOT_DIGIT -> "\\D"
              ReCategory.SPACE -> "\\s"
              ReCategory.NOT_SPACE -> "\\S"
              ReCategory.WORD -> "\\w"
              ReCategory.NOT_WORD -> "\\W"
            },
        )
    else -> throw IllegalArgumentException("unsupported atom ${node.op}")
  }
  return sb.toString()
}

private fun applyIgnorecase(intervals: IntervalSet, flags: Int): IntervalSet =
    if (flags and PyReFlags.IGNORECASE == 0) intervals
    else expandIgnorecase(intervals, asciiOnly = flags and PyReFlags.ASCII != 0)

private fun categoryIntervals(category: ReCategory, flags: Int): IntervalSet {
  val predicate = categoryPredicate(category, flags)
  return cachedCategoryIntervals(
      Triple("category", category, flags and PyReFlags.ASCII),
      predicate,
  )
}

private fun memberIntervals(node: ReNode, flags: Int): IntervalSet =
    when (node.op) {
      ReOp.RANGE -> {
        val (low, high) = node.av as Pair<Int, Int>
        applyIgnorecase(IntervalSet.fromRange(low, high), flags)
      }
      ReOp.LITERAL -> applyIgnorecase(IntervalSet.single(node.av as Int), flags)
      ReOp.CATEGORY -> categoryIntervals(node.av as ReCategory, flags)
      else -> IntervalSet.empty()
    }

private fun inIntervals(items: List<ReNode>, flags: Int): IntervalSet {
  var negate = false
  var member = IntervalSet.empty()
  for (item in items) {
    if (item.op == ReOp.NEGATE) {
      negate = true
      continue
    }
    member = member.union(memberIntervals(item, flags))
  }
  return if (negate) member.complement() else member
}

private fun anyIntervals(flags: Int): IntervalSet {
  val full = IntervalSet.full()
  return if (flags and PyReFlags.DOTALL != 0) full
  else full.difference(IntervalSet.single('\n'.code))
}

/** _node_intervals: member intervals for any pairing op. */
public fun nodeIntervals(node: ReNode, flags: Int): IntervalSet =
    when (node.op) {
      ReOp.NOT_LITERAL -> applyIgnorecase(IntervalSet.single(node.av as Int), flags).complement()
      ReOp.IN -> inIntervals(node.av as List<ReNode>, flags)
      ReOp.ANY -> anyIntervals(flags)
      ReOp.CATEGORY -> categoryIntervals(node.av as ReCategory, flags)
      else -> memberIntervals(node, flags)
    }

/** _candidate_chars_for_atom_text: parse a one-atom source and return first members as chars. */
public fun candidateCharsForAtomText(atomText: String, flags: Int): Set<Char> {
  val parsed =
      try {
        PyReParser.parse(atomText, flags)
      } catch (e: ReParseError) {
        return emptySet()
      }
  if (parsed.data.size != 1) return emptySet()
  val intervals = nodeIntervals(parsed.data[0], parsed.stateFlags)
  return intervals.componentFirstMembers().map { Character.toChars(it)[0] }.toSet()
}

private fun pairingAtom(
    node: ReNode,
    flags: Int,
    allowsZero: Boolean,
    unbounded: Boolean,
    maxRepeat: Int? = null,
    variableBounded: Boolean = false,
): Slot =
    PairingAtom(
        nodeIntervals(node, flags),
        allowsZero,
        unbounded,
        classNodePredicate(node, flags),
        maxRepeat,
        variableBounded,
    )

private fun nonPairingSlot(
    node: ReNode,
    flags: Int,
    allowsZero: Boolean,
    unbounded: Boolean,
    maxRepeat: Int? = null,
    variableBounded: Boolean = false,
): Slot =
    when (node.op) {
      ReOp.BRANCH -> {
        val alternatives = (node.av as BranchAv).alternatives
        NonPairingSlot(
            !allowsZero,
            alternatives.map { walkSequence(it, flags) },
            unbounded,
            maxRepeat,
            variableBounded,
        )
      }
      ReOp.SUBPATTERN -> {
        val av = node.av as SubPatternAv
        val childFlags = (flags or av.addFlags) and av.delFlags.inv()
        NonPairingSlot(
            !allowsZero,
            sequenceToAlternatives(av.body, childFlags),
            unbounded,
            maxRepeat,
            variableBounded,
        )
      }
      ReOp.ATOMIC_GROUP -> {
        val body = node.av as List<ReNode>
        NonPairingSlot(
            !allowsZero,
            sequenceToAlternatives(body, flags),
            unbounded,
            maxRepeat,
            variableBounded,
        )
      }
      in assertOps -> {
        val av = node.av as AssertAv
        NonPairingSlot(false, sequenceToAlternatives(av.body, flags), false)
      }
      ReOp.AT -> NonPairingSlot(false, null, false)
      else -> NonPairingSlot(true, null, false)
    }

private fun unrepeatedSlot(node: ReNode, flags: Int): Slot =
    if (node.op in pairingOps) pairingAtom(node, flags, false, false)
    else nonPairingSlot(node, flags, false, false)

private fun repeatSlot(av: RepeatAv, flags: Int): Slot {
  val allowsZero = av.low == 0
  val unbounded = av.high == SRE_MAXREPEAT
  val variableBounded = !unbounded && av.low < av.high
  val maxRepeat = if (!unbounded) av.high else null
  if (av.body.size == 1) {
    val item = av.body[0]
    return if (item.op in pairingOps) {
      pairingAtom(item, flags, allowsZero, unbounded, maxRepeat, variableBounded)
    } else {
      nonPairingSlot(item, flags, allowsZero, unbounded, maxRepeat, variableBounded)
    }
  }
  return NonPairingSlot(
      !allowsZero,
      sequenceToAlternatives(av.body, flags),
      unbounded,
      maxRepeat,
      variableBounded,
  )
}

private fun slotForFlatItem(item: ReNode, flags: Int): Slot =
    if (item.op in repeatOps) repeatSlot(item.av as RepeatAv, flags)
    else unrepeatedSlot(item, flags)

private fun walkSequence(items: List<ReNode>, flags: Int): List<Slot> = items.map {
  slotForFlatItem(it, flags)
}

private fun sequenceToAlternatives(items: List<ReNode>, flags: Int): List<List<Slot>> {
  if (items.size == 1 && items[0].op == ReOp.BRANCH) {
    val alternatives = (items[0].av as BranchAv).alternatives
    return alternatives.map { walkSequence(it, flags) }
  }
  return listOf(walkSequence(items, flags))
}

/** _pattern_slots: parse a pattern and extract its slot sequence; null when unparseable. */
public fun patternSlots(pattern: String, flags: Int): List<Slot>? {
  val parsed: ParsedPattern =
      try {
        PyReParser.parse(pattern, flags)
      } catch (e: ReParseError) {
        return null
      }
  return walkSequence(parsed.data, parsed.stateFlags)
}
