package com.guardcore.engine.detection

/**
 * Prefix-walk state: the concrete prefix a pattern forces before a repeat site, with pending
 * continuation, exclusions, forbidden words, and captures.
 *
 * Port of guard_core/detection_engine/_redos_repeat_prefix_state.py.
 */
public const val REPEAT_PREFIX_BUDGET: Int = 24000
public const val REPEAT_PREFIX_STATE_LIMIT: Int = 1024
public const val PREFIX_WALK_STATE_LIMIT: Int = 16384
public const val PREFIX_WALK_TEXT_BUDGET: Int = 2000000

public class RepeatPrefixState(
    public val text: String,
    public val pending: String = "",
    public val excluded: IntervalSet = IntervalSet.empty(),
    public val forbidden: List<String> = emptyList(),
    public val captures: List<Pair<Int, String>> = emptyList(),
    public val lastAtom: IntervalSet? = null,
) {
  override fun equals(other: Any?): Boolean =
      other is RepeatPrefixState &&
          other.text == text &&
          other.pending == pending &&
          other.excluded == excluded &&
          other.forbidden == forbidden &&
          other.captures == captures &&
          other.lastAtom == lastAtom

  override fun hashCode(): Int =
      (((text.hashCode() * 31 + pending.hashCode()) * 31 + excluded.hashCode()) * 31 +
          forbidden.hashCode()) * 31 + captures.hashCode()

  override fun toString(): String = "RepeatPrefixState($text, pending=$pending)"
}

public fun stateTextSize(state: RepeatPrefixState): Int =
    state.text.length +
        state.pending.length +
        state.forbidden.sumOf { it.length } +
        state.captures.sumOf { it.second.length }

/** _merge_pending: the common pending continuation of two states, or null. */
public fun mergePending(left: String, right: String): String? {
  val common = minOf(left.length, right.length)
  if (left.take(common) != right.take(common)) return null
  return if (left.length >= right.length) left else right
}

private fun remainingForbidden(words: List<String>, piece: String): List<String>? {
  for (word in words) {
    if (piece.startsWith(word)) return null
  }
  return words.filter { it.startsWith(piece) }.map { it.substring(piece.length) }
}

/** _consume_piece: extend the state's prefix by a literal piece. */
public fun consumePiece(state: RepeatPrefixState, piece: String): RepeatPrefixState? {
  if (piece.isEmpty()) return state
  if (state.excluded.contains(piece[0].code)) return null
  val common = minOf(state.pending.length, piece.length)
  if (state.pending.take(common) != piece.take(common)) return null
  val forbidden = remainingForbidden(state.forbidden, piece) ?: return null
  if (state.text.length + piece.length > REPEAT_PREFIX_BUDGET) {
    throw PatternValidationTimeout("Pattern validation repeat-prefix length budget exceeded")
  }
  return RepeatPrefixState(
      text = state.text + piece,
      pending = state.pending.substring(common),
      excluded = IntervalSet.empty(),
      forbidden = forbidden,
      lastAtom = IntervalSet.single(piece[piece.length - 1].code),
  )
}

/** _consume_atom: consume one atom from the available intervals. */
public fun consumeAtom(state: RepeatPrefixState, intervals: IntervalSet): RepeatPrefixState? {
  var available = intervals.difference(state.excluded)
  for (word in state.forbidden) {
    if (word.length == 1) {
      available = available.difference(IntervalSet.single(word[0].code))
    }
  }
  val member = if (state.pending.isNotEmpty()) state.pending[0].code else available.firstMember()
  if (member == null || !available.contains(member)) return null
  val consumed = consumePiece(state, String(Character.toChars(member))) ?: return null
  return RepeatPrefixState(
      text = consumed.text,
      pending = consumed.pending,
      excluded = consumed.excluded,
      forbidden = consumed.forbidden,
      captures = consumed.captures,
      lastAtom = available,
  )
}

/** _capture_state: record a group's captured prefix text. */
public fun captureState(
    state: RepeatPrefixState,
    group: Int?,
    start: Int,
): RepeatPrefixState {
  if (group == null) return state
  val captures = state.captures.toMap().toMutableMap()
  captures[group] = state.text.substring(start)
  return RepeatPrefixState(
      text = state.text,
      pending = state.pending,
      excluded = state.excluded,
      forbidden = state.forbidden,
      captures = captures.entries.sortedBy { it.key }.map { Pair(it.key, it.value) },
      lastAtom = state.lastAtom,
  )
}

/** _positive_assertion: merge a positive assertion's witnesses into the state. */
public fun positiveAssertion(
    direction: Int,
    witnesses: List<RepeatPrefixState>,
    state: RepeatPrefixState,
): List<RepeatPrefixState> {
  if (direction < 0) {
    return witnesses.map { witness ->
      val newText =
          if (witness.text.isNotEmpty()) {
            state.text.substring(0, state.text.length - witness.text.length) + witness.text
          } else {
            state.text
          }
      val captures =
          (state.captures.toMap() + witness.captures.toMap())
              .entries
              .sortedBy { it.key }
              .map { Pair(it.key, it.value) }
      RepeatPrefixState(
          text = newText,
          pending = state.pending,
          excluded = state.excluded,
          forbidden = state.forbidden,
          captures = captures,
          lastAtom = state.lastAtom,
      )
    }
  }
  val out = ArrayList<RepeatPrefixState>()
  for (witness in witnesses) {
    val pending = mergePending(state.pending, witness.text) ?: continue
    val captures =
        (state.captures.toMap() + witness.captures.toMap())
            .entries
            .sortedBy { it.key }
            .map { Pair(it.key, it.value) }
    out.add(
        RepeatPrefixState(
            text = state.text,
            pending = pending,
            excluded = state.excluded,
            forbidden = state.forbidden,
            captures = captures,
            lastAtom = state.lastAtom,
        ),
    )
  }
  return out
}

/** _negative_assertion: exclude a single-atom body or forbid witness words. */
public fun negativeAssertion(
    body: List<com.guardcore.engine.py.ReNode>,
    flags: Int,
    witnesses: List<RepeatPrefixState>,
    state: RepeatPrefixState,
): List<RepeatPrefixState> {
  if (body.isEmpty()) return emptyList()
  if (body.size == 1 && body[0].op in pairingOpsForHistory) {
    val node = body[0]
    val intervals = nodeIntervals(node, flags)
    return listOf(
        RepeatPrefixState(
            text = state.text,
            pending = state.pending,
            excluded = state.excluded.union(intervals),
            forbidden = state.forbidden,
            captures = state.captures,
            lastAtom = state.lastAtom,
        ),
    )
  }
  val words = witnesses.map { it.text }.filter { it.isNotEmpty() }
  return listOf(
      RepeatPrefixState(
          text = state.text,
          pending = state.pending,
          excluded = state.excluded,
          forbidden = state.forbidden + words,
          captures = state.captures,
          lastAtom = state.lastAtom,
      ),
  )
}
