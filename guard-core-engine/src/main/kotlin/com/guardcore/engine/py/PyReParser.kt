package com.guardcore.engine.py

/**
 * A Python-re-compatible regular-expression parser for the detection engine.
 *
 * The reference safety chain (guard_core/detection_engine) validates patterns against CPython's sre
 * grammar: a pattern the reference oracle rejects at compile time must be rejected here with the
 * same verdict class, including constructs java.util.regex accepts but Python re does not (atomic
 * groups, possessive quantifiers, named groups via (?<name>), group references to undefined groups,
 * ...).
 *
 * The parser is intentionally narrow: it models the sre grammar the reference engine accepts
 * (Python 3.10 grammar is the corpus oracle) and rejects everything else fail-closed. It produces
 * the AST shape the probe-synthesis machinery needs (member intervals per pairing atom, repeat
 * bounds, group tables) in place of Python's re._parser module.
 */
public object PyReFlags {
  public const val IGNORECASE: Int = 1
  public const val MULTILINE: Int = 2
  public const val DOTALL: Int = 4
  public const val ASCII: Int = 8
  public const val LOCALE: Int = 16
  public const val VERBOSE: Int = 32

  /** re.IGNORECASE | re.MULTILINE, the reference engine's default pattern flags. */
  public const val DEFAULT: Int = IGNORECASE or MULTILINE
}

/** Sentinel mirroring re._parser.MAXREPEAT: an unbounded quantifier upper bound. */
public const val SRE_MAXREPEAT: Int = Int.MAX_VALUE

/** AST operations the safety layer models (mirrors the sre_parse op codes it consumes). */
public enum class ReOp {
  LITERAL,
  NOT_LITERAL,
  IN,
  ANY,
  CATEGORY,
  MAX_REPEAT,
  MIN_REPEAT,
  SUBPATTERN,
  BRANCH,
  ASSERT,
  ASSERT_NOT,
  AT,
  GROUPREF,
  GROUPREF_EXISTS,
  NEGATE,
  RANGE,
  ATOMIC_GROUP,
}

/** Anchors (op AT payloads). */
public enum class AtAnchor {
  BEGINNING,
  END,
  BOUNDARY,
  NON_BOUNDARY,
  BEGIN_STRING,
  END_STRING,
}

/** Category shorthand escapes (op CATEGORY payloads). */
public enum class ReCategory {
  DIGIT,
  NOT_DIGIT,
  SPACE,
  NOT_SPACE,
  WORD,
  NOT_WORD,
}

/** sre MAX_REPEAT/MIN_REPEAT payload: (min, max, body). */
public class RepeatAv(public val low: Int, public val high: Int, public val body: List<ReNode>)

/** sre SUBPATTERN payload: (group, add_flags, del_flags, body). */
public class SubPatternAv(
    public val group: Int?,
    public val addFlags: Int,
    public val delFlags: Int,
    public val body: List<ReNode>,
)

/** sre BRANCH payload: alternatives. */
public class BranchAv(public val alternatives: List<List<ReNode>>)

/** sre ASSERT/ASSERT_NOT payload: (direction, body). */
public class AssertAv(public val direction: Int, public val body: List<ReNode>)

/** sre GROUPREF_EXISTS payload: (group, yes, no). */
public class ConditionalAv(
    public val group: Int,
    public val yes: List<ReNode>,
    public val no: List<ReNode>,
)

/** One AST node: an op plus its payload, mirroring a sre_parse (op, av) item. */
public class ReNode(public val op: ReOp, public val av: Any?)

/** Parsed pattern: the node sequence plus the group table and final state flags. */
public class ParsedPattern(
    public val data: List<ReNode>,
    public val groups: Int,
    public val groupNames: Map<String, Int>,
    public val stateFlags: Int,
)

/** Python-re parse failure (mirrors re.error's messages where the corpus can observe them). */
public class ReParseError(public val messageText: String, public val position: Int) :
    RuntimeException("$messageText at position $position")

private class Quant(val low: Int, val high: Int, val length: Int)

private class Dec(val value: Int, val parsed: Boolean)

public class PyReParser(private val src: String, initialFlags: Int) {
  private var pos: Int = 0
  // sre_parse.State starts the group counter at 1; the first opening parenthesis is group 1.
  private var groups: Int = 1
  private val openGroups: MutableSet<Int> = HashSet()
  private val groupNames: MutableMap<String, Int> = HashMap()
  private var flags: Int = initialFlags
  private var nesting: Int = 0
  private var overflow: Boolean = false

  private fun err(message: String, at: Int): ReParseError = ReParseError(message, at)

  private fun atEnd(): Boolean = pos >= src.length

  private fun peek(): Char = src[pos]

  /** sre_parse source.next: the char after the current one, or None. */
  private fun nextChar(): Char? = if (pos + 1 < src.length) src[pos + 1] else null

  private fun getWhile(count: Int, pred: (Char) -> Boolean): String {
    val sb = StringBuilder()
    var i = 0
    while (i < count && pos < src.length && pred(src[pos])) {
      sb.append(src[pos])
      pos++
      i++
    }
    return sb.toString()
  }

  public fun parse(): ParsedPattern {
    val nodes = parseAlternations()
    if (!atEnd()) {
      // A ')' stopped the parse: unbalanced at top level.
      throw err("unbalanced parenthesis", pos)
    }
    return ParsedPattern(nodes, groups, groupNames, flags)
  }

  private fun parseAlternations(): List<ReNode> {
    val branches = ArrayList<List<ReNode>>()
    while (true) {
      val nodes = parseSequence()
      branches.add(nodes)
      if (atEnd() || peek() != '|') break
      pos++
    }
    if (branches.size == 1) return branches[0]
    return listOf(ReNode(ReOp.BRANCH, BranchAv(branches)))
  }

  private fun parseSequence(): List<ReNode> {
    val nodes = ArrayList<ReNode>()
    while (!atEnd()) {
      val c = peek()
      if (c == '|' || c == ')') return nodes
      val item = parseItem() ?: continue
      nodes.add(item)
    }
    return nodes
  }

  private fun parseItem(): ReNode? {
    skipVerbose()
    if (atEnd()) return null
    val atom = parseAtom() ?: return null
    // At most one quantifier per atom: stacking quantifiers is the reference's "multiple
    // repeat" error.
    skipVerbose()
    if (atEnd()) return atom
    val c = peek()
    if (c != '*' && c != '+' && c != '?' && c != '{') return atom
    val q = parseQuantifier()
    if (q == null) {
      if (overflow) throw err("the repetition number is too large", pos)
      // A malformed '{' is a literal (Python behavior): the atom stands and the '{' is
      // handled by the next parseAtom call.
      return atom
    }
    if (atom.op == ReOp.AT) throw err("nothing to repeat", pos - q.length)
    var lazy = false
    if (!atEnd() && peek() == '?') {
      lazy = true
      pos++
    }
    if (!atEnd()) {
      when (peek()) {
        '*',
        '+',
        '?' -> throw err("multiple repeat", pos)
        '{' -> if (probeQuantifier() != null) throw err("multiple repeat", pos)
      }
    }
    val op = if (lazy) ReOp.MIN_REPEAT else ReOp.MAX_REPEAT
    return ReNode(op, RepeatAv(q.low, q.high, listOf(atom)))
  }

  private fun parseQuantifier(): Quant? {
    val start = pos
    when (peek()) {
      '*' -> {
        pos++
        return Quant(0, SRE_MAXREPEAT, 1)
      }
      '+' -> {
        pos++
        return Quant(1, SRE_MAXREPEAT, 1)
      }
      '?' -> {
        pos++
        return Quant(0, 1, 1)
      }
      '{' -> {
        val end = src.indexOf('}', pos)
        if (end < 0) return null
        val body = src.substring(pos + 1, end)
        val parts = body.split(",")
        var lowStr: String
        var highStr: String
        when (parts.size) {
          1 -> {
            lowStr = parts[0]
            highStr = parts[0]
          }
          2 -> {
            lowStr = parts[0]
            highStr = parts[1]
          }
          else -> return null
        }
        if (lowStr.isEmpty() && highStr.isEmpty()) return null
        val low = parseDecimal(lowStr)
        val high = parseDecimal(highStr)
        if (low == null || high == null || !low.parsed || !high.parsed) {
          // An all-digit run that overflowed the sentinel is the reference's "repetition
          // number too large"; junk is a literal. The parsed flag matters: without it an
          // overflowed bound silently degraded to a {0,0} quantifier.
          if (low != null && !low.parsed && isAllDigits(lowStr)) overflow = true
          if (high != null && !high.parsed && isAllDigits(highStr)) overflow = true
          return null
        }
        val hmax = if (highStr.isEmpty()) SRE_MAXREPEAT else high.value
        if (low.value > hmax) return null
        pos = end + 1
        return Quant(low.value, hmax, pos - start)
      }
      else -> return null
    }
  }

  private fun probeQuantifier(): Quant? {
    val saved = pos
    val q = parseQuantifier()
    pos = saved
    return q
  }

  private fun parseDecimal(s: String): Dec? {
    if (s.isEmpty()) return Dec(0, true)
    var n = 0L
    for (ch in s) {
      if (ch < '0' || ch > '9') return null
      n = n * 10 + (ch - '0')
      if (n > SRE_MAXREPEAT) return Dec(0, false)
    }
    return Dec(n.toInt(), true)
  }

  private fun isAllDigits(s: String): Boolean = s.isNotEmpty() && s.all { it in '0'..'9' }

  /** Parses one atom; null means nothing parsed (comment group or global flags consumed). */
  private fun parseAtom(): ReNode? {
    when (val c = peek()) {
      '*',
      '+',
      '?' -> throw err("nothing to repeat", pos)
      '{' -> {
        if (probeQuantifier() != null) throw err("nothing to repeat", pos)
        pos++
        return ReNode(ReOp.LITERAL, '{'.code)
      }
      '^' -> {
        pos++
        return ReNode(ReOp.AT, AtAnchor.BEGINNING)
      }
      '$' -> {
        pos++
        return ReNode(ReOp.AT, AtAnchor.END)
      }
      '[' -> return parseCharClass()
      '(' -> return parseGroup()
      '\\' -> return parseEscapeAtom()
      '.' -> {
        pos++
        return ReNode(ReOp.ANY, null)
      }
      else -> {
        pos++
        return ReNode(ReOp.LITERAL, c.code)
      }
    }
  }

  /** sre_parse _escape: handle escape code in expression. */
  private fun parseEscapeAtom(): ReNode {
    // pos is on the backslash.
    val escapeStart = pos
    val c =
        if (pos + 1 < src.length) src[pos + 1] else throw err("bad escape (end of pattern)", pos)
    var escape = "\\" + c
    pos += 2
    when (c) {
      'A' -> return ReNode(ReOp.AT, AtAnchor.BEGIN_STRING)
      'Z' -> return ReNode(ReOp.AT, AtAnchor.END_STRING)
      'b' -> return ReNode(ReOp.AT, AtAnchor.BOUNDARY)
      'B' -> return ReNode(ReOp.AT, AtAnchor.NON_BOUNDARY)
      'd' -> return inCategoryNode(ReCategory.DIGIT)
      'D' -> return inCategoryNode(ReCategory.NOT_DIGIT)
      's' -> return inCategoryNode(ReCategory.SPACE)
      'S' -> return inCategoryNode(ReCategory.NOT_SPACE)
      'w' -> return inCategoryNode(ReCategory.WORD)
      'W' -> return inCategoryNode(ReCategory.NOT_WORD)
      'a' -> return ReNode(ReOp.LITERAL, 0x07)
      'f' -> return ReNode(ReOp.LITERAL, 0x0C)
      'n' -> return ReNode(ReOp.LITERAL, '\n'.code)
      'r' -> return ReNode(ReOp.LITERAL, '\r'.code)
      't' -> return ReNode(ReOp.LITERAL, '\t'.code)
      'v' -> return ReNode(ReOp.LITERAL, 0x0B)
      '\\' -> return ReNode(ReOp.LITERAL, '\\'.code)
      'x' -> {
        escape += getWhile(2) { it.isHexDigitInternal() }
        if (escape.length != 4) throw err("incomplete escape $escape", escapeStart)
        return ReNode(ReOp.LITERAL, escape.substring(2).toInt(16))
      }
      'u' -> {
        escape += getWhile(4) { it.isHexDigitInternal() }
        if (escape.length != 6) throw err("incomplete escape $escape", escapeStart)
        return ReNode(ReOp.LITERAL, escape.substring(2).toInt(16))
      }
      'U' -> {
        escape += getWhile(8) { it.isHexDigitInternal() }
        if (escape.length != 10) throw err("incomplete escape $escape", escapeStart)
        return ReNode(ReOp.LITERAL, escape.substring(2).toInt(16))
      }
      'N' -> {
        // The \\N{NAME} named escape has no java.util.regex equivalent and the JVM exposes
        // no name-to-codepoint table on JDK 17: fail closed (python raises "undefined
        // character name" for unknown names; this engine raises for all names).
        throw err("bad escape \\N", escapeStart)
      }
      '0' -> {
        escape += getWhile(2) { it in '0'..'7' }
        return ReNode(ReOp.LITERAL, escape.substring(1).toInt(8))
      }
      else -> {
        if (c in '1'..'9') {
          if (nextChar() != null && nextChar()!! in '0'..'9') {
            escape += src[pos]
            pos++
            // python's source.next is the UNCONSUMED char at pos, not the one
            // after it: without this peek the third octal digit is missed and
            // \\101 parses as group reference 10 instead of octal 65.
            if (escape[1] in '0'..'7' && escape[2] in '0'..'7' && !atEnd() && peek() in '0'..'7') {
              // Got three octal digits: this is an octal escape.
              escape += src[pos]
              pos++
              val value = escape.substring(1).toInt(8)
              if (value > 0xFF) {
                throw err("octal escape value $escape outside of range 0-0o377", escapeStart)
              }
              return ReNode(ReOp.LITERAL, value)
            }
          }
          // Not an octal escape, so this is a group reference.
          val group = escape.substring(1).toInt()
          if (group < groups) {
            if (openGroups.contains(group)) {
              throw err("cannot refer to an open group", escapeStart)
            }
            return ReNode(ReOp.GROUPREF, group)
          }
          throw err("invalid group reference $group", escapeStart + 1)
        }
        if (c == 'g') {
          // sre_parse \g<num> / \g<name>: the spelled-out group-reference form.
          if (atEnd() || peek() != '<') throw err("bad escape \\g", escapeStart)
          pos++ // consume the '<'
          val refStart = pos
          while (!atEnd() && peek() != '>') pos++
          if (atEnd()) throw err("missing >, unterminated name", escapeStart)
          val ref = src.substring(refStart, pos)
          pos++ // consume the '>'
          if (ref.isEmpty()) throw err("missing group name", refStart)
          if (ref[0] in '0'..'9') {
            if (!ref.all { it in '0'..'9' }) throw err("bad character in group name", refStart)
            val group = ref.toInt()
            if (group >= groups) throw err("invalid group reference $group", refStart)
            if (openGroups.contains(group)) {
              throw err("cannot refer to an open group", escapeStart)
            }
            return ReNode(ReOp.GROUPREF, group)
          }
          if (!ref.all { it.isLetterOrDigit() || it == '_' }) {
            throw err("bad character in group name", refStart)
          }
          val idx = groupNames[ref] ?: throw err("unknown group name '$ref'", refStart)
          return ReNode(ReOp.GROUPREF, idx)
        }
        if (c.isAsciiLetterInternal()) throw err("bad escape \\$c", escapeStart)
        return ReNode(ReOp.LITERAL, c.code)
      }
    }
  }

  /** sre_parse _class_escape: handle escape code inside a character class. */
  private fun parseClassEscape(): ReNode {
    val escapeStart = pos
    val c =
        if (pos + 1 < src.length) src[pos + 1] else throw err("bad escape (end of pattern)", pos)
    var escape = "\\" + c
    pos += 2
    when (c) {
      'a' -> return ReNode(ReOp.LITERAL, 0x07)
      'b' -> return ReNode(ReOp.LITERAL, 0x08)
      'f' -> return ReNode(ReOp.LITERAL, 0x0C)
      'n' -> return ReNode(ReOp.LITERAL, '\n'.code)
      'r' -> return ReNode(ReOp.LITERAL, '\r'.code)
      't' -> return ReNode(ReOp.LITERAL, '\t'.code)
      'v' -> return ReNode(ReOp.LITERAL, 0x0B)
      '\\' -> return ReNode(ReOp.LITERAL, '\\'.code)
      'd' -> return ReNode(ReOp.CATEGORY, ReCategory.DIGIT)
      'D' -> return ReNode(ReOp.CATEGORY, ReCategory.NOT_DIGIT)
      's' -> return ReNode(ReOp.CATEGORY, ReCategory.SPACE)
      'S' -> return ReNode(ReOp.CATEGORY, ReCategory.NOT_SPACE)
      'w' -> return ReNode(ReOp.CATEGORY, ReCategory.WORD)
      'W' -> return ReNode(ReOp.CATEGORY, ReCategory.NOT_WORD)
      'x' -> {
        escape += getWhile(2) { it.isHexDigitInternal() }
        if (escape.length != 4) throw err("incomplete escape $escape", escapeStart)
        return ReNode(ReOp.LITERAL, escape.substring(2).toInt(16))
      }
      'u' -> {
        escape += getWhile(4) { it.isHexDigitInternal() }
        if (escape.length != 6) throw err("incomplete escape $escape", escapeStart)
        return ReNode(ReOp.LITERAL, escape.substring(2).toInt(16))
      }
      'U' -> {
        escape += getWhile(8) { it.isHexDigitInternal() }
        if (escape.length != 10) throw err("incomplete escape $escape", escapeStart)
        return ReNode(ReOp.LITERAL, escape.substring(2).toInt(16))
      }
      'N' -> throw err("bad escape \\N", escapeStart)
      else -> {
        if (c in '0'..'7') {
          escape += getWhile(2) { it in '0'..'7' }
          val value = escape.substring(1).toInt(8)
          if (value > 0xFF) {
            throw err("octal escape value $escape outside of range 0-0o377", escapeStart)
          }
          return ReNode(ReOp.LITERAL, value)
        }
        if (c.isDigitInternal()) throw err("bad escape \\$c", escapeStart)
        if (c.isAsciiLetterInternal()) throw err("bad escape \\$c", escapeStart)
        return ReNode(ReOp.LITERAL, c.code)
      }
    }
  }

  /** Parses a character class beginning at '['. */
  private fun parseCharClass(): ReNode {
    val open = pos
    pos++ // consume '['
    val items = ArrayList<ReNode>()
    var negate = false
    if (!atEnd() && peek() == '^') {
      negate = true
      pos++
    }
    var first = true
    while (true) {
      if (atEnd()) throw err("unterminated character set", open)
      val c = peek()
      if (c == ']' && !first) {
        pos++
        break
      }
      first = false
      val lowNode =
          if (c == '\\') {
            parseClassEscape()
          } else {
            pos++
            ReNode(ReOp.LITERAL, c.code)
          }
      // Range?
      if (!atEnd() && peek() == '-' && pos + 1 < src.length && src[pos + 1] != ']') {
        pos++ // consume '-'
        if (atEnd()) throw err("unterminated character set", open)
        val c2 = peek()
        val highNode =
            if (c2 == '\\') {
              parseClassEscape()
            } else {
              pos++
              ReNode(ReOp.LITERAL, c2.code)
            }
        if (lowNode.op != ReOp.LITERAL || highNode.op != ReOp.LITERAL) {
          throw err("bad character range", pos)
        }
        val lo = lowNode.av as Int
        val hi = highNode.av as Int
        if (hi < lo) throw err("bad character range", pos)
        items.add(ReNode(ReOp.RANGE, Pair(lo, hi)))
      } else {
        items.add(lowNode)
      }
    }
    if (negate) items.add(0, ReNode(ReOp.NEGATE, null))
    return ReNode(ReOp.IN, items)
  }

  private fun inCategoryNode(category: ReCategory): ReNode =
      ReNode(ReOp.IN, listOf(ReNode(ReOp.CATEGORY, category)))

  private fun parseGroup(): ReNode? {
    val open = pos
    pos++ // consume '('
    if (atEnd()) throw err("missing ), unterminated subpattern", open)
    if (peek() != '?') {
      // Plain capturing group (sre_parse.opengroup assigns the current counter then
      // increments).
      val idx = groups
      groups++
      openGroups.add(idx)
      val body = parseGroupBody(open)
      openGroups.remove(idx)
      return ReNode(ReOp.SUBPATTERN, SubPatternAv(idx, 0, 0, body))
    }
    pos++ // consume '?'
    if (atEnd()) throw err("unknown extension", open)
    when (peek()) {
      'P' -> {
        pos++
        if (atEnd()) throw err("unknown extension ?P", open)
        when (peek()) {
          '<' -> return parseNamedGroup(open)
          '=' -> {
            pos++
            val nameStart = pos
            val name = parseGroupNameToken(')')
            if (atEnd() || peek() != ')') throw err("missing ), unterminated name", open)
            pos++
            val idx = groupNames[name] ?: throw err("unknown group name '$name'", nameStart)
            return ReNode(ReOp.GROUPREF, idx)
          }
          else -> throw err("unknown extension ?P" + peek(), open)
        }
      }
      '<' -> {
        pos++
        if (!atEnd() && (peek() == '=' || peek() == '!')) {
          val negative = peek() == '!'
          pos++
          val body = parseGroupBody(open)
          return ReNode(if (negative) ReOp.ASSERT_NOT else ReOp.ASSERT, AssertAv(-1, body))
        }
        // (?<name>...) is Python 3.11+ syntax; the corpus oracle grammar (Python 3.10)
        // rejects it fail-closed.
        throw err("unknown extension ?<", open)
      }
      '=' -> {
        pos++
        val body = parseGroupBody(open)
        return ReNode(ReOp.ASSERT, AssertAv(1, body))
      }
      '!' -> {
        pos++
        val body = parseGroupBody(open)
        return ReNode(ReOp.ASSERT_NOT, AssertAv(1, body))
      }
      ':' -> {
        pos++
        val body = parseGroupBody(open)
        return ReNode(ReOp.SUBPATTERN, SubPatternAv(null, 0, 0, body))
      }
      '#' -> {
        // Comment group: scan to the closing ')'.
        val end = src.indexOf(')', pos)
        if (end < 0) throw err("missing ), unterminated comment", open)
        pos = end + 1
        return null
      }
      '>' -> {
        // Atomic group: valid Python 3.11+ syntax, rejected by the corpus oracle grammar
        // (Python 3.10) fail-closed.
        throw err("unknown extension ?>", open)
      }
      '(' -> throw err("unknown extension ?(", open)
      else -> return parseInlineFlags(open)
    }
  }

  private fun parseNamedGroup(open: Int): ReNode {
    pos++ // consume '<'
    val nameStart = pos
    val name = parseGroupNameToken('>')
    if (atEnd() || peek() != '>') throw err("missing >, unterminated name", open)
    pos++
    if (groupNames.containsKey(name)) {
      throw err("redefinition of group name '$name'", nameStart)
    }
    val idx = groups
    groups++
    groupNames[name] = idx
    openGroups.add(idx)
    val body = parseGroupBody(open)
    openGroups.remove(idx)
    return ReNode(ReOp.SUBPATTERN, SubPatternAv(idx, 0, 0, body))
  }

  private fun parseGroupBody(open: Int): List<ReNode> {
    nesting++
    if (nesting > MAX_GROUP_NESTING_DEPTH) {
      throw err(
          "sorry, but this version only supports $MAX_GROUP_NESTING_DEPTH nested parentheses",
          open,
      )
    }
    try {
      val body = parseAlternations()
      if (atEnd() || peek() != ')') throw err("missing ), unterminated subpattern", open)
      pos++
      return body
    } finally {
      nesting--
    }
  }

  /** Handles (?flags), (?flags:...) and (?flags-i:...). */
  private fun parseInlineFlags(open: Int): ReNode? {
    var add = 0
    var remove = 0
    var negative = false
    while (!atEnd()) {
      when (val c = peek()) {
        'i' -> {
          if (negative) remove = remove or PyReFlags.IGNORECASE
          else add = add or PyReFlags.IGNORECASE
        }
        'm' -> {
          if (negative) remove = remove or PyReFlags.MULTILINE else add = add or PyReFlags.MULTILINE
        }
        's' -> {
          if (negative) remove = remove or PyReFlags.DOTALL else add = add or PyReFlags.DOTALL
        }
        'a' -> {
          if (negative) remove = remove or PyReFlags.ASCII else add = add or PyReFlags.ASCII
        }
        'L' -> {
          // re.LOCALE is fail-closed for this port (the top-level flag gate raises the same
          // UnsupportedPatternFeature); a scoped (?L:...) must not leak into the java pattern,
          // where it would die later as a bare "Unknown inline modifier" compile error.
          throw com.guardcore.engine.py.PyRe.UnsupportedPatternFeature(
              "re.LOCALE has no java.util.regex equivalent",
          )
        }
        'x' -> {
          if (negative) remove = remove or PyReFlags.VERBOSE else add = add or PyReFlags.VERBOSE
        }
        'u' -> {}
        '-' ->
            if (negative) {
              throw err("global flags not at the start of the expression", open)
            } else {
              negative = true
            }
        ':' -> {
          pos++
          val saved = flags
          flags = (flags or add) and remove.inv()
          val body = parseGroupBody(open)
          flags = saved
          return ReNode(ReOp.SUBPATTERN, SubPatternAv(null, add, remove, body))
        }
        ')' -> {
          // Global flags: only legal when the opening parenthesis is at the very start.
          if (open != 0) throw err("global flags not at the start of the expression", open)
          pos++
          flags = (flags or add) and remove.inv()
          return null
        }
        else -> throw err("unknown flag", pos)
      }
      pos++
    }
    throw err("unknown flag", open)
  }

  private fun parseGroupNameToken(end: Char): String {
    val start = pos
    while (!atEnd() && peek() != end) pos++
    return src.substring(start, pos)
  }

  private fun skipVerbose() {
    if (flags and PyReFlags.VERBOSE == 0) return
    while (!atEnd()) {
      val c = peek()
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '' || c == '') {
        pos++
        continue
      }
      if (c == '#') {
        val end = src.indexOf('\n', pos)
        if (end < 0) {
          pos = src.length
          return
        }
        pos = end + 1
        continue
      }
      return
    }
  }

  public companion object {
    /** Mirrors _MAX_GROUP_NESTING_DEPTH. */
    public const val MAX_GROUP_NESTING_DEPTH: Int = 20

    public fun parse(pattern: String, flags: Int): ParsedPattern =
        PyReParser(pattern, flags).parse()

    private fun Char.isHexDigitInternal(): Boolean =
        this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private fun Char.isDigitInternal(): Boolean = this in '0'..'9'

    private fun Char.isAsciiLetterInternal(): Boolean = this in 'a'..'z' || this in 'A'..'Z'
  }
}
