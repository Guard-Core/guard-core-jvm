package com.guardcore.engine.py

import java.util.regex.Matcher
import java.util.regex.Pattern

/**
 * Python-re compile/execute semantics on top of java.util.regex.
 *
 * Flag mapping (python -> java):
 * - IGNORECASE -> CASE_INSENSITIVE | UNICODE_CASE
 * - MULTILINE -> MULTILINE
 * - DOTALL -> DOTALL
 * - ASCII -> nothing (java \d \s \w are ASCII-only by default)
 * - otherwise (Unicode default) -> UNICODE_CHARACTER_CLASS, so \d \s \w are Unicode-aware
 * - LOCALE -> unsupported (fail-closed); VERBOSE -> COMMENTS
 * - UNIX_LINES is always set: python `.` excludes only \n and `$` anchors only at \n, which java's
 *   default line-terminator set (CR LF NEL LS PS) would widen.
 *
 * Source translation (python-only constructs, everything else is copied verbatim):
 * - \Z -> \z (python \Z is the absolute end of input)
 * - (?P<name> -> (?<name>, (?P=name) -> \k<name>
 * - (?-i:...) flag removal: java cannot lower a flag inside a pattern, so the pattern is
 *   restructured: compiled without the removed flag globally and every other segment is wrapped in
 *   its own scoped positive flag group (see rewriteNegativeFlagScopes).
 * - \g<n> / \g<name> -> \n / \k<name>; \N{NAME} -> the raw character.
 * - {,n} -> {0,n}.
 */
public object PyRe {

  /** Compile-time failure after the python grammar check (java rejected the translated source). */
  public class ReCompileError(message: String) : RuntimeException(message)

  /** A python-accepted construct this engine cannot compile under java.util.regex. */
  public class UnsupportedPatternFeature(message: String) : RuntimeException(message)

  private fun javaFlagsFor(pythonFlags: Int): Int {
    if (pythonFlags and PyReFlags.LOCALE != 0) {
      throw UnsupportedPatternFeature("re.LOCALE has no java.util.regex equivalent")
    }
    var flags = Pattern.UNIX_LINES
    if (pythonFlags and PyReFlags.IGNORECASE != 0) {
      flags = flags or Pattern.CASE_INSENSITIVE or Pattern.UNICODE_CASE
    }
    if (pythonFlags and PyReFlags.MULTILINE != 0) flags = flags or Pattern.MULTILINE
    if (pythonFlags and PyReFlags.DOTALL != 0) flags = flags or Pattern.DOTALL
    if (pythonFlags and PyReFlags.VERBOSE != 0) flags = flags or Pattern.COMMENTS
    if (pythonFlags and PyReFlags.ASCII == 0) {
      flags = flags or Pattern.UNICODE_CHARACTER_CLASS
    }
    return flags
  }

  /** python 3.7+ re.escape: escape only the special characters. */
  public fun escapeSource(text: String): String {
    val specials = "()[]{}?*+-|^\$\\.&~# \t\n\r\u000B\u000C"
    val sb = StringBuilder(text.length + 8)
    for (ch in text) {
      if (specials.indexOf(ch) != -1) sb.append('\\')
      sb.append(ch)
    }
    return sb.toString()
  }

  /**
   * Validates the pattern against the python sre grammar (fail-closed) and returns the parse. A
   * python-invalid pattern raises [ReParseError] with the reference's message text.
   */
  public fun parse(pattern: String, flags: Int): ParsedPattern = PyReParser.parse(pattern, flags)

  /** True when the pattern's parse tree contains a negative inline flag scope. */
  private fun hasNegativeFlagScope(nodes: List<ReNode>): Boolean = nodes.any { node ->
    when (node.op) {
      ReOp.SUBPATTERN -> {
        val av = node.av as SubPatternAv
        av.delFlags != 0 || hasNegativeFlagScope(av.body)
      }
      ReOp.MAX_REPEAT,
      ReOp.MIN_REPEAT -> hasNegativeFlagScope((node.av as RepeatAv).body)
      ReOp.BRANCH -> (node.av as BranchAv).alternatives.any { hasNegativeFlagScope(it) }
      ReOp.ASSERT,
      ReOp.ASSERT_NOT -> hasNegativeFlagScope((node.av as AssertAv).body)
      else -> false
    }
  }

  private fun flagLetters(flags: Int): String {
    val sb = StringBuilder()
    if (flags and PyReFlags.IGNORECASE != 0) sb.append('i')
    if (flags and PyReFlags.MULTILINE != 0) sb.append('m')
    if (flags and PyReFlags.DOTALL != 0) sb.append('s')
    if (flags and PyReFlags.VERBOSE != 0) sb.append('x')
    return sb.toString()
  }

  /**
   * Compiles a python pattern for the JVM: python grammar validation (fail-closed), source
   * translation, then java.util.regex compilation. The returned pattern carries the python source
   * it was built from.
   */
  public fun compile(pattern: String, flags: Int): PyRePattern {
    val parsed = parse(pattern, flags)
    val (javaSource, effectiveFlags) =
        if (hasNegativeFlagScope(parsed.data)) {
          rewriteNegativeFlagScopes(parsed.data, flags)
        } else {
          Pair(translateSource(pattern), flags)
        }
    return try {
      val java = Pattern.compile(javaSource, javaFlagsFor(effectiveFlags))
      PyRePattern(pattern, flags, javaSource, java, parsed.groups)
    } catch (e: Exception) {
      throw ReCompileError("Pattern validation failed: ${e.message}")
    }
  }

  /**
   * Verbatim-copy translation for patterns without negative flag scopes. Class-aware: python treats
   * a `{` that is not a well-formed quantifier as a literal, while java rejects it ("illegal
   * repetition"), so non-quantifier braces are escaped.
   */
  public fun translateSource(pattern: String): String {
    val quantifier = Regex("\\{[0-9]*,?[0-9]*\\}")
    val sb = StringBuilder(pattern.length + 8)
    var i = 0
    val n = pattern.length
    var inClass = false
    while (i < n) {
      val c = pattern[i]
      when {
        c == '\\' && i + 1 < n -> {
          val next = pattern[i + 1]
          when {
            next == 'Z' -> {
              sb.append("\\z")
              i += 2
            }
            next == 'g' && i + 2 < n && pattern[i + 2] == '<' -> {
              val close = pattern.indexOf('>', i + 3)
              if (close < 0) {
                sb.append(c)
                i++
              } else {
                val ref = pattern.substring(i + 3, close)
                if (ref.isNotEmpty() && ref.all { it in '0'..'9' }) {
                  sb.append('\\').append(ref)
                } else {
                  sb.append("\\k<").append(ref).append('>')
                }
                i = close + 1
              }
            }
            else -> {
              sb.append(c).append(next)
              i += 2
            }
          }
        }
        c == '[' -> {
          inClass = true
          sb.append(c)
          i++
          // A leading ] in a class is a literal (python behavior).
          if (i < n && pattern[i] == ']') {
            sb.append(']')
            i++
          }
        }
        c == ']' && inClass -> {
          inClass = false
          sb.append(c)
          i++
        }
        c == '{' && !inClass -> {
          val close = pattern.indexOf('}', i)
          val body = if (close > i) pattern.substring(i + 1, close) else null
          val isQuantifier =
              body != null &&
                  body.split(",").let { parts ->
                    parts.size <= 2 &&
                        parts.all { it.isEmpty() || it.all { ch -> ch in '0'..'9' } } &&
                        parts.any { it.isNotEmpty() }
                  }
          val matches = body?.let { quantifier.matchEntire("{" + it + "}") } != null
          if (isQuantifier && matches) {
            // python {,m} means {0,m}; java has no such form.
            val parts = body!!.split(",")
            if (parts.size == 2 && parts[0].isEmpty()) {
              sb.append("{0,").append(parts[1]).append('}')
            } else {
              sb.append(pattern, i, close + 1)
            }
            i = close + 1
          } else {
            // python: a malformed { is a literal; java rejects it: escape.
            sb.append("\\{")
            i++
          }
        }
        else -> {
          sb.append(c)
          i++
        }
      }
    }
    return sb.toString()
  }

  /**
   * Restructures a pattern containing (?-i:...) scopes: emits AST segments where non-locked parts
   * are wrapped in scoped positive flag groups and locked parts are emitted bare. The compiled
   * pattern drops those flags globally. Only IGNORECASE removal occurs in the reference pattern
   * tables.
   */
  private fun rewriteNegativeFlagScopes(nodes: List<ReNode>, flags: Int): Pair<String, Int> {
    val removed = collectRemovedFlags(nodes, 0)
    val base = flags and removed.inv()
    val sb = StringBuilder()
    emitScopedNodes(sb, nodes, base, flags)
    return Pair(sb.toString(), base)
  }

  private fun collectRemovedFlags(nodes: List<ReNode>, depth: Int): Int {
    if (depth > PyReParser.MAX_GROUP_NESTING_DEPTH) return 0
    var removed = 0
    for (node in nodes) {
      when (node.op) {
        ReOp.SUBPATTERN -> {
          val av = node.av as SubPatternAv
          removed = removed or av.delFlags
          removed = removed or collectRemovedFlags(av.body, depth + 1)
        }
        ReOp.MAX_REPEAT,
        ReOp.MIN_REPEAT ->
            removed = removed or collectRemovedFlags((node.av as RepeatAv).body, depth + 1)
        ReOp.BRANCH -> {
          for (alt in (node.av as BranchAv).alternatives) {
            removed = removed or collectRemovedFlags(alt, depth + 1)
          }
        }
        ReOp.ASSERT,
        ReOp.ASSERT_NOT ->
            removed = removed or collectRemovedFlags((node.av as AssertAv).body, depth + 1)
        else -> {}
      }
    }
    return removed
  }

  private fun emitScopedNodes(
      sb: StringBuilder,
      nodes: List<ReNode>,
      baseFlags: Int,
      topFlags: Int,
  ) {
    for (node in nodes) {
      when (node.op) {
        ReOp.SUBPATTERN -> {
          val av = node.av as SubPatternAv
          val inner = baseFlags or av.addFlags
          val bodySb = StringBuilder()
          emitScopedNodes(bodySb, av.body, inner and av.delFlags.inv(), topFlags)
          val scoped = av.delFlags == 0 && av.addFlags == 0
          if (av.group != null) {
            if (scoped) {
              sb.append('(').append(bodySb).append(')')
            } else {
              // Keep the capturing group outermost; the flag scope nests inside it.
              sb.append("(?").append(flagLetters(inner)).append(":(").append(bodySb).append("))")
            }
          } else {
            if (scoped) {
              sb.append(bodySb)
            } else {
              sb.append("(?").append(flagLetters(inner)).append(':').append(bodySb).append(')')
            }
          }
        }
        ReOp.MAX_REPEAT,
        ReOp.MIN_REPEAT -> {
          val av = node.av as RepeatAv
          val bodySb = StringBuilder()
          emitScopedNodes(bodySb, av.body, baseFlags, topFlags)
          sb.append(bodySb)
          emitQuantifier(sb, node.op == ReOp.MIN_REPEAT, av.low, av.high)
        }
        else -> {
          val nodeSb = StringBuilder()
          emitNodeSource(nodeSb, node, baseFlags)
          if (needsCiWrapper(node, baseFlags)) {
            sb.append("(?").append(flagLetters(baseFlags)).append(':').append(nodeSb).append(')')
          } else {
            sb.append(nodeSb)
          }
        }
      }
    }
  }

  /** Non-locked segments inside a flag-restructured pattern need their CI re-applied. */
  private fun needsCiWrapper(node: ReNode, baseFlags: Int): Boolean =
      baseFlags and PyReFlags.IGNORECASE != 0 && nodeTouchesLiteralText(node)

  private fun nodeTouchesLiteralText(node: ReNode): Boolean =
      when (node.op) {
        ReOp.LITERAL,
        ReOp.NOT_LITERAL,
        ReOp.IN,
        ReOp.ANY -> true
        ReOp.MAX_REPEAT,
        ReOp.MIN_REPEAT -> nodeTouchesLiteralText((node.av as RepeatAv).body[0])
        else -> false
      }

  /** Emits java source for one non-group AST node (used by the negative-flag rewriter). */
  private fun emitNodeSource(sb: StringBuilder, node: ReNode, flags: Int) {
    when (node.op) {
      ReOp.LITERAL -> appendLiteralChar(sb, node.av as Int)
      ReOp.NOT_LITERAL -> {
        sb.append("[^")
        appendLiteralChar(sb, node.av as Int)
        sb.append(']')
      }
      ReOp.ANY -> sb.append('.')
      ReOp.IN -> emitClassSource(sb, node.av as List<ReNode>)
      ReOp.CATEGORY -> sb.append(categoryEscape(node.av as ReCategory))
      ReOp.AT ->
          sb.append(
              when (node.av as AtAnchor) {
                AtAnchor.BEGINNING -> "^"
                AtAnchor.END -> "$"
                AtAnchor.BOUNDARY -> "\\b"
                AtAnchor.NON_BOUNDARY -> "\\B"
                AtAnchor.BEGIN_STRING -> "\\A"
                AtAnchor.END_STRING -> "\\z"
              },
          )
      ReOp.GROUPREF -> sb.append('\\').append(node.av as Int)
      ReOp.ASSERT ->
          if ((node.av as AssertAv).direction < 0) {
            sb.append("(?<=").append(emitBodySource(node.av.body, flags)).append(')')
          } else {
            sb.append("(?=").append(emitBodySource(node.av.body, flags)).append(')')
          }
      ReOp.ASSERT_NOT ->
          if ((node.av as AssertAv).direction < 0) {
            sb.append("(?<!").append(emitBodySource(node.av.body, flags)).append(')')
          } else {
            sb.append("(?!").append(emitBodySource(node.av.body, flags)).append(')')
          }
      ReOp.BRANCH -> {
        val alts = (node.av as BranchAv).alternatives
        sb.append("(?:")
        alts.forEachIndexed { index, alt ->
          if (index > 0) sb.append('|')
          sb.append(emitBodySource(alt, flags))
        }
        sb.append(')')
      }
      else ->
          throw UnsupportedPatternFeature(
              "python construct ${node.op} inside a (?-i:...) scope is not supported",
          )
    }
  }

  private fun emitBodySource(nodes: List<ReNode>, flags: Int): String {
    val sb = StringBuilder()
    emitScopedNodes(sb, nodes, flags, flags)
    return sb.toString()
  }

  private fun emitClassSource(sb: StringBuilder, items: List<ReNode>) {
    sb.append('[')
    for (item in items) {
      when (item.op) {
        ReOp.NEGATE -> sb.append('^')
        ReOp.LITERAL -> appendLiteralChar(sb, item.av as Int)
        ReOp.RANGE -> {
          val (lo, hi) = item.av as Pair<Int, Int>
          appendLiteralChar(sb, lo)
          sb.append('-')
          appendLiteralChar(sb, hi)
        }
        ReOp.CATEGORY -> sb.append(categoryEscape(item.av as ReCategory))
        else ->
            throw UnsupportedPatternFeature(
                "python construct ${item.op} inside a (?-i:...) scope is not supported",
            )
      }
    }
    sb.append(']')
  }

  private fun emitQuantifier(sb: StringBuilder, lazy: Boolean, low: Int, high: Int) {
    when {
      low == 0 && high == SRE_MAXREPEAT -> sb.append('*')
      low == 1 && high == SRE_MAXREPEAT -> sb.append('+')
      low == 0 && high == 1 -> sb.append('?')
      low == high -> sb.append('{').append(low).append('}')
      high == SRE_MAXREPEAT -> sb.append('{').append(low).append(",}")
      else -> sb.append('{').append(low).append(',').append(high).append('}')
    }
    if (lazy) sb.append('?')
  }

  private fun categoryEscape(category: ReCategory): String =
      when (category) {
        ReCategory.DIGIT -> "\\d"
        ReCategory.NOT_DIGIT -> "\\D"
        ReCategory.SPACE -> "\\s"
        ReCategory.NOT_SPACE -> "\\S"
        ReCategory.WORD -> "\\w"
        ReCategory.NOT_WORD -> "\\W"
      }

  /** Appends a literal code point to java pattern source, escaping regex metacharacters. */
  private fun appendLiteralChar(sb: StringBuilder, cp: Int) {
    if (cp in 0x30..0x39 || cp in 0x41..0x5A || cp in 0x61..0x7A) {
      sb.appendCodePoint(cp)
      return
    }
    when (cp) {
      '\n'.code -> {
        sb.append("\\n")
        return
      }
      '\r'.code -> {
        sb.append("\\r")
        return
      }
      '\t'.code -> {
        sb.append("\\t")
        return
      }
      0x0C -> {
        sb.append("\\f")
        return
      }
      0x0B -> {
        sb.append("\\x0B")
        return
      }
      0x07 -> {
        sb.append("\\x07")
        return
      }
      0x08 -> {
        sb.append("\\x08")
        return
      }
    }
    if (cp < 0x80 && !cp.toChar().isLetterOrDigit()) {
      sb.append('\\').appendCodePoint(cp)
      return
    }
    sb.appendCodePoint(cp)
  }

  /**
   * The engine-wide hard match deadline (Go posture: DeadlineCharSequence abort idiom). The
   * wall-clock budget is checked inside the character sequence the matcher reads, so a catastrophic
   * pattern aborts with [DeadlineExceededException] instead of pinning the thread.
   */
  public class DeadlineExceededException :
      RuntimeException("regex match exceeded its hard deadline")

  public class DeadlineCharSequence(
      private val inner: CharSequence,
      private val deadlineNanos: Long,
  ) : CharSequence {
    private var ticks: Int = 0

    override val length: Int
      get() = inner.length

    override fun get(index: Int): Char {
      // Long.MAX_VALUE is the "no deadline" sentinel: the strict > check can never fire.
      if (
          (++ticks and 0x1FF) == 0 &&
              deadlineNanos != Long.MAX_VALUE &&
              System.nanoTime() > deadlineNanos
      ) {
        throw DeadlineExceededException()
      }
      return inner[index]
    }

    override fun subSequence(startIndex: Int, endIndex: Int): CharSequence =
        DeadlineCharSequence(inner.subSequence(startIndex, endIndex), deadlineNanos)

    override fun toString(): String = inner.toString()

    public companion object {
      /** Wraps [text] with a deadline [timeoutSeconds] in the future (0 or less = no deadline). */
      public fun withTimeout(text: CharSequence, timeoutSeconds: Double): CharSequence {
        if (timeoutSeconds <= 0.0) return text
        val nanos = (timeoutSeconds * 1e9).toLong()
        val now = System.nanoTime()
        val deadline = if (nanos > Long.MAX_VALUE - now) Long.MAX_VALUE else now + nanos
        return DeadlineCharSequence(text, deadline)
      }

      public fun absolute(text: CharSequence, deadlineNanos: Long): CharSequence =
          DeadlineCharSequence(text, deadlineNanos)
    }
  }
}

/** A compiled python pattern: python source in, java.util.regex behavior out. */
public class PyRePattern(
    public val source: String,
    public val flags: Int,
    public val javaSource: String,
    private val java: Pattern,
    public val groups: Int,
) {
  private fun matcherFor(text: CharSequence): Matcher = java.matcher(text)

  /**
   * python re.finditer: all matches scanning the whole input. Lookbehind sees the entire string
   * before each attempt position; \A anchors at absolute 0. Runs on the big-stack scan pool
   * (java.util.regex recurses per group-repetition iteration).
   */
  public fun finditer(text: String, deadlineNanos: Long): List<PyReMatch> {
    val cs = PyRe.DeadlineCharSequence.absolute(text, deadlineNanos)
    val m = matcherFor(cs)
    val out = ArrayList<PyReMatch>()
    while (m.find()) out.add(PyReMatch(text, m, this))
    return out
  }

  /** python re.search from [start]. */
  public fun search(text: String, start: Int, deadlineNanos: Long): PyReMatch? {
    if (start > text.length) return null
    val cs = PyRe.DeadlineCharSequence.absolute(text, deadlineNanos)
    val m = matcherFor(cs)
    return if (m.find(start)) PyReMatch(text, m, this) else null
  }

  /**
   * python re.search(string, pos, endpos): search within [start, endpos) with the whole string
   * visible to lookbehind and anchors.
   */
  public fun search(
      text: String,
      start: Int,
      endpos: Int,
      deadlineNanos: Long,
  ): PyReMatch? {
    if (start > text.length || endpos < start) return null
    val cs = PyRe.DeadlineCharSequence.absolute(text, deadlineNanos)
    val m = matcherFor(cs)
    m.region(start, endpos.coerceAtMost(text.length))
    m.useTransparentBounds(true)
    m.useAnchoringBounds(false)
    return if (m.find()) PyReMatch(text, m, this) else null
  }

  /**
   * python re.match anchored at [pos] with python endpos semantics: transparent bounds so
   * lookbehind can inspect characters before pos (CPython behavior), non-anchoring bounds so \A
   * still means absolute start of input.
   */
  public fun matchAt(text: String, pos: Int, endpos: Int, deadlineNanos: Long): PyReMatch? {
    if (pos < 0 || pos > text.length || endpos < pos) return null
    val cs = PyRe.DeadlineCharSequence.absolute(text, deadlineNanos)
    val m = matcherFor(cs)
    m.region(pos, endpos.coerceAtMost(text.length))
    m.useTransparentBounds(true)
    m.useAnchoringBounds(false)
    return if (m.lookingAt()) PyReMatch(text, m, this) else null
  }

  /**
   * python pattern.match(slice) where the caller passes an already-extracted substring: the region
   * behaves as the whole string, so \A / \Z / ^ / $ anchor at the region edges (anchoring bounds).
   */
  public fun matchSubstring(
      text: String,
      start: Int,
      endpos: Int,
      deadlineNanos: Long,
  ): PyReMatch? {
    if (start < 0 || start > text.length || endpos < start) return null
    val cs = PyRe.DeadlineCharSequence.absolute(text, deadlineNanos)
    val m = matcherFor(cs)
    m.region(start, endpos.coerceAtMost(text.length))
    m.useTransparentBounds(false)
    m.useAnchoringBounds(true)
    return if (m.lookingAt()) PyReMatch(text, m, this) else null
  }

  /** python re.fullmatch anchored at [pos]. */
  public fun fullmatchAt(text: String, pos: Int, endpos: Int, deadlineNanos: Long): PyReMatch? {
    if (pos < 0 || pos > text.length || endpos < pos) return null
    val cs = PyRe.DeadlineCharSequence.absolute(text, deadlineNanos)
    val m = matcherFor(cs)
    m.region(pos, endpos.coerceAtMost(text.length))
    m.useTransparentBounds(true)
    m.useAnchoringBounds(false)
    return if (m.matches()) PyReMatch(text, m, this) else null
  }

  public fun matchesFull(text: String, deadlineNanos: Long): PyReMatch? {
    val cs = PyRe.DeadlineCharSequence.absolute(text, deadlineNanos)
    val m = matcherFor(cs)
    return if (m.matches()) PyReMatch(text, m, this) else null
  }

  override fun toString(): String = source
}

/** A match with python-style group access; positions are code point indices. */
public class PyReMatch(
    text: String,
    m: Matcher,
    public val pattern: PyRePattern? = null,
) {
  // Snapshot: the underlying matcher is mutable and shared across finditer results.
  private val text: String = text
  private val charStarts: IntArray
  private val charEnds: IntArray
  private val groupTexts: Array<String?>

  init {
    val count = m.groupCount() + 1
    charStarts = IntArray(count)
    charEnds = IntArray(count)
    groupTexts = arrayOfNulls(count)
    for (i in 0 until count) {
      charStarts[i] = m.start(i)
      charEnds[i] = m.end(i)
      groupTexts[i] = m.group(i)
    }
  }

  private val cpTable: IntArray by lazy { PyUnicode.charToCpTable(text) }

  private fun toCp(charIndex: Int): Int {
    if (cpTable.size == text.length + 1 && text.codePointCount(0, text.length) == text.length) {
      return charIndex
    }
    return cpTable[charIndex.coerceIn(0, text.length)]
  }

  public fun start(groupIndex: Int = 0): Int = toCp(charStarts[groupIndex])

  public fun end(groupIndex: Int = 0): Int = toCp(charEnds[groupIndex])

  /** The matched text of group [groupIndex] (empty string when the group did not participate). */
  public fun group(groupIndex: Int = 0): String = groupTexts[groupIndex] ?: ""

  public fun groupOrNull(groupIndex: Int): String? = groupTexts[groupIndex]

  /** python match.string: the whole subject. */
  public fun subject(): String = text

  /** The underlying java matcher offset (UTF-16 unit) for group [groupIndex]. */
  public fun charStart(groupIndex: Int = 0): Int = charStarts[groupIndex]

  public fun charEnd(groupIndex: Int = 0): Int = charEnds[groupIndex]
}
