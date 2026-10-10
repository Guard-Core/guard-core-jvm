package com.guardcore.engine.suspatterns

import com.guardcore.engine.py.PyReMatch

/**
 * Pickle opcode-stream prefix/suffix walkers for the generic global validator.
 *
 * Port of guard_core/handlers/_suspatterns_pickle.py. The reference drives python's
 * pickle._Unpickler with bounded reads; this walker models the opcode dispatch the safety decision
 * needs (shape validation only: no class resolution, no object construction - the ops python routes
 * through find_class/persistent_load raise, and a raise means "not a provable opcode stream").
 */
public const val PICKLE_SURROGATEESCAPE_LOW: Int = 0xDC80
public const val PICKLE_SURROGATEESCAPE_HIGH: Int = 0xDCFF

private class PickleShortRead(val size: Int) : RuntimeException("short read $size")

/** Raised where python's blocked unpickler would raise (find_class/persistent_load etc). */
private class PickleOpcodeError(message: String) : RuntimeException(message)

private class PickleReader(private val data: ByteArray) {
  var pos: Int = 0

  fun read(n: Int): ByteArray {
    if (pos + n > data.size) throw PickleShortRead(n)
    val out = data.copyOfRange(pos, pos + n)
    pos += n
    return out
  }

  fun readline(): ByteArray {
    val start = pos
    while (pos < data.size) {
      if (data[pos] == '\n'.code.toByte()) {
        pos++
        return data.copyOfRange(start, pos)
      }
      pos++
    }
    throw PickleShortRead(-1)
  }

  fun u1(): Int = read(1)[0].toInt() and 0xFF

  fun u2(): Int {
    val b = read(2)
    return (b[0].toInt() and 0xFF) or ((b[1].toInt() and 0xFF) shl 8)
  }

  fun u4(): Int {
    val b = read(4)
    var v = 0
    for (i in 3 downTo 0) v = (v shl 8) or (b[i].toInt() and 0xFF)
    return v
  }

  fun u8(): Long {
    val b = read(8)
    var v = 0L
    for (i in 7 downTo 0) v = (v shl 8) or (b[i].toLong() and 0xFF)
    return v
  }
}

private object PickleMark

private fun MutableList<Any>.popToMark(): List<Any> {
  for (i in indices.reversed()) {
    if (this[i] == PickleMark) {
      val items = subList(i + 1, size).toList()
      subList(i, size).clear()
      return items
    }
  }
  val items = toList()
  clear()
  return items
}

private fun MutableList<Any>.popCount(n: Int): List<Any> {
  val out = ArrayList<Any>(n)
  repeat(n) {
    if (isEmpty()) throw PickleOpcodeError("empty stack")
    out.add(removeAt(size - 1))
  }
  out.reverse()
  return out
}

private const val PROTO_OPCODE = 0x80
private const val FRAME_OPCODE = 0x95

private class PickleVm(private val r: PickleReader) {
  val stack = ArrayList<Any>()

  fun push(v: Any) {
    stack.add(v)
  }

  fun pop(): Any {
    if (stack.isEmpty()) throw PickleOpcodeError("empty stack")
    return stack.removeAt(stack.size - 1)
  }

  /** Returns true when a REDUCE/BUILD opcode was reached (checkReduceBuild mode). */
  fun step(checkReduceBuild: Boolean): Boolean {
    val key = r.u1()
    when (key) {
      // Protocol/frame headers.
      PROTO_OPCODE -> r.u1()
      FRAME_OPCODE -> r.u8()
      0x94 -> pop() // MEMOIZE
      // Strings/bytes.
      'S'.code -> push(pickleUnquoteString(r.readline())) // STRING
      'V'.code -> push(pickleUnquoteString(r.readline())) // UNICODE
      'T'.code -> { // BINSTRING (4-byte len)
        val n = r.u4()
        push(String(r.read(n), Charsets.ISO_8859_1))
      }
      'X'.code -> { // BINUNICODE (4-byte len)
        val n = r.u4()
        push(String(r.read(n), Charsets.UTF_8))
      }
      'U'.code -> { // SHORT_BINUNICODE
        val n = r.u1()
        push(String(r.read(n), Charsets.UTF_8))
      }
      0x8c -> { // SHORT_BINUNICODE (proto 4)
        val n = r.u1()
        push(String(r.read(n), Charsets.UTF_8))
      }
      0x8d -> { // BINUNICODE8
        val n = r.u8().toInt()
        push(String(r.read(n), Charsets.UTF_8))
      }
      'C'.code -> { // SHORT_BINBYTES
        val n = r.u1()
        push(r.read(n))
      }
      'B'.code -> { // BINBYTES (4-byte len)
        val n = r.u4()
        push(r.read(n))
      }
      0x8e -> { // BINBYTES8
        val n = r.u8().toInt()
        push(r.read(n))
      }
      0x90 -> { // BYTEARRAY8
        val n = r.u4()
        push(r.read(n))
      }
      0x91,
      0x92 -> throw PickleOpcodeError("buffer opcodes need buffer support") // NEXT_BUFFER etc
      // Numbers.
      'I'.code -> push(pickleParseInt(r.readline()))
      'L'.code -> push(pickleParseInt(r.readline()))
      'i'.code -> {
        r.u4()
        push(0)
      }
      'K'.code -> {
        r.u1()
        push(0)
      }
      'M'.code -> {
        r.u2()
        push(0)
      }
      'G'.code -> {
        r.u8()
        push(0.0)
      }
      0x8a -> { // LONG1
        val n = r.u1()
        r.read(n)
        push(0)
      }
      0x8b -> { // LONG4
        val n = r.u4()
        r.read(n)
        push(0)
      }
      // Constants.
      'N'.code -> push("None")
      0x88 -> push(true) // NEWTRUE
      0x89 -> push(false) // NEWFALSE
      'F'.code -> push(false)
      // Containers.
      '('.code -> push(PickleMark)
      't'.code -> push(stack.popToMark())
      ')'.code -> push(emptyList<Any>())
      ']'.code -> push(emptyList<Any>())
      '}'.code -> push(HashMap<Any, Any>())
      '<'.code -> push(stack.popToMark())
      'l'.code -> push(stack.popToMark())
      'd'.code -> push(stack.popToMark())
      0x85 -> push(stack.popCount(1))
      0x86 -> push(stack.popCount(2))
      0x87 -> push(stack.popCount(3))
      // Mutations.
      'a'.code -> {
        pop()
      }
      'e'.code -> stack.popToMark()
      's'.code -> {
        pop()
        pop()
        pop()
      }
      'u'.code -> stack.popToMark()
      'b'.code -> if (checkReduceBuild) return true
      'R'.code -> if (checkReduceBuild) return true
      // Globals resolve through find_class: always blocked -> not a provable stream.
      'c'.code -> throw PickleOpcodeError("global")
      'f'.code -> throw PickleOpcodeError("inst")
      'o'.code -> throw PickleOpcodeError("obj")
      0x96 -> throw PickleOpcodeError("stack_global")
      0x81,
      0x82,
      0x83,
      0x84 -> throw PickleOpcodeError("newobj/ext")
      'P'.code -> throw PickleOpcodeError("persid")
      // Memo ops.
      'p'.code -> r.readline() // PUT
      'q'.code -> r.u1() // BINPUT
      'r'.code -> r.u4() // LONG_BINPUT
      'g'.code -> {
        r.readline() // GET
        push("memo")
      }
      'h'.code -> {
        r.u1() // BINGET
        push("memo")
      }
      'j'.code -> {
        r.u4() // LONG_BINGET
        push("memo")
      }
      '.'.code -> {} // STOP: done
      else -> throw PickleOpcodeError("unknown opcode $key")
    }
    return false
  }
}

private fun trimRn(s: String): String = s.trimEnd('\n', '\r')

private fun replaceEscapes(s: String): String {
  val out = StringBuilder()
  var i = 0
  while (i < s.length) {
    val c = s[i]
    if (c == '\\' && i + 1 < s.length) {
      i++
      when (val esc = s[i]) {
        'n' -> out.append('\n')
        't' -> out.append('\t')
        'r' -> out.append('\r')
        else -> out.append(esc)
      }
      i++
      continue
    }
    out.append(c)
    i++
  }
  return out.toString()
}

private fun pickleUnquoteString(line: ByteArray): String {
  val s = trimRn(String(line, Charsets.ISO_8859_1))
  if (s.length >= 2 && (s[0] == '\'' || s[0] == '"') && s[s.length - 1] == s[0]) {
    return replaceEscapes(s.substring(1, s.length - 1))
  }
  return s
}

private fun pickleParseInt(line: ByteArray): Int {
  val s = trimRn(String(line, Charsets.ISO_8859_1))
  var negative = false
  var body = s
  if (body.isNotEmpty() && (body[0] == '-' || body[0] == '+')) {
    negative = body[0] == '-'
    body = body.substring(1)
  }
  var v = 0
  for (c in body) {
    if (c < '0' || c > '9') break
    v = v * 10 + (c - '0')
  }
  return if (negative) -v else v
}

/** _pickle_prefix_window_from_chars; null when a char is outside the byte/surrogate range. */
public fun picklePrefixWindowFromChars(chars: String): ByteArray? {
  val window = java.io.ByteArrayOutputStream()
  for (char in chars) {
    val code = char.code
    when {
      code <= 0xFF -> window.write(code)
      code in PICKLE_SURROGATEESCAPE_LOW..PICKLE_SURROGATEESCAPE_HIGH ->
          window.write(code - PICKLE_SURROGATEESCAPE_LOW + 0x80)
      else -> return null
    }
  }
  return window.toByteArray()
}

private fun pickleOpcodeScanWindow(text: String, budget: Int): Pair<ByteArray?, Boolean> {
  val isComplete = text.length <= budget
  val scanSlice = if (isComplete) text else text.substring(0, budget)
  return Pair(picklePrefixWindowFromChars(scanSlice), isComplete)
}

private fun pickleWalkPrefix(window: ByteArray, isCompletePrefix: Boolean): Boolean {
  val reader = PickleReader(window)
  val vm = PickleVm(reader)
  return try {
    while (reader.pos < window.size) {
      vm.step(checkReduceBuild = false)
    }
    true
  } catch (e: PickleShortRead) {
    !isCompletePrefix
  } catch (e: Exception) {
    false
  }
}

private fun pickleWalkSuffix(window: ByteArray, isCompleteSuffix: Boolean): Boolean {
  val reader = PickleReader(window)
  val vm = PickleVm(reader)
  vm.push(Any())
  return try {
    while (reader.pos < window.size) {
      val reached = vm.step(checkReduceBuild = true)
      if (reached) return true
    }
    !isCompleteSuffix
  } catch (e: PickleShortRead) {
    !isCompleteSuffix
  } catch (e: Exception) {
    false
  }
}

/** _pickle_global_prefix_is_opcode_stream. */
public fun pickleGlobalPrefixIsOpcodeStream(prefix: String): Boolean {
  if (prefix.isEmpty() || prefix[prefix.length - 1] == '\n') return true
  val (window, isComplete) = pickleOpcodeScanWindow(prefix, PICKLE_OPCODE_WORK_BUDGET_BYTES)
  if (window == null) return false
  return pickleWalkPrefix(window, isComplete)
}

/** _pickle_global_suffix_reaches_reduce_or_build. */
public fun pickleGlobalSuffixReachesReduceOrBuild(suffix: String): Boolean {
  val (window, isComplete) = pickleOpcodeScanWindow(suffix, PICKLE_OPCODE_WORK_BUDGET_BYTES)
  if (window == null) return false
  return pickleWalkSuffix(window, isComplete)
}

/** _pickle_global_candidate_is_injection. */
public fun pickleGlobalCandidateIsInjection(match: PyReMatch, context: String): Boolean {
  val text = match.subject()
  val prefix = text.substring(0, match.charStart())
  if (!pickleGlobalPrefixIsOpcodeStream(prefix)) return false
  val suffix = text.substring(match.charEnd(1))
  return pickleGlobalSuffixReachesReduceOrBuild(suffix)
}
