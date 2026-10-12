package com.guardcore.engine.suspatterns

import com.guardcore.engine.py.PyRe
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_sus_patterns/test_pickle_finder_security.py and
 * test_pickle_global_opcode_prefix_bypass.py: the pickle opcode-stream walkers behind the
 * deserialization validators.
 */
class SusPatternsPickleTest {
  private fun ba(vararg bytes: Int): ByteArray = bytes.map { it.toByte() }.toByteArray()

  // ---- prefix walker: a provable opcode stream ----

  @Test
  fun emptyOrNewlineTerminatedPrefixesAreStreams() {
    assertTrue(pickleGlobalPrefixIsOpcodeStream(""))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("text\n"))
    // A non-pickle continuation is not a stream.
    assertFalse(pickleGlobalPrefixIsOpcodeStream("just words"))
    assertFalse(pickleGlobalPrefixIsOpcodeStream("\u4e2d\u6587"))
  }

  @Test
  fun protoAndShortUnicodeStream() {
    assertTrue(pickleGlobalPrefixIsOpcodeStream("\u0080\u0004U\u0003abc"))
    // A COMPLETE prefix that runs out mid-opcode is not a provable stream.
    assertFalse(pickleGlobalPrefixIsOpcodeStream("\u0080\u0004U\u0003ab"))
    // Unknown opcode: not a stream.
    assertFalse(pickleGlobalPrefixIsOpcodeStream("\u0080\u0004Zq"))
  }

  @Test
  fun stringOpcodes() {
    // STRING 'S' + quoted line with escapes.
    assertTrue(pickleGlobalPrefixIsOpcodeStream("S'a\\nb\\n'\n"))
    // UNICODE 'V'.
    assertTrue(pickleGlobalPrefixIsOpcodeStream("Vtext\n"))
    // BINSTRING 'T' + 4-byte length.
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(
            ba('T'.code, 3, 0, 0, 0, 0x61, 0x62, 0x63).toString(Charsets.ISO_8859_1),
        ),
    )
    // BINUNICODE 'X'.
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(
            ba('X'.code, 2, 0, 0, 0, 0x61, 0x62).toString(Charsets.ISO_8859_1),
        ),
    )
    // SHORT_BINUNICODE 'U'.
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(ba('U'.code, 2, 0x61, 0x62).toString(Charsets.ISO_8859_1)),
    )
    // Protocol-4 SHORT_BINUNICODE 0x8c.
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(ba(0x8c, 2, 0x61, 0x62).toString(Charsets.ISO_8859_1)),
    )
    // BINUNICODE8 0x8d.
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(
            ba(0x8d, 2, 0, 0, 0, 0, 0, 0, 0, 0x61, 0x62).toString(Charsets.ISO_8859_1),
        ),
    )
    // SHORT_BINBYTES 'C'.
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(ba('C'.code, 1, 0x61).toString(Charsets.ISO_8859_1)),
    )
    // BINBYTES 'B'.
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(
            ba('B'.code, 1, 0, 0, 0, 0x61).toString(Charsets.ISO_8859_1),
        ),
    )
    // BINBYTES8 0x8e.
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(
            ba(0x8e, 1, 0, 0, 0, 0, 0, 0, 0, 0x61).toString(Charsets.ISO_8859_1),
        ),
    )
    // BYTEARRAY8 0x90.
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(ba(0x90, 1, 0, 0, 0, 0x61).toString(Charsets.ISO_8859_1)),
    )
  }

  @Test
  fun numberAndMemoOpcodes() {
    // INT 'I' with sign, LONG 'L', INT 'i', BININT 'K'/'M', BINFLOAT 'G'.
    assertTrue(pickleGlobalPrefixIsOpcodeStream("I-42\n"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("L+7\n"))
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(ba('i'.code, 1, 0, 0, 0).toString(Charsets.ISO_8859_1)),
    )
    assertTrue(pickleGlobalPrefixIsOpcodeStream(ba('K'.code, 9).toString(Charsets.ISO_8859_1)))
    assertTrue(pickleGlobalPrefixIsOpcodeStream(ba('M'.code, 9, 0).toString(Charsets.ISO_8859_1)))
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(
            ba('G'.code, 0, 0, 0, 0, 0, 0, 0, 0).toString(Charsets.ISO_8859_1),
        ),
    )
    // LONG1 0x8a / LONG4 0x8b.
    assertTrue(pickleGlobalPrefixIsOpcodeStream(ba(0x8a, 1, 5).toString(Charsets.ISO_8859_1)))
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(ba(0x8b, 1, 0, 0, 0, 5).toString(Charsets.ISO_8859_1)),
    )
    // Memo put/get.
    assertTrue(pickleGlobalPrefixIsOpcodeStream("p0\n"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream(ba('q'.code, 1).toString(Charsets.ISO_8859_1)))
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(ba('r'.code, 1, 0, 0, 0).toString(Charsets.ISO_8859_1)),
    )
    assertTrue(pickleGlobalPrefixIsOpcodeStream("g0\n"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream(ba('h'.code, 1).toString(Charsets.ISO_8859_1)))
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(ba('j'.code, 1, 0, 0, 0).toString(Charsets.ISO_8859_1)),
    )
  }

  @Test
  fun containerAndMutationOpcodes() {
    // Mark + TUPLE 't', EMPTY_LIST ']' etc.
    assertTrue(pickleGlobalPrefixIsOpcodeStream("(t"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("]"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream(")"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("}"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("(<"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("(l"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("(d"))
    // TUPLE1/2/3 0x85/0x86/0x87 pop their members off the stack.
    assertTrue(pickleGlobalPrefixIsOpcodeStream(ba('N'.code, 0x85).toString(Charsets.ISO_8859_1)))
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(
            ba('N'.code, 'N'.code, 0x86).toString(Charsets.ISO_8859_1),
        ),
    )
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(
            ba('N'.code, 'N'.code, 'N'.code, 0x87).toString(Charsets.ISO_8859_1),
        ),
    )
    // Mutations append/setitems/exts need stack depth.
    assertTrue(pickleGlobalPrefixIsOpcodeStream("(ta"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("(e"))
    // SETITEMS pops three values: push three constants first.
    assertTrue(pickleGlobalPrefixIsOpcodeStream("NNNs"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("(tu"))
    // BUILD/REDUCE without checkReduceBuild keep walking (prefix mode).
    assertTrue(pickleGlobalPrefixIsOpcodeStream("(tb"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("(tR"))
    // Constants.
    assertTrue(pickleGlobalPrefixIsOpcodeStream("N"))
    assertTrue(pickleGlobalPrefixIsOpcodeStream(ba(0x88).toString(Charsets.ISO_8859_1)))
    assertTrue(pickleGlobalPrefixIsOpcodeStream(ba(0x89).toString(Charsets.ISO_8859_1)))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("F"))
    // FRAME 0x95 + 8-byte length, MEMOIZE 0x94.
    assertTrue(
        pickleGlobalPrefixIsOpcodeStream(
            ba(0x95, 0, 0, 0, 0, 0, 0, 0, 0, 'U'.code, 1, 0x61, 0x94).toString(Charsets.ISO_8859_1),
        ),
    )
  }

  @Test
  fun blockedGlobalOpcodesFailClosed() {
    for (op in listOf('c', 'f', 'o', 'P')) {
      assertFalse(pickleGlobalPrefixIsOpcodeStream(op.toString()))
    }
    for (op in listOf(0x96, 0x81, 0x82, 0x83, 0x84, 0x91, 0x92)) {
      assertFalse(pickleGlobalPrefixIsOpcodeStream(ba(op).toString(Charsets.ISO_8859_1)))
    }
    // A complete prefix that runs out mid-opcode is not a stream.
    assertFalse(pickleGlobalPrefixIsOpcodeStream(ba('U'.code, 9).toString(Charsets.ISO_8859_1)))
  }

  // ---- suffix walker: must reach BUILD or REDUCE ----

  @Test
  fun suffixReachesReduceOrBuild() {
    assertTrue(pickleGlobalSuffixReachesReduceOrBuild("b"))
    assertTrue(pickleGlobalSuffixReachesReduceOrBuild("R"))
    assertTrue(pickleGlobalSuffixReachesReduceOrBuild("b."))
    // Non-reduce suffixes do not qualify.
    assertFalse(pickleGlobalSuffixReachesReduceOrBuild(""))
    assertFalse(pickleGlobalSuffixReachesReduceOrBuild("U\u0001c"))
    // Blocked globals in the suffix disqualify it.
    assertFalse(pickleGlobalSuffixReachesReduceOrBuild("cb"))
  }

  // ---- the injection candidate predicate ----

  @Test
  fun injectionCandidateNeedsStreamPrefixAndReduceSuffix() {
    val compiled = PyRe.compile("(R)", 0)
    val match = compiled.search("Rb.", 0, Long.MAX_VALUE)
    assertNotNull(match)
    assertTrue(pickleGlobalCandidateIsInjection(match, "ctx"))
    // A prefix that is not an opcode stream disqualifies.
    val match2 = compiled.search("words Rb.", 0, Long.MAX_VALUE)
    assertNotNull(match2)
    assertFalse(pickleGlobalCandidateIsInjection(match2, "ctx"))
  }

  // ---- the prefix window builder ----

  @Test
  fun prefixWindowFromCharsMapsSurrogateEscapes() {
    assertEquals("ab".toByteArray().toList(), picklePrefixWindowFromChars("ab")!!.toList())
    // surrogateescape range maps back to the raw high byte.
    val surrogated = String(intArrayOf(0xDC80), 0, 1)
    val window = picklePrefixWindowFromChars(surrogated)!!
    assertEquals(0x80.toByte(), window[0])
    // A char outside both ranges rejects the whole window.
    assertNull(picklePrefixWindowFromChars("\u4e2d"))
  }
}
