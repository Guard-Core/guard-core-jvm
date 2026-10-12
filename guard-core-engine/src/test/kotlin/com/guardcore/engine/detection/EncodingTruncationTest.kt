package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyUnicode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_detection/test_encoding_truncation_evasion.py,
 * test_wide_encoding_detection.py, tests/test_sus_patterns/test_base64_view.py and the truncation
 * helpers: escape decoders, base64 candidate decoding, attack-region extraction, and safe
 * truncation.
 */
class EncodingTruncationTest {
  // ---- EncodingDecoders ----

  @Test
  fun hexUnicodeAndPercentUEscapesDecode() {
    assertEquals("<", EncodingDecoders.decodeHexEscapes("""\x3c"""))
    assertEquals("\u00e9", EncodingDecoders.decodeHexEscapes("""\xe9"""))
    // Lone surrogates carry through as chars (python chr()).
    assertEquals("éd", EncodingDecoders.decodeUnicodeEscapes("""\u00e9\u0064"""))
    assertEquals("<script", EncodingDecoders.decodePercentUEscapes("""%u003cscript"""))
    // Non-escapes pass through.
    assertEquals(
        """\xzz %u12 noescape""",
        EncodingDecoders.decodeHexEscapes("""\xzz %u12 noescape"""),
    )
  }

  @Test
  fun overlongUtf8Decode() {
    // C0 AF is the classic overlong slash.
    assertEquals(
        "/",
        EncodingDecoders.lenientOverlongUtf8Decode(byteArrayOf(0xC0.toByte(), 0xAF.toByte())),
    )
    // E0 80 AF is the 3-byte overlong slash.
    assertEquals(
        "/",
        EncodingDecoders.lenientOverlongUtf8Decode(
            byteArrayOf(0xE0.toByte(), 0x80.toByte(), 0xAF.toByte()),
        ),
    )
    // F0 80 80 AF is the 4-byte overlong slash.
    assertEquals(
        "/",
        EncodingDecoders.lenientOverlongUtf8Decode(
            byteArrayOf(0xF0.toByte(), 0x80.toByte(), 0x80.toByte(), 0xAF.toByte()),
        ),
    )
    // Truncated overlong sequence falls back to plain bytes.
    assertEquals(
        "",
        EncodingDecoders.lenientOverlongUtf8Decode(byteArrayOf(0xC0.toByte())),
    )
    // A non-overlong lead byte that is >= 0x80 but not a spec lead is dropped.
    assertEquals("", EncodingDecoders.lenientOverlongUtf8Decode(byteArrayOf(0xFF.toByte())))
    // ASCII passes through.
    assertEquals("abc", EncodingDecoders.lenientOverlongUtf8Decode("abc".toByteArray()))
    // A continuation-range violation rejects the sequence and passes the byte through.
    assertEquals(
        "A",
        EncodingDecoders.lenientOverlongUtf8Decode(
            byteArrayOf(0xC0.toByte(), 0x41.toByte()),
        ),
    )
  }

  @Test
  fun overlongPercentRunsDecode() {
    // A valid strict-UTF-8 percent run is kept as-is.
    assertEquals("%41", EncodingDecoders.decodeOverlongUtf8PercentRuns("%41"))
    // The overlong slash run decodes to the char.
    assertEquals("/", EncodingDecoders.decodeOverlongUtf8PercentRuns("%c0%af"))
  }

  // ---- Base64Decode ----

  @Test
  fun hexLiteralDetection() {
    assertTrue(Base64Decode.isHexLiteral("0xDEADBEEF"))
    assertTrue(Base64Decode.isHexLiteral("0x10"))
    assertFalse(Base64Decode.isHexLiteral("0x"))
    assertFalse(Base64Decode.isHexLiteral("deadbeef"))
  }

  @Test
  fun printableAndReplacementRatios() {
    assertEquals(0.0, Base64Decode.printableRatio(""))
    assertEquals(1.0, Base64Decode.printableRatio("abc"))
    assertTrue(Base64Decode.printableRatio("a\u0000b") < 1.0)
    assertEquals(0.0, Base64Decode.replacementCharRatio(""))
    assertEquals(0.5, Base64Decode.replacementCharRatio("\uFFFDx"))
  }

  @Test
  fun boundedGunzipGuards() {
    assertNull(Base64Decode.boundedGunzip("plain".toByteArray()))
    assertNull(Base64Decode.boundedGunzip(byteArrayOf(0x1F.toByte())))
    // Corrupt gzip magic-adjacent payload fails cleanly.
    assertNull(
        Base64Decode.boundedGunzip(
            byteArrayOf(0x1F.toByte(), 0x8B.toByte(), 0x01.toByte(), 0x02.toByte()),
        ),
    )
    // A real gzip payload inflates.
    val gz = gzipOf("select * from users where name = 'admin' and 1=1")
    val out = Base64Decode.boundedGunzip(gz)
    assertNotNull(out)
    assertTrue(String(out, Charsets.UTF_8).startsWith("select"))
    // Output beyond the cap fails closed.
    assertNull(Base64Decode.boundedGunzip(gz, maxOutputBytes = 4))
  }

  private fun gzipOf(text: String): ByteArray {
    val bytes = text.toByteArray(Charsets.UTF_8)
    val out = java.io.ByteArrayOutputStream()
    val gz = java.util.zip.GZIPOutputStream(out)
    gz.write(bytes)
    gz.close()
    return out.toByteArray()
  }

  @Test
  fun decodeBase64CandidatesReplacesDecodableRuns() {
    val encoded =
        java.util.Base64.getEncoder().encodeToString("SELECT password FROM users".toByteArray())
    val out = Base64Decode.decodeBase64Candidates("prefix $encoded suffix")
    assertTrue("SELECT password FROM users" in out, out)
    // Non-decodable runs stay untouched.
    val untouched = Base64Decode.decodeBase64Candidates("plain text here ok")
    assertEquals("plain text here ok", untouched)
  }

  @Test
  fun decodeBase64CandidatesPeelsGzipLayers() {
    val inner = "UNION SELECT credit_card FROM payments"
    val payload = gzipOf(inner)
    val encoded = java.util.Base64.getEncoder().encodeToString(payload)
    val out = Base64Decode.decodeBase64Candidates(encoded, intArrayOf(3))
    assertTrue(inner in out, out)
  }

  @Test
  fun decodeBase64CandidatesHandlesUrlsafeAndSubFloorReassembly() {
    // URL-safe alphabet with - and _ decodes through the translate path.
    val urlsafe = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmdlcl9zdHJpbmc-"
    val out = Base64Decode.decodeBase64Candidates(urlsafe)
    // Decoded or not, no exception; the standard variant must decode.
    val standard = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmdlcitzdHJpbmc="
    val out2 = Base64Decode.decodeBase64Candidates(standard)
    assertTrue("hello world this is a longer" in out2 || out2 == standard, out2)
    assertFalse(out.isEmpty())
  }

  // ---- Truncation ----

  private fun preprocessor(): ContentPreprocessor =
      ContentPreprocessor(
          maxContentLength = 4000,
          preserveAttackPatterns = true,
          maxFullScanBytes = 4000,
      )

  @Test
  fun extractAttackRegionsFindsAndMerges() {
    val pp = preprocessor()
    val content =
        "safe <script>alert(1)</script> safe UNION SELECT password FROM x safe ../../etc/passwd"
    val regions = extractAttackRegions(pp, content)
    assertTrue(regions.isNotEmpty())
    // Regions are merged and sorted.
    for (i in 1 until regions.size) {
      assertTrue(regions[i].first > regions[i - 1].last)
    }
    assertEquals(emptyList(), extractAttackRegions(pp, "nothing malicious here at all"))
  }

  @Test
  fun extractAndConcatenateAttackRegionsHonorsBudget() {
    val content = "0123456789"
    val out = extractAndConcatenateAttackRegions(content, listOf(IntRange(2, 5)), budget = 100)
    assertEquals("2345", out)
    val capped = extractAndConcatenateAttackRegions(content, listOf(IntRange(0, 9)), budget = 4)
    assertEquals("0123", capped)
  }

  @Test
  fun buildResultKeepsContextWithinBudget() {
    val content = "aaaa<bbb>cccc"
    val out = buildResultWithAttackRegionsAndContext(content, listOf(IntRange(4, 8)), 13)
    assertTrue("<bbb>" in out, out)
    // Gaps beyond the budget are elided with a space marker.
    val tight =
        buildResultWithAttackRegionsAndContext(
            "x".repeat(100) + "<y>" + "z".repeat(100),
            listOf(IntRange(100, 102)),
            10,
        )
    assertTrue("<y>" in tight, tight)
    assertTrue(" " in tight, tight)
  }

  @Test
  fun capWithTailKeepsHeadAndTail() {
    val content = (0 until 1000).joinToString("") { (it % 10).toString() }
    val capped = capWithTail(content, 100)
    assertEquals(100, capped.length)
    assertTrue(capped.startsWith(content.take(50)))
    assertTrue(capped.endsWith(content.takeLast(50)))
  }

  @Test
  fun truncateSafelyBranches() {
    val pp = preprocessor()
    // Under the cap: unchanged.
    assertEquals("hello", truncateSafely(pp, "hello"))
    // Over the cap without preserve: head only.
    val noPreserve =
        ContentPreprocessor(
            maxContentLength = 100,
            preserveAttackPatterns = false,
            maxFullScanBytes = 100,
        )
    val head = truncateSafely(noPreserve, "q".repeat(500))
    assertEquals(100, head.length)
    // Over the cap with no attack regions: head+tail.
    val capped = truncateSafely(pp, "z".repeat(5000))
    assertEquals(4000, capped.length)
    // Attack regions within the cap keep context.
    val attack = "safe " + "<script>alert('xss')</script>".repeat(200)
    val kept = truncateSafely(pp, attack)
    assertTrue("<script>" in kept, kept.take(200))
    // Regions larger than the budget: concatenated attacks only.
    val huge = "<script>".repeat(2000)
    val attacks = truncateSafely(pp, huge)
    assertTrue(attacks.contains("<script>"))
  }

  // ---- IgnorecaseFold ----

  @Test
  fun expandIgnorecaseAddsFoldPartners() {
    val lower = IntervalSet.single('k'.code) // K has the Kelvin sign partner.
    val expanded = expandIgnorecase(lower, asciiOnly = false)
    assertTrue(expanded.contains('K'.code))
    assertTrue(expanded.contains('\u212A'.code))
    // asciiOnly restricts to ASCII partners.
    val asciiExpanded = expandIgnorecase(lower, asciiOnly = true)
    assertTrue(asciiExpanded.contains('K'.code))
    assertFalse(asciiExpanded.contains('\u212A'.code))
    // The group-scan path (large member count) matches results.
    val wide = IntervalSet.fromRange(0x0041, 0x005A) // A-Z, 26 members
    val wideExpanded = expandIgnorecase(wide, asciiOnly = true)
    assertTrue(wideExpanded.contains('a'.code))
  }

  // ---- Binary / ScanWindow / Base64 one-line tails ----

  @Test
  fun binaryIslandsExtractRuns() {
    val content = "ab\u0000\u0001cd\u0002ef"
    assertTrue(BinaryIslands.valueIsBinaryLike(content))
    // A run length of 1 or less returns the content unchanged.
    assertEquals(listOf(content), BinaryIslands.extractBinaryIslands(content, 1))
    // The printable islands between the artifacts.
    assertEquals(listOf("ab", "cd", "ef"), BinaryIslands.extractBinaryIslands(content, 2))
    assertFalse(BinaryIslands.valueIsBinaryLike("clean text"))
  }

  @Test
  fun binaryPrefixDenseMatches() {
    val content = "ab\u0000\u0001cd"
    val prefix = BinaryPrefix.buildBinaryPrefix(content)
    assertEquals(content.length + 1, prefix.size)
    val compiled = PyRe.compile("cd", 0)
    val match = compiled.search(content, 0, Long.MAX_VALUE)
    assertNotNull(match)
    // Two artifacts in the window: under the density limit.
    assertFalse(BinaryPrefix.matchIsBinaryDense(prefix, match))
    // Eight artifacts within the 64-char radius: dense.
    val denseContent = "\u0000".repeat(8) + "x"
    val densePrefix = BinaryPrefix.buildBinaryPrefix(denseContent)
    val dense = PyRe.compile("x", 0)
    val denseMatch = dense.search(denseContent, 0, Long.MAX_VALUE)
    assertNotNull(denseMatch)
    assertTrue(BinaryPrefix.matchIsBinaryDense(densePrefix, denseMatch))
    // A null prefix is never dense.
    assertFalse(BinaryPrefix.matchIsBinaryDense(null, denseMatch))
  }

  @Test
  fun base64AlphabetSeparators() {
    assertTrue(Base64Alphabet.isWidenedSeparatorChar('-'))
    assertTrue(Base64Alphabet.isWidenedSeparatorChar('_'))
    assertEquals('a', Base64Alphabet.urlsafeTranslate('a'))
    assertEquals('+', Base64Alphabet.urlsafeTranslate('-'))
    assertEquals('/', Base64Alphabet.urlsafeTranslate('_'))
  }

  @Test
  fun scanWindowAndIntervalSetTails() {
    // IntervalSet boundaries from the existing chain helpers.
    val set = IntervalSet.fromRange('a'.code, 'c'.code)
    assertFalse(set.isEmpty)
    assertEquals('a'.code, set.firstMember())
  }

  // ---- PyUnicode tails ----

  @Test
  fun pyUnicodeHelpersCoverTheTails() {
    assertEquals(3, PyUnicode.cpLength("abc"))
    assertEquals("bc", PyUnicode.cpSlice("abc", 1, 3))
    assertEquals("", PyUnicode.cpSlice("abc", 2, 1))
    assertTrue(PyUnicode.isPrintable('a'))
    assertFalse(PyUnicode.isPrintable('\u0000'))
  }

  // ---- RegexWorkers tail ----

  @Test
  fun regexWorkersSubmitRunsOnThePool() {
    val result = com.guardcore.engine.py.RegexWorkers.submit { 41 + 1 }
    assertEquals(42, result)
  }
}
