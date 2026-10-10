package com.guardcore.engine.suspatterns

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyRePattern

/**
 * XML/XXE internal-entity and public-DTD walkers.
 *
 * Port of guard_core/handlers/_suspatterns_xml_xxe.py.
 */
public object SusPatternsXmlXxe {
  public val PUBLIC_EXTERNAL_DTD_COMPILED_RE: PyRePattern =
      PyRe.compile(XML_XXE_PUBLIC_EXTERNAL_DTD_RE, PyReFlags.IGNORECASE)
  public val DOCTYPE_RE: PyRePattern = PyRe.compile("<!DOCTYPE", PyReFlags.IGNORECASE)
  public val PUBLIC_RE: PyRePattern = PyRe.compile("PUBLIC", PyReFlags.IGNORECASE)
  public val QUOTE_CHARS: Set<Char> = setOf('"', '\'')
  public val SCHEME_RE: PyRePattern = PyRe.compile("https?://", PyReFlags.IGNORECASE)
  public val W3_ORG_RE: PyRePattern = PyRe.compile("(?:www\\.)?w3\\.org/", PyReFlags.IGNORECASE)
  public val CLASS12_BOUNDARY_RE: PyRePattern = PyRe.compile("[>\\[]", 0)
  public val CLASS3_BOUNDARY_RE: PyRePattern = PyRe.compile("[\"'>]", 0)
  public val VALIDATED_SPAN_RE: PyRePattern = PyRe.compile(".*", PyReFlags.DOTALL)
  private val XML_SYSTEM_PREFIX_RE: PyRePattern =
      PyRe.compile("<!(?:ENTITY|DOCTYPE)", PyReFlags.IGNORECASE)
  private val XML_SYSTEM_KEYWORD_RE: PyRePattern = PyRe.compile("SYSTEM", PyReFlags.IGNORECASE)
  private val XML_ENTITY_PREFIX_RE: PyRePattern = PyRe.compile("<!ENTITY", PyReFlags.IGNORECASE)
  private val XML_GT_RE: PyRePattern = PyRe.compile(">", 0)

  private fun xmlValidatedMatch(text: String, start: Int, end: Int): PyReMatch =
      VALIDATED_SPAN_RE.matchAt(text, start, end, Long.MAX_VALUE)
          ?: error("validated span must match")

  /** _xml_system_finditer. */
  public fun xmlSystemFinditer(text: String): List<PyReMatch> {
    val ends = XML_GT_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val out = ArrayList<PyReMatch>()
    var lastEnd = 0
    for (prefix in XML_SYSTEM_PREFIX_RE.finditer(text, Long.MAX_VALUE)) {
      if (prefix.charStart() < lastEnd) continue
      val end = firstAtOrAfter(ends, prefix.charEnd()) ?: return out
      lastEnd = end + 1
      if (
          XML_SYSTEM_KEYWORD_RE.search(text, prefix.charEnd() + 1, end - 1, Long.MAX_VALUE) != null
      ) {
        out.add(xmlValidatedMatch(text, prefix.charStart(), lastEnd))
      }
    }
    return out
  }

  /** _xml_internal_entity_finditer. */
  public fun xmlInternalEntityFinditer(text: String): List<PyReMatch> {
    val boundaries = CLASS12_BOUNDARY_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val entities = XML_ENTITY_PREFIX_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val out = ArrayList<PyReMatch>()
    var lastEnd = 0
    for (prefix in DOCTYPE_RE.finditer(text, Long.MAX_VALUE)) {
      if (prefix.charStart() < lastEnd) continue
      val boundary = firstAtOrAfter(boundaries, prefix.charEnd()) ?: return out
      lastEnd = boundary + 1
      if (text[boundary] != '[') continue
      val entity = firstAtOrAfter(entities, boundary + 1) ?: return out
      lastEnd = entity + "<!ENTITY".length
      out.add(xmlValidatedMatch(text, prefix.charStart(), lastEnd))
    }
    return out
  }

  /** _xml_xxe_first_at_or_after. */
  public fun firstAtOrAfter(sortedPositions: List<Int>, floor: Int): Int? {
    var idx = sortedPositions.binarySearch(floor)
    if (idx < 0) idx = -(idx + 1)
    return if (idx < sortedPositions.size) sortedPositions[idx] else null
  }

  /** _xml_xxe_scheme_completion_end. */
  public fun schemeCompletionEnd(
      text: String,
      schemeStart: Int,
      class12Boundaries: List<Int>,
      class3Boundaries: List<Int>,
  ): Int? {
    if (schemeStart == 0 || text[schemeStart - 1] !in QUOTE_CHARS) return null
    val schemeMatch =
        SCHEME_RE.matchAt(text, schemeStart, text.length, Long.MAX_VALUE) ?: return null
    val schemeEnd = schemeMatch.charEnd()
    if (W3_ORG_RE.matchAt(text, schemeEnd, text.length, Long.MAX_VALUE) != null) return null
    return quotedUrlEnd(text, schemeEnd, class12Boundaries, class3Boundaries)
  }

  private fun quotedUrlEnd(
      text: String,
      schemeEnd: Int,
      class12Boundaries: List<Int>,
      class3Boundaries: List<Int>,
  ): Int? {
    var idx = class3Boundaries.binarySearch(schemeEnd)
    if (idx < 0) idx = -(idx + 1)
    if (idx >= class3Boundaries.size) return null
    val quote2 = class3Boundaries[idx]
    if (quote2 == schemeEnd || text[quote2] == '>') return null
    var idx12 = class12Boundaries.binarySearch(quote2 + 1)
    if (idx12 < 0) idx12 = -(idx12 + 1)
    if (idx12 >= class12Boundaries.size) return null
    val finalBoundary = class12Boundaries[idx12]
    return if (text[finalBoundary] == '>') finalBoundary else null
  }

  /** _xml_xxe_valid_quote_completions. */
  public fun validQuoteCompletions(
      text: String,
      class12Boundaries: List<Int>,
      class3Boundaries: List<Int>,
  ): Pair<List<Int>, Map<Int, Int>> {
    val quotePositions = ArrayList<Int>()
    val quoteToFinalGt = HashMap<Int, Int>()
    for (schemeMatch in SCHEME_RE.finditer(text, Long.MAX_VALUE)) {
      val finalGt =
          schemeCompletionEnd(text, schemeMatch.charStart(), class12Boundaries, class3Boundaries)
              ?: continue
      val quotePos = schemeMatch.charStart() - 1
      quotePositions.add(quotePos)
      quoteToFinalGt[quotePos] = finalGt
    }
    return Pair(quotePositions, quoteToFinalGt)
  }

  /** _xml_xxe_public_run_bounds. */
  public fun publicRunBounds(
      class12Boundaries: List<Int>,
      publicPos: Int,
      textLen: Int,
  ): Pair<Int, Int> {
    var runIdx = 0
    // bisect_right(class12_boundaries, public_pos)
    var lo = 0
    var hi = class12Boundaries.size
    while (lo < hi) {
      val mid = (lo + hi) / 2
      if (class12Boundaries[mid] <= publicPos) lo = mid + 1 else hi = mid
    }
    runIdx = lo
    val runStart = if (runIdx > 0) class12Boundaries[runIdx - 1] + 1 else 0
    val runEnd = if (runIdx < class12Boundaries.size) class12Boundaries[runIdx] else textLen
    return Pair(runStart, runEnd)
  }

  /** _xml_xxe_candidate_span. */
  public fun candidateSpan(
      doctypePositions: List<Int>,
      quotePositions: List<Int>,
      quoteToFinalGt: Map<Int, Int>,
      class12Boundaries: List<Int>,
      publicPos: Int,
      textLen: Int,
  ): Pair<Int, Int>? {
    val (runStart, runEnd) = publicRunBounds(class12Boundaries, publicPos, textLen)
    val doctypeBefore = firstAtOrAfter(doctypePositions, runStart)
    if (doctypeBefore == null || doctypeBefore >= publicPos - 9) return null
    val quote1 = firstAtOrAfter(quotePositions, publicPos + 7)
    if (quote1 == null || quote1 >= runEnd) return null
    return Pair(doctypeBefore, quoteToFinalGt[quote1] ?: return null)
  }

  /** _xml_xxe_precompute or null when the text cannot host a public-DTD match. */
  public fun precompute(text: String): Precomputed? {
    val doctypePositions = DOCTYPE_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val publicPositions = PUBLIC_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    if (doctypePositions.isEmpty() || publicPositions.isEmpty()) return null
    val class12Boundaries =
        CLASS12_BOUNDARY_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val class3Boundaries = CLASS3_BOUNDARY_RE.finditer(text, Long.MAX_VALUE).map { it.charStart() }
    val (quotePositions, quoteToFinalGt) =
        validQuoteCompletions(text, class12Boundaries, class3Boundaries)
    if (quotePositions.isEmpty()) return null
    return Precomputed(
        doctypePositions,
        publicPositions,
        class12Boundaries,
        quotePositions,
        quoteToFinalGt,
    )
  }

  public class Precomputed(
      public val doctypePositions: List<Int>,
      public val publicPositions: List<Int>,
      public val class12Boundaries: List<Int>,
      public val quotePositions: List<Int>,
      public val quoteToFinalGt: Map<Int, Int>,
  )

  /** _xml_xxe_public_external_dtd_finditer. */
  public fun publicExternalDtdFinditer(text: String): List<PyReMatch> {
    val precomputed = precompute(text) ?: return emptyList()
    val out = ArrayList<PyReMatch>()
    var lastEnd = 0
    for (publicPos in precomputed.publicPositions) {
      if (publicPos < lastEnd) continue
      val span =
          candidateSpan(
              precomputed.doctypePositions,
              precomputed.quotePositions,
              precomputed.quoteToFinalGt,
              precomputed.class12Boundaries,
              publicPos,
              text.length,
          ) ?: continue
      val (doctypeBefore, finalGt) = span
      val match = xmlValidatedMatch(text, doctypeBefore, finalGt + 1)
      out.add(match)
      lastEnd = match.charEnd()
    }
    return out
  }
}
