package com.guardcore.util

import com.guardcore.util.py.PyJson
import com.guardcore.util.py.PyUrllib
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Port of tests/test_sensitive_pair_grammar.py: the redaction pair grammar sweep (name casings,
 * whitespace, assign chars, separators, quoting, wrappers, percent-encoding rounds), the assignment
 * run grammar, the hidden-wrapper and JSON-leaf-split families, and the escaped-gap arms.
 */
class PairGrammarRedactionTest {
  private val sensitive = setOf("password")
  private val benignName = "note"
  private val tail = "TAILMARKER"

  private fun percentEncodeN(text: String, rounds: Int): String {
    var encoded = text
    repeat(rounds) { encoded = PyUrllib.quote(encoded, safe = "") }
    return encoded
  }

  private fun quoteValue(value: String, quoting: String): String =
      when (quoting) {
        "double" -> "\"$value\""
        "single" -> "'$value'"
        else -> value
      }

  private fun quoteName(name: String, nameQuoting: String): String =
      when (nameQuoting) {
        "double" -> "\"$name\""
        "single" -> "'$name'"
        else -> name
      }

  private fun makePair(
      name: String,
      wsPre: String,
      wsPost: String,
      assignChar: String,
      quoting: String,
      value: String,
      encRounds: Int,
      encTarget: String,
      nameQuoting: String = "none",
  ): String {
    val quotedName = quoteName(name, nameQuoting)
    val quotedValue = quoteValue(value, quoting)
    if (encRounds == 0 || encTarget == "sep") {
      return "$quotedName$wsPre$assignChar$wsPost$quotedValue"
    }
    if (encTarget == "whole") {
      return percentEncodeN("$quotedName$wsPre$assignChar$wsPost$quotedValue", encRounds)
    }
    val encodedAssign = percentEncodeN(assignChar, encRounds)
    return "$quotedName$wsPre$encodedAssign$wsPost$quotedValue"
  }

  private fun makeSeparator(separator: String, encRounds: Int, encTarget: String): String =
      if (encTarget == "sep" && encRounds > 0) percentEncodeN(separator, encRounds) else separator

  private fun eligibleForUrlDisplay(
      wsPre: String,
      wsPost: String,
      separator: String,
      wrapper: String,
  ): Boolean {
    if (wrapper !in listOf("bare", "nested_data")) return false
    val controlChars = "\t\r\n"
    return (wsPre + wsPost + separator).none { it in controlChars }
  }

  private fun wrap(wrapper: String, pair: String): String =
      when (wrapper) {
        "bare" -> pair
        "nested_data" -> "data=$pair"
        "filename_quoted" -> "filename=\"$pair\""
        "xml_text" -> "<note>$pair</note>"
        "xml_attr" -> "<user $pair/>"
        else -> error("unhandled wrapper $wrapper")
      }

  private fun renderAndCheck(
      name: String,
      wsPre: String,
      wsPost: String,
      assignChar: String,
      separator: String,
      quoting: String,
      wrapper: String,
      encRounds: Int,
      encTarget: String,
      marker: String,
      nameQuoting: String = "none",
  ): String {
    if (wrapper == "json_leaf") {
      val quotedName = quoteName(name, nameQuoting)
      val quotedMarker = quoteValue(marker, quoting)
      val pair = "$quotedName$wsPre$assignChar$wsPost$quotedMarker"
      val result =
          LoggingUtils.redactSensitiveJson(
              linkedMapOf<String, Any?>("note" to pair),
              emptySet(),
              sensitive,
              32,
          ) as Map<*, *>
      return result["note"].toString()
    }
    val pair =
        makePair(
            name,
            wsPre,
            wsPost,
            assignChar,
            quoting,
            marker,
            encRounds,
            encTarget,
            nameQuoting,
        )
    val body = wrap(wrapper, pair)
    val sepText = makeSeparator(separator, encRounds, encTarget)
    val text = "$body$sepText$tail"
    return if (eligibleForUrlDisplay(wsPre, wsPost, separator, wrapper)) {
      RequestLogging.redactUrlForDisplay("/r?$text", emptySet(), emptySet())
    } else {
      RequestLogging.redactBlobForDisplay(text, emptySet(), emptySet())
    }
  }

  private data class Case(
      val name: String,
      val wsPre: String,
      val wsPost: String,
      val assignChar: String,
      val separator: String,
      val quoting: String,
      val wrapper: String,
      val encRounds: Int,
      val encTarget: String,
      val nameQuoting: String,
  )

  private fun oneAxisSweepCases(): List<Case> {
    val nameCasings = listOf("password", "Password", "PASSWORD")
    val wsCombos = listOf("" to "", " " to "", "" to " ", " " to " ", "\t" to "\t")
    val assignChars = listOf("=", ":")
    val separators = listOf("&", ";", ",", "?", "|", " ", "\t", "\r", "\n", "\r\n", " ")
    val quotings = listOf("none", "double", "single")
    val wrappers =
        listOf("bare", "nested_data", "filename_quoted", "json_leaf", "xml_text", "xml_attr")
    val encodings: List<Pair<Int, String>> =
        listOf(0, 1, 2, 3, 4, 5).map { it to "whole" } +
            listOf(1, 2, 3).flatMap { r -> listOf("eq", "sep").map { t -> r to t } }
    val nameQuotings = listOf("none", "double", "single")

    val cases = mutableListOf<Case>()
    fun add(
        name: String = "password",
        wsPre: String = "",
        wsPost: String = "",
        assignChar: String = "=",
        separator: String = "&",
        quoting: String = "none",
        wrapper: String = "bare",
        rounds: Int = 0,
        target: String = "whole",
        nameQuoting: String = "none",
    ) {
      cases.add(
          Case(
              name,
              wsPre,
              wsPost,
              assignChar,
              separator,
              quoting,
              wrapper,
              rounds,
              target,
              nameQuoting,
          ),
      )
    }
    for (value in nameCasings) add(name = value)
    for ((pre, post) in wsCombos) {
      add(wsPre = pre, wsPost = post)
    }
    for (value in assignChars) add(assignChar = value)
    for (value in separators) add(separator = value)
    for (value in quotings) add(quoting = value)
    for (value in wrappers) add(wrapper = value)
    for ((rounds, target) in encodings) {
      add(rounds = rounds, target = target)
    }
    for (value in nameQuotings) add(nameQuoting = value)
    return cases
  }

  /** test_sensitive_pair_grammar.py:318 (secret absent over the deterministic axis sweep). */
  @Test
  fun testSensitivePairGrammarRedactsSecretAcrossAxisSweep() {
    for ((index, case) in oneAxisSweepCases().withIndex()) {
      val secret = "SEC RET-${case.hashCode() % 1000000}-$index"
      val result =
          renderAndCheck(
              case.name,
              case.wsPre,
              case.wsPost,
              case.assignChar,
              case.separator,
              case.quoting,
              case.wrapper,
              case.encRounds,
              case.encTarget,
              secret,
              case.nameQuoting,
          )
      assertTrue(secret !in result, "secret leaked for case $index ($case): $result")
    }
  }

  /** test_sensitive_pair_grammar.py:345 benign twins byte-identical. */
  @Test
  fun testSensitivePairGrammarPreservesBenignTwins() {
    val benignValue = "benignvalue"
    for (case in oneAxisSweepCases()) {
      if (case.wrapper == "json_leaf") {
        val quotedName = quoteName(benignName, case.nameQuoting)
        val quotedBenign = quoteValue(benignValue, case.quoting)
        val pair = "$quotedName${case.wsPre}${case.assignChar}${case.wsPost}$quotedBenign"
        val result =
            LoggingUtils.redactSensitiveJson(
                linkedMapOf<String, Any?>("note" to pair),
                emptySet(),
                sensitive,
                32,
            ) as Map<*, *>
        assertEquals(pair, result["note"], "case $case")
        continue
      }
      val pair =
          makePair(
              benignName,
              case.wsPre,
              case.wsPost,
              case.assignChar,
              case.quoting,
              benignValue,
              case.encRounds,
              case.encTarget,
              case.nameQuoting,
          )
      val body = wrap(case.wrapper, pair)
      val sepText = makeSeparator(case.separator, case.encRounds, case.encTarget)
      val text = "$body$sepText$tail"
      if (eligibleForUrlDisplay(case.wsPre, case.wsPost, case.separator, case.wrapper)) {
        val url = "/r?$text"
        assertEquals(
            url,
            RequestLogging.redactUrlForDisplay(url, emptySet(), emptySet()),
            "case $case",
        )
      } else {
        assertEquals(
            text,
            RequestLogging.redactBlobForDisplay(text, emptySet(), emptySet()),
            "case $case",
        )
      }
    }
  }

  // --------------------------------------------------- assignment run grammar (:409)

  private val assignRunSpecs: List<List<Pair<String, Int>>> =
      listOf(
          listOf("=" to 0),
          listOf(":" to 0),
          listOf("=" to 1),
          listOf("=" to 2),
          listOf("=" to 3),
          listOf("=" to 0, "=" to 0),
          listOf(":" to 0, ":" to 0),
          listOf("=" to 0, "=" to 1),
          listOf("=" to 1, "=" to 0),
          listOf("=" to 2, "=" to 3),
          listOf("=" to 0, ":" to 0),
          listOf("=" to 0, "=" to 0, "=" to 0),
          listOf("=" to 1, "=" to 2, "=" to 3),
          listOf("=" to 3, "=" to 0, "=" to 1),
      )
  private val runWsInside = listOf("", " ")
  private val runOuterWs = listOf("" to "", " " to " ")
  private val runQuotings = listOf("none", "double", "single")

  private fun assignRunText(spec: List<Pair<String, Int>>, wsInside: String): String =
      spec.joinToString(wsInside) { (char, rounds) ->
        if (rounds == 0) char else percentEncodeN(char, rounds)
      }

  @Test
  fun testAssignmentRunGrammarRedactsSecret() {
    var index = 0
    for (spec in assignRunSpecs) {
      for (wsInside in runWsInside) {
        for ((wsPre, wsPost) in runOuterWs) {
          for (quoting in runQuotings) {
            index++
            val secret = "SECRET-run-$index"
            val assignRun = assignRunText(spec, wsInside)
            val quotedValue = quoteValue(secret, quoting)
            val text = "PASSWORD$wsPre$assignRun$wsPost$quotedValue $tail"
            val result = RequestLogging.redactBlobForDisplay(text, emptySet(), emptySet())
            assertTrue(secret !in result, "secret leaked for run=$index spec=$spec: $result")
          }
        }
      }
    }
  }

  @Test
  fun testAssignmentRunGrammarPreservesBenignTwin() {
    for (spec in assignRunSpecs) {
      for (wsInside in runWsInside) {
        for ((wsPre, wsPost) in runOuterWs) {
          for (quoting in runQuotings) {
            val assignRun = assignRunText(spec, wsInside)
            val quotedValue = quoteValue("benignvalue", quoting)
            val text = "$benignName$wsPre$assignRun$wsPost$quotedValue $tail"
            assertEquals(
                text,
                RequestLogging.redactBlobForDisplay(text, emptySet(), emptySet()),
                "run=$spec ws=$wsInside outer=$wsPre/$wsPost quoting=$quoting",
            )
          }
        }
      }
    }
  }

  // --------------------------------- hidden assign nested in encoded wrapper (:533)

  private val hiddenOuterRounds = listOf(1, 2, 3)
  private val hiddenSpecs: List<List<Pair<String, Int>>> =
      listOf(
          listOf("=" to 0, "=" to 0),
          listOf(":" to 0, ":" to 0),
          listOf("=" to 1, "=" to 0),
          listOf("=" to 0, "=" to 1),
          listOf("=" to 2, "=" to 3),
      )
  private val hiddenQuotings = listOf("double", "single")
  private val hiddenSeparators = listOf("&", ";", ",", "?", "|", " ", "\t", "\r", "\n", "\r\n", " ")

  private fun hiddenWrapperPairText(
      outerRounds: Int,
      spec: List<Pair<String, Int>>,
      quoting: String,
      separator: String,
      value: String,
      innerName: String = "password",
  ): String {
    val assignRun = assignRunText(spec, "")
    val quotedValue = quoteValue(value, quoting)
    val inner = "$innerName$assignRun$quotedValue"
    val wrapped = "filename=\"$inner\""
    val outerAssign = percentEncodeN("=", outerRounds)
    return "data$outerAssign$wrapped${separator}x=1${separator}y=2"
  }

  @Test
  fun testHiddenAssignNestedQuoteInsideEncodedWrapperRedactsSecret() {
    var index = 0
    for (outerRounds in hiddenOuterRounds) {
      for (spec in hiddenSpecs) {
        for (quoting in hiddenQuotings) {
          for (separator in hiddenSeparators) {
            index++
            val secret = "SECRET-hw-$index"
            val text = hiddenWrapperPairText(outerRounds, spec, quoting, separator, secret)
            val result = RequestLogging.redactBlobForDisplay(text, setOf("password"), emptySet())
            assertTrue(
                secret !in result,
                "secret leaked for outer=$outerRounds spec=$spec quoting=$quoting sep=$separator: $result",
            )
          }
        }
      }
    }
  }

  @Test
  fun testHiddenAssignNestedQuoteInsideEncodedWrapperPreservesBenign() {
    for (outerRounds in hiddenOuterRounds) {
      for (spec in hiddenSpecs) {
        for (quoting in hiddenQuotings) {
          for (separator in hiddenSeparators) {
            val text =
                hiddenWrapperPairText(
                    outerRounds,
                    spec,
                    quoting,
                    separator,
                    "benignvalue",
                    innerName = benignName,
                )
            assertEquals(
                text,
                RequestLogging.redactBlobForDisplay(text, emptySet(), emptySet()),
                "outer=$outerRounds spec=$spec quoting=$quoting sep=$separator",
            )
          }
        }
      }
    }
  }

  // ------------------------------- json leaf value with query char split (:641)

  private val escapedGaps =
      listOf(
          "\\t",
          "\\n",
          "\\r",
          "\\f",
          "\\x09",
          "\\X09",
          "\\u0020",
          "\\u{9}",
          "\\U00000009",
          "\\N{TAB}",
          "\\0",
          "\\011",
          "\\\"",
          "\\'",
      )
  private val jsonLeafWsCombos: List<Pair<String, String>> =
      listOf("" to "", "\t" to "", "" to "\t", "\t" to "\t") +
          escapedGaps.map { it to "" } +
          escapedGaps.map { " $it " to "" }

  private fun jsonLeafSplitUrl(
      innerName: String,
      wsPre: String,
      wsPost: String,
      assignChar: String,
      quoting: String,
      value: String,
      position: String,
  ): String {
    val quotedValue = quoteValue(value, quoting)
    val pair = "$innerName$wsPre$assignChar$wsPost$quotedValue"
    val noteText = "x=1?y=2?$pair?z=3"
    val blob = PyJson.dumps(linkedMapOf<String, Any?>("note" to noteText))
    return if (position == "matrix") "https://test/resource;$blob" else "https://test/$blob"
  }

  @Test
  fun testJsonLeafValueWithQueryCharAndHiddenAssignRedactsSecret() {
    var index = 0
    for ((wsPre, wsPost) in jsonLeafWsCombos) {
      for (assignChar in listOf("=", ":")) {
        for (quoting in listOf("double", "single")) {
          for (position in listOf("path", "matrix")) {
            index++
            val secret = "SECRET-jls-$index"
            val url =
                jsonLeafSplitUrl("password", wsPre, wsPost, assignChar, quoting, secret, position)
            val result = RequestLogging.redactUrlForDisplay(url, emptySet(), emptySet())
            assertTrue(
                secret !in result,
                "secret leaked for ws=($wsPre,$wsPost) assign=$assignChar quoting=$quoting pos=$position: $result",
            )
          }
        }
      }
    }
  }

  @Test
  fun testJsonLeafValueWithQueryCharAndHiddenAssignPreservesBenign() {
    for ((wsPre, wsPost) in jsonLeafWsCombos) {
      for (assignChar in listOf("=", ":")) {
        for (quoting in listOf("double", "single")) {
          for (position in listOf("path", "matrix")) {
            val url =
                jsonLeafSplitUrl(
                    benignName,
                    wsPre,
                    wsPost,
                    assignChar,
                    quoting,
                    "benignvalue",
                    position,
                )
            assertEquals(url, RequestLogging.redactUrlForDisplay(url, emptySet(), emptySet()))
          }
        }
      }
    }
  }

  // ------------------------------------------ escaped gap surfaces (:716)

  @Test
  fun testEscapedWhitespaceOrQuoteBeforeAssignmentRedactsSecret() {
    var index = 0
    for (gap in escapedGaps) {
      for (assignChar in listOf("=", ":")) {
        for (surface in listOf("header", "matrix", "json_leaf")) {
          index++
          val secret = "SECRET-egap-$index"
          val pair = "password$gap$assignChar$secret"
          val text =
              when (surface) {
                "header" -> "Mozilla/5.0 $pair x=1"
                "matrix" -> "https://test/orders;$pair/x"
                else ->
                    "https://test/resource;${PyJson.dumps(linkedMapOf<String, Any?>("note" to pair))}"
              }
          val result =
              if (surface == "header") {
                RequestLogging.redactBlobForDisplay(text, emptySet(), emptySet(), emptySet())
              } else {
                RequestLogging.redactUrlForDisplay(text, emptySet(), emptySet())
              }
          assertTrue(secret !in result, "gap=$gap assign=$assignChar $surface: $result")
        }
      }
    }
  }

  @Test
  fun testEscapedWhitespaceOrQuoteBeforeAssignmentPreservesBenign() {
    for (gap in escapedGaps) {
      for (assignChar in listOf("=", ":")) {
        for (surface in listOf("header", "matrix", "json_leaf")) {
          val pair = "$benignName$gap$assignChar" + "benignvalue"
          val text =
              when (surface) {
                "header" -> "Mozilla/5.0 $pair x=1"
                "matrix" -> "https://test/orders;$pair/x"
                else ->
                    "https://test/resource;${PyJson.dumps(linkedMapOf<String, Any?>("note" to pair))}"
              }
          val result =
              if (surface == "header") {
                RequestLogging.redactBlobForDisplay(text, emptySet(), emptySet(), emptySet())
              } else {
                RequestLogging.redactUrlForDisplay(text, emptySet(), emptySet())
              }
          assertEquals(text, result, "gap=$gap assign=$assignChar $surface")
        }
      }
    }
  }

  /** test_sensitive_pair_grammar.py:768 quoted value cut by a slash in the nested value. */
  @Test
  fun testQuotedValueCutBySlashRedactsToSegmentEnd() {
    val secret = "SECRET-nested-quote-path"
    val url =
        "https://test/filename=\"x=1%2520password%2520:%2520" +
            secret +
            "%2520<script>alert(1)</script>\"%2520y=2\""
    val result = RequestLogging.redactUrlForDisplay(url, emptySet(), emptySet())
    assertTrue(secret !in result, result)
  }

  @Test
  fun testQuotedValueCutBySlashPreservesBenignTwin() {
    val secret = "SECRET-nested-quote-path"
    val url =
        "https://test/filename=\"x=1%2520password%2520:%2520" +
            secret +
            "%2520<script>alert(1)</script>\"%2520y=2\""
    val benign = url.replace("password", "note")
    assertEquals(benign, RequestLogging.redactUrlForDisplay(benign, emptySet(), emptySet()))
  }
}
