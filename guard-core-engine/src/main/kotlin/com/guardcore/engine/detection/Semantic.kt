package com.guardcore.engine.detection

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.py.PyRePattern
import com.guardcore.engine.py.PyUnicode
import kotlin.math.log2

/**
 * SemanticAnalyzer: token/keyword/structure heuristics behind the semantic threat path.
 *
 * Port of guard_core/detection_engine/semantic.py. The AST-parse risk check (_check_ast_
 * parsing_risk) is a python-grammar oracle; the JVM engine's analog compiles the content as a
 * python-expression grammar via the PyRe parser surface and times it under a 0.1s budget.
 */
private const val BINARY_CONTENT_RATIO_THRESHOLD = 0.2

/** looks_like_binary_content. */
public fun looksLikeBinaryContent(content: String): Boolean {
  if (content.isEmpty()) return false
  var nonText = 0
  for (ch in content) {
    val printable = PyUnicode.isPrintable(ch)
    if (ch != '\t' && ch != '\r' && ch != '\n' && (!printable || ch == '\uFFFD')) nonText++
  }
  return nonText.toDouble() / content.length >= BINARY_CONTENT_RATIO_THRESHOLD
}

private val semanticWhitespace: PyRePattern = PyRe.compile("\\s+", 0)
private val wordTokenRe: PyRePattern = PyRe.compile("\\b\\w+\\b", 0)
private val specialCharRe: PyRePattern = PyRe.compile("[^a-zA-Z0-9\\s]", 0)
private val longRunRe: PyRePattern = PyRe.compile("\\S{100,}", 0)
private val percentRe: PyRePattern = PyRe.compile("%[0-9a-fA-F]{2}", 0)
private val base64RunRe: PyRePattern = PyRe.compile("[A-Za-z0-9+/]{4,}={0,2}", 0)
private val hexRunRe: PyRePattern = PyRe.compile("(?:0x)?[0-9a-fA-F]{4,}", 0)
private val unicodeEscapeRe: PyRePattern = PyRe.compile("\\\\u[0-9a-fA-F]{4}", 0)
private val htmlEntityRe: PyRePattern = PyRe.compile("&[#\\w]+;", 0)
private val braceNestingRe: PyRePattern = PyRe.compile("[\\{\\}].*[\\{\\}]", PyReFlags.DOTALL)
private val dollarVarRe: PyRePattern = PyRe.compile("[$@]\\w+", 0)
private val operatorRunRe: PyRePattern = PyRe.compile("[=+\\-*/]{2,}", 0)
private val functionCallRe: PyRePattern = PyRe.compile("\\w{1,64}\\s*\\([^)]{0,256}\\)", 0)

public class SemanticAnalyzer {
  public val attackKeywords: Map<String, Set<String>> =
      mapOf(
          "xss" to
              setOf(
                  "script",
                  "javascript",
                  "onerror",
                  "onload",
                  "onclick",
                  "onmouseover",
                  "alert",
                  "eval",
                  "document",
                  "cookie",
                  "window",
                  "location",
              ),
          "sql" to
              setOf(
                  "select",
                  "union",
                  "insert",
                  "update",
                  "delete",
                  "drop",
                  "from",
                  "where",
                  "order",
                  "group",
                  "having",
                  "concat",
                  "substring",
                  "database",
                  "table",
                  "column",
              ),
          "command" to
              setOf(
                  "exec",
                  "system",
                  "shell",
                  "cmd",
                  "bash",
                  "powershell",
                  "wget",
                  "curl",
                  "nc",
                  "netcat",
                  "chmod",
                  "chown",
                  "sudo",
                  "passwd",
              ),
          "path" to setOf("etc", "passwd", "shadow", "hosts", "proc", "boot", "win", "ini"),
          "template" to
              setOf(
                  "render",
                  "template",
                  "jinja",
                  "mustache",
                  "handlebars",
                  "ejs",
                  "pug",
                  "twig",
              ),
      )

  public val attackStructures: Map<String, PyRePattern> =
      mapOf(
          "tag_like" to PyRe.compile("<[^>]+>", 0),
          "function_call" to PyRe.compile("\\w{1,64}\\s*\\([^)]{0,256}\\)", 0),
          "command_chain" to PyRe.compile("[;&|]{1,2}", 0),
          "path_traversal" to PyRe.compile("\\.{2,20}[/\\\\]", 0),
          "url_pattern" to PyRe.compile("[a-z]{1,32}://", 0),
      )

  private val structureBoostPatterns: Map<String, Pair<PyRePattern, Int>> =
      mapOf(
          "xss" to Pair(attackStructures["tag_like"]!!, 0),
          "sql" to Pair(PyRe.compile("\\b(?:union|select|from|where)\\b", 0), PyReFlags.IGNORECASE),
          "command" to Pair(PyRe.compile("[;&|]", 0), 0),
          "path" to Pair(attackStructures["path_traversal"]!!, 0),
      )

  private val injectionKeywordPatterns: List<PyRePattern> =
      listOf("eval", "exec", "compile", "__import__", "globals", "locals").map {
        PyRe.compile("\\b$it\\b", PyReFlags.IGNORECASE)
      }

  /** _tag_scan_window. */
  private fun tagScanWindow(content: String): String {
    val lastGt = content.lastIndexOf('>')
    return if (lastGt == -1) "" else content.substring(0, lastGt + 1)
  }

  /** extract_tokens. */
  public fun extractTokens(content: String): List<String> {
    val maxContentLength = 50000
    var content = content
    if (content.length > maxContentLength) content = content.substring(0, maxContentLength)

    content = semanticWhitespace.replaceAll(content) { " " }

    val maxTokens = 1000
    val tokens =
        wordTokenRe.finditer(content.lowercase(), Long.MAX_VALUE).map { it.group() }.take(maxTokens)

    val specialPatterns = ArrayList<String>()
    for ((name, pattern) in attackStructures) {
      val scanContent = if (name == "tag_like") tagScanWindow(content) else content
      val flags = if (name == "tag_like") 0 else PyReFlags.IGNORECASE
      val matches = finditerWithFlags(pattern, scanContent, flags).map { it.group() }.take(10)
      specialPatterns.addAll(matches)
      if (specialPatterns.size >= 50) break
    }

    return (tokens + specialPatterns).take(maxTokens)
  }

  // The structure regexes are compiled without case flags; python scans them with
  // re.IGNORECASE, so re-scan with a case-insensitive compiled variant when needed.
  private val ignorecaseCache: MutableMap<PyRePattern, PyRePattern> = HashMap()

  private fun finditerWithFlags(
      pattern: PyRePattern,
      content: String,
      flags: Int,
  ): List<com.guardcore.engine.py.PyReMatch> {
    val effective =
        if (flags and PyReFlags.IGNORECASE != 0) {
          synchronized(ignorecaseCache) {
            ignorecaseCache.getOrPut(pattern) {
              PyRe.compile(pattern.source, flags)
            }
          }
        } else {
          pattern
        }
    return effective.finditer(content, Long.MAX_VALUE)
  }

  /** calculate_entropy. */
  public fun calculateEntropy(content: String): Double {
    if (content.isEmpty()) return 0.0
    val maxEntropyLength = 10000
    var content = content
    if (content.length > maxEntropyLength) content = content.substring(0, maxEntropyLength)

    val charCounts = HashMap<Char, Int>()
    for (ch in content) charCounts[ch] = (charCounts[ch] ?: 0) + 1
    val length = content.length

    var entropy = 0.0
    for (count in charCounts.values) {
      val probability = count.toDouble() / length
      if (probability > 0) entropy -= probability * log2(probability)
    }
    return entropy
  }

  /** detect_encoding_layers. */
  public fun detectEncodingLayers(content: String): Int {
    val maxScanLength = 10000
    var content = content
    if (content.length > maxScanLength) content = content.substring(0, maxScanLength)

    var layers = 0
    if (percentRe.search(content, 0, Long.MAX_VALUE) != null) layers += 1
    if (base64RunRe.search(content, 0, Long.MAX_VALUE) != null) layers += 1
    if (hexRunRe.search(content, 0, Long.MAX_VALUE) != null) layers += 1
    if (unicodeEscapeRe.search(content, 0, Long.MAX_VALUE) != null) layers += 1
    if (htmlEntityRe.search(content, 0, Long.MAX_VALUE) != null) layers += 1
    return layers
  }

  private fun calculateBaseScore(tokenSet: Set<String>, keywords: Set<String>): Double {
    if (keywords.isEmpty()) return 0.0
    val matches = tokenSet.intersect(keywords).size
    return matches.toDouble() / keywords.size
  }

  private fun getStructuralPatternBoost(attackType: String, content: String): Double {
    val check = structureBoostPatterns[attackType] ?: return 0.0
    val (pattern, flags) = check
    val scanContent = if (attackType == "xss") tagScanWindow(content) else content
    val effective =
        if (flags and PyReFlags.IGNORECASE != 0) {
          synchronized(ignorecaseCache) {
            ignorecaseCache.getOrPut(pattern) { PyRe.compile(pattern.source, flags) }
          }
        } else {
          pattern
        }
    if (effective.search(scanContent, 0, Long.MAX_VALUE) != null) return 0.3
    return 0.0
  }

  private fun attackProbabilitiesForTokens(
      tokenSet: Set<String>,
      content: String,
  ): Map<String, Double> {
    val probabilities = LinkedHashMap<String, Double>()
    for ((attackType, keywords) in attackKeywords) {
      val baseScore = calculateBaseScore(tokenSet, keywords)
      val patternBoost = getStructuralPatternBoost(attackType, content)
      val score = baseScore + patternBoost
      probabilities[attackType] = minOf(score, 1.0)
    }
    return probabilities
  }

  /** analyze_attack_probability. */
  public fun analyzeAttackProbability(content: String): Map<String, Double> {
    val tokens = extractTokens(content)
    return attackProbabilitiesForTokens(tokens.toSet(), content)
  }

  /** detect_obfuscation. */
  public fun detectObfuscation(content: String): Boolean {
    if (looksLikeBinaryContent(content)) return false
    if (calculateEntropy(content) > 4.5) return true
    if (detectEncodingLayers(content) > 2) return true
    val specialCharRatio =
        specialCharRe.finditer(content, Long.MAX_VALUE).size.toDouble() / maxOf(content.length, 1)
    if (specialCharRatio > 0.4) return true
    if (longRunRe.search(content, 0, Long.MAX_VALUE) != null) return true
    return false
  }

  /** extract_suspicious_patterns. */
  public fun extractSuspiciousPatterns(content: String): List<Map<String, Any>> {
    val patterns = ArrayList<Map<String, Any>>()
    for ((name, pattern) in attackStructures) {
      val scanContent = if (name == "tag_like") tagScanWindow(content) else content
      val flags = if (name == "tag_like") 0 else PyReFlags.IGNORECASE
      for (match in finditerWithFlags(pattern, scanContent, flags)) {
        val contextStart = maxOf(0, match.start() - 20)
        val contextEnd = minOf(content.length, match.end() + 20)
        patterns.add(
            mapOf(
                "type" to name,
                "pattern" to match.group(),
                "position" to match.start(),
                "context" to content.substring(contextStart, contextEnd),
            ),
        )
      }
    }
    return patterns
  }

  private fun checkCodePatternRisks(content: String): Double {
    var risk = 0.0
    if (braceNestingRe.search(content, 0, Long.MAX_VALUE) != null) risk += 0.2
    if (functionCallRe.search(content, 0, Long.MAX_VALUE) != null) risk += 0.2
    if (dollarVarRe.search(content, 0, Long.MAX_VALUE) != null) risk += 0.1
    if (operatorRunRe.search(content, 0, Long.MAX_VALUE) != null) risk += 0.1
    return risk
  }

  /**
   * _check_ast_parsing_risk analog: python parses its own grammar in a worker with a 0.1s timeout
   * (0.3 for parse success, 0.2 on timeout). The JVM engine parses the content with the PyRe
   * expression parser (a python-grammar oracle) under the same budget.
   */
  private fun checkAstParsingRisk(content: String): Double {
    val maxAstLength = 1000
    if (content.length > maxAstLength) return 0.0
    val result = java.util.concurrent.atomic.AtomicReference<String?>("pending")
    val thread = Thread {
      result.set(
          try {
            if (com.guardcore.engine.py.PyAst.parsesAsExpression(content)) "parsed" else "failed"
          } catch (e: Exception) {
            "failed"
          },
      )
    }
    thread.isDaemon = true
    thread.start()
    thread.join(100)
    if (thread.isAlive) {
      thread.interrupt()
      return 0.2
    }
    return when (result.get()) {
      "parsed" -> 0.3
      else -> 0.0
    }
  }

  private fun checkInjectionKeywords(content: String): Double {
    for (pattern in injectionKeywordPatterns) {
      if (pattern.search(content, 0, Long.MAX_VALUE) != null) return 0.2
    }
    return 0.0
  }

  /** analyze_code_injection_risk. */
  public fun analyzeCodeInjectionRisk(content: String): Double {
    var riskScore = 0.0
    riskScore += checkCodePatternRisks(content)
    riskScore += checkAstParsingRisk(content)
    riskScore += checkInjectionKeywords(content)
    return minOf(riskScore, 1.0)
  }

  /** analyze: the full analysis map (threat-score input). */
  public fun analyze(content: String): Map<String, Any> {
    val tokens = extractTokens(content)
    return mapOf(
        "attack_probabilities" to attackProbabilitiesForTokens(tokens.toSet(), content),
        "entropy" to calculateEntropy(content),
        "encoding_layers" to detectEncodingLayers(content),
        "is_obfuscated" to detectObfuscation(content),
        "suspicious_patterns" to extractSuspiciousPatterns(content),
        "code_injection_risk" to analyzeCodeInjectionRisk(content),
        "token_count" to tokens.size,
    )
  }

  /** get_threat_score. */
  public fun getThreatScore(analysisResults: Map<String, Any>): Double {
    var score = 0.0

    @Suppress("UNCHECKED_CAST")
    val attackProbs = analysisResults["attack_probabilities"] as? Map<String, Double>
    if (attackProbs != null && attackProbs.isNotEmpty()) {
      val maxProb = attackProbs.values.max()
      score += maxProb * 0.3
    }

    if (analysisResults["is_obfuscated"] == true) score += 0.2

    val encodingLayers = analysisResults["encoding_layers"] as? Int ?: 0
    if (encodingLayers > 0) score += minOf(encodingLayers * 0.1, 0.2)

    val injectionRisk = analysisResults["code_injection_risk"] as? Double ?: 0.0
    score += injectionRisk * 0.2

    val patterns = analysisResults["suspicious_patterns"] as? List<*>
    if (!patterns.isNullOrEmpty()) score += minOf(patterns.size * 0.05, 0.1)

    return minOf(score, 1.0)
  }
}
