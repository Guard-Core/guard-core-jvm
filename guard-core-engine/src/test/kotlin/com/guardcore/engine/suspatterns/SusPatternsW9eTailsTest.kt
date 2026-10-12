package com.guardcore.engine.suspatterns

import com.guardcore.engine.detection.firstOverBudgetReason
import com.guardcore.engine.py.PyRe
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9e arm closure for the suspatterns modules: the seeded single arms (pickle string/int decoders,
 * backtick-pair verdict windows, recon-path probes, the manager add/remove surface and the
 * candidate-rejection scan loop) plus the arbiter deadline injection. The shared manager state is
 * restored after every mutation.
 */
class SusPatternsW9eTailsTest {
  private fun configure(semanticThreshold: Double = 0.7) {
    SusPatternsManager.shared()
        .configure(
            object : DetectionConfigView {
              override val detectionCompilerTimeout: Double = 10.0
              override val detectionMaxTrackedPatterns: Int = 1000
              override val detectionMaxContentLength: Int = 100000
              override val detectionPreserveAttackPatterns: Boolean = true
              override val detectionAnomalyThreshold: Double = 3.0
              override val detectionSlowPatternThreshold: Double = 0.1
              override val detectionMonitorHistorySize: Int = 1000
              override val detectionAnomalyEmissionCooldown: Double = 60.0
              override val detectionMinSamplesForAnomaly: Int = 30
              override val detectionSemanticThreshold: Double = semanticThreshold
              override val detectionThreatScoreThreshold: Double = 1.0
              override val detectionMaxBodyInspectBytes: Int = 262144
              override val detectionPatternValidationCachePath: String? = null
            },
        )
  }

  private fun reset() {
    SusPatternsManager.shared().configure(null)
  }

  // ------------------------------------------------------------ pickle decoders

  @Test
  fun `pickle stream walks signed ints and quoted escape strings`() {
    // signed + multi-digit ints through the I opcode
    assertTrue(pickleGlobalPrefixIsOpcodeStream("I-42\np0\n."))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("I+37\np0\n."))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("I12345\np0\n."))
    // quoted strings with n/t/r escapes and an unknown escape fall-through
    assertTrue(pickleGlobalPrefixIsOpcodeStream("S'a\\nb\\tc\\rd\\qe'\np0\n."))
    assertTrue(pickleGlobalPrefixIsOpcodeStream("V\"x\\ny\"\np0\n."))
  }

  // ------------------------------------------------------------ matchers / sources

  @Test
  fun `pickle global marker scan advances past implausible candidates`() {
    // the first two candidates lack a following identifier char; the third succeeds
    assertEquals(2, pickleGlobalFirstValidMarker("c co", 'c', 'c', 0, 10))
    // every candidate fails the identifier-start test -> null
    assertNull(pickleGlobalFirstValidMarker("c,c", 'c', 'c', 0, 10))
    assertEquals(0, pickleGlobalFirstValidMarker("co", 'c', 'c', 0, 10))
  }

  @Test
  fun `recon path value probe treats absolute groups as probes`() {
    val pattern = PyRe.compile("/[a-z]+", 0)
    val match = assertNotNull(pattern.search("x /admin y", 0, Long.MAX_VALUE))
    // a leading-slash group is a probe in every context
    assertTrue(reconPathValueIsProbe(match, "header"))
    // a relative group is only a probe in the bare-path contexts
    val relativePattern = PyRe.compile("admin", 0)
    val relative = assertNotNull(relativePattern.search("x admin y", 0, Long.MAX_VALUE))
    assertFalse(reconPathValueIsProbe(relative, "header"))
    assertTrue(reconPathValueIsProbe(relative, "url_path"))
  }

  // ------------------------------------------------------------ backtick pair verdict

  @Test
  fun `backtick pair verdict walks the window and sql-glue arms`() {
    val pattern = PyRe.compile("`[^`]+`", 0)
    // a plain quoted identifier in prose: not glued, no appended clause -> not injection
    val plain = assertNotNull(pattern.search("see `name` below", 0, Long.MAX_VALUE))
    assertFalse(gluedBacktickPairIsInjection(plain, "body"))
    // glued with shell metacharacters in the window -> injection
    val glued = assertNotNull(pattern.search("x`id`;whoami", 0, Long.MAX_VALUE))
    assertTrue(gluedBacktickPairIsInjection(glued, "body"))
  }

  // ------------------------------------------------------------ manager add/remove

  @Test
  fun `manager add and remove pattern walk both custom arms`() {
    val shared = SusPatternsManager.shared()
    try {
      configure()
      // the default (non-custom) arm
      assertTrue(shared.addPattern("w9e_default_pat"))
      assertTrue(shared.removePattern("w9e_default_pat"))
      assertFalse(shared.removePattern("w9e_default_pat"))
      // a custom pattern the registry round-trips
      assertTrue(shared.addPattern("w9e_custom_pat", custom = true))
      assertTrue(shared.removePattern("w9e_custom_pat", custom = true))
      assertFalse(shared.removePattern("w9e_custom_pat", custom = true))
      // an unsafe pattern is rejected at add time
      assertFalse(shared.addPattern("(a+)+\$"))
    } finally {
      shared.removePattern("w9e_default_pat")
      shared.removePattern("w9e_default_pat", custom = true)
      reset()
    }
  }

  // ------------------------------------------------------------ candidate rejection loop

  @Test
  fun `detection scan rejects benign candidates then admits real threats`() {
    try {
      configure()
      val shared = SusPatternsManager.shared()
      // a quoted SQL identifier is a glued-backtick candidate but not an injection; a later
      // shell-shaped pair is. The scan must advance past the rejected candidate.
      val verdict = shared.detect("see `name` below then x`id`;whoami", "203.0.113.7", "body")
      assertTrue(verdict.threats.isNotEmpty(), "second candidate should threaten")
      // a fully benign content with only rejected candidates stays clean
      val clean = shared.detect("see `name` below", "203.0.113.7", "body")
      assertTrue(clean.threats.none { it.category == "suspicious" }, clean.threats.toString())
    } finally {
      reset()
    }
  }

  @Test
  fun `detection scan emits the semantic fallback threat`() {
    try {
      // a near-zero semantic threshold makes a plain keyword soup cross the fallback line
      configure(semanticThreshold = 0.05)
      val verdict =
          SusPatternsManager.shared()
              .detect("function import class module def return", "203.0.113.7", "body")
      assertTrue(
          verdict.threats.any { it.type == "semantic" },
          verdict.threats.map { it.type }.toString(),
      )
    } finally {
      reset()
    }
  }

  // ------------------------------------------------------------ arbiter deadline injection

  @Test
  fun `first over budget reason honors an already-expired deadline`() {
    val builders =
        com.guardcore.engine.detection.reachProbeCandidateBuilders("[ab]+[bc]+", 0, Long.MAX_VALUE)
    assertTrue(builders.isNotEmpty())
    val reason =
        firstOverBudgetReason(
            "[ab]+[bc]+",
            builders,
            8192,
            null,
            System.nanoTime() + 1,
        )
    assertNotNull(reason)
    assertTrue(reason.contains("timeout"), reason)
  }

  @Test
  fun `reach probe cost verdict reports construction budget exhaustion`() {
    try {
      configure()
      // the state-budget bomb throws PatternValidationTimeout inside the builders phase
      val alt130 = (1..130).joinToString("|") { "a$it" }
      val stateBomb = "(?:$alt130)(?:$alt130)+c"
      val (safe, reason) = com.guardcore.engine.detection.reachProbeCostVerdict(stateBomb, null)
      assertFalse(safe)
      assertTrue(reason.isNotEmpty(), reason)
    } finally {
      reset()
    }
  }

  // ------------------------------------------------------------ file upload / templates

  @Test
  fun `file upload truncation and template date arms answer`() {
    // raw truncation markers after a dangerous extension
    assertTrue(
        SusPatternsFileUpload.isTruncation("evil.php%00.jpg", decoded = false),
        "raw percent truncation",
    )
    assertTrue(
        SusPatternsFileUpload.isTruncation("evil.php;touch", decoded = false),
        "semicolon truncation",
    )
    // decoded truncation via the kind router
    assertTrue(
        SusPatternsFileUpload.kindMatches(
            "filename=\"evil.php\u0000\"",
            SusPatternsFileUpload.DECODED_TRUNCATION_RE,
        ),
        "decoded truncation kind",
    )
    // the date-anchored template arm: a date before a second frame re-anchors the start
    val compiled = PyRe.compile("[a-z]+\\(.*\\)", 0)
    val dated =
        SusPatternsTemplates.templateExpressionMatches(
            "{{a 2024-01-01 {{f()}}",
            compiled,
            "curly",
        )
    assertTrue(dated.isNotEmpty(), "dated template")
    // a plain frame keeps the start anchor
    val plain = SusPatternsTemplates.templateExpressionMatches("{{ f() }}", compiled, "curly")
    assertTrue(plain.isNotEmpty(), "plain template")
  }
}
