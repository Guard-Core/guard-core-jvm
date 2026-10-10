package com.guardcore.util

import com.guardcore.config.ConfigSeams
import com.guardcore.engine.detection.PatternCompiler
import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReFlags
import com.guardcore.engine.suspatterns.SusPatternsManager
import com.guardcore.errors.ConfigValidationError

/**
 * W2 seam registration: wires the detection engine into the facade seams left open in W1
 * (KNOWN_GAPS.md G-1, G-4, G-5). Mirrors the python wiring sites:
 *
 * - G-1 `ConfigSeams.blockedUserAgentsPatternGate`
 *   (guard_core/_security_config_field_validators.py:324-340): every blocked_user_agents pattern
 *   must pass PatternCompiler.validate_pattern_safety with max_content_length =
 *   _MAX_USER_AGENT_MATCH_LENGTH (512) or construction fails.
 * - G-4 `BodyReader.straddleOverlapBytesProvider` (body_reader.py:46-58): the longest-pattern
 *   overlap computation used when a straddled body chunk boundary might hide a pattern prefix; the
 *   engine exposes the compiled max-pattern length.
 * - G-5 `AccessControl.userAgentBlockedPatternMatcher`
 *   (guard_core/_utils/detection_scan.py:197-208): subject truncated to
 *   _MAX_USER_AGENT_MATCH_LENGTH, each pattern matched via the inline safe finder.
 */
public object DetectionEngineWiring {
  /** _MAX_USER_AGENT_MATCH_LENGTH (guard_core/_utils/detection_scan.py:194). */
  public const val MAX_USER_AGENT_MATCH_LENGTH: Int = 512

  @Volatile private var registered: Boolean = false

  /** _MAX_STRADDLE_OVERLAP_BYTES (guard_core/_utils/body_reader.py). */
  public const val MAX_STRADDLE_OVERLAP_BYTES: Int = 256

  /** Idempotent: registers all three seams on first call. */
  public fun register() {
    if (registered) return
    synchronized(this) {
      if (registered) return
      registerBlockedUserAgentsGate()
      registerUserAgentBlockedPatternMatcher()
      registerStraddleOverlapProvider()
      registered = true
    }
  }

  /** G-1: the config-layer ReDoS gate for blocked_user_agents patterns. */
  private fun registerBlockedUserAgentsGate() {
    ConfigSeams.blockedUserAgentsPatternGate = { patterns ->
      val compiler = PatternCompiler()
      for (pattern in patterns) {
        val (isSafe, reason) =
            compiler.validatePatternSafety(
                pattern,
                maxContentLength = MAX_USER_AGENT_MATCH_LENGTH,
            )
        if (!isSafe) {
          throw ConfigValidationError(
              "blocked_user_agents pattern rejected by ReDoS validator: " +
                  "\"$pattern\" ($reason)",
          )
        }
      }
    }
  }

  /** G-5: the UA blocked-pattern matcher over the inline safe finder. */
  private fun registerUserAgentBlockedPatternMatcher() {
    AccessControl.userAgentBlockedPatternMatcher = { userAgent, patterns ->
      val subject = userAgent.take(MAX_USER_AGENT_MATCH_LENGTH)
      val compiler = PatternCompiler()
      var blocked = false
      for (pattern in patterns) {
        val matches =
            try {
              val compiled = compiler.compilePattern(pattern, PyReFlags.DEFAULT)
              compiled.finditer(subject, Long.MAX_VALUE)
            } catch (e: PyRe.DeadlineExceededException) {
              emptyList()
            } catch (e: Exception) {
              // python: create_async_safe_finditer_matcher swallows compile/match errors
              emptyList()
            }
        if (matches.isNotEmpty()) {
          blocked = true
          break
        }
      }
      blocked
    }
  }

  /** G-4: the longest compiled pattern length, capped at the straddle window. */
  private fun registerStraddleOverlapProvider() {
    BodyReader.straddleOverlapBytesProvider = {
      val patterns = SusPatternsManager.shared().compiledPatterns
      if (patterns.isEmpty()) {
        0
      } else {
        val longest = patterns.maxOf { it.compiled.source.length }
        minOf(longest, MAX_STRADDLE_OVERLAP_BYTES)
      }
    }
  }
}
