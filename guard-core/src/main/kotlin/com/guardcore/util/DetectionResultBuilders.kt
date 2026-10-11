package com.guardcore.util

import com.guardcore.DetectionResult
import com.guardcore.engine.suspatterns.Threat
import com.guardcore.engine.suspatterns.sanitizeForReporting

/**
 * Port of `guard_core/_utils/detection_result_builders.py` (G-7d,
 * detection_result_builders.py:5-43): collapse engine threat dicts into the pipeline-facing
 * [DetectionResult].
 */
public object DetectionResultBuilders {
  /** Python `_threat_category` (detection_result_builders.py:5). */
  public fun threatCategory(threat: Threat): String? =
      if (threat.type == "regex") {
        threat.category
      } else if (threat.type == "semantic") {
        threat.attackType
      } else {
        null
      }

  /** Python `_threat_score` (detection_result_builders.py:15). */
  public fun threatScore(threat: Threat): Double {
    threat.probability?.let {
      return it
    }
    threat.threatScore?.let {
      return it
    }
    return 1.0
  }

  /** Python `_build_detection_hit` (detection_result_builders.py:23). */
  public fun buildDetectionHit(trigger: String, threats: List<Threat>): DetectionResult {
    val categories = mutableListOf<String>()
    val scores = mutableMapOf<String, Double>()
    for (threat in threats) {
      val category = threatCategory(threat) ?: continue
      if (category !in categories) {
        categories.add(category)
      }
      val score = threatScore(threat)
      scores[category] = maxOf(scores[category] ?: 0.0, score)
    }
    return DetectionResult(
        isThreat = true,
        triggerInfo = sanitizeForReporting(trigger),
        threatCategories = categories,
        threatScores = scores,
    )
  }

  /** Python `_build_detection_miss` (detection_result_builders.py:42). */
  public fun buildDetectionMiss(): DetectionResult =
      DetectionResult(isThreat = false, triggerInfo = "")
}
