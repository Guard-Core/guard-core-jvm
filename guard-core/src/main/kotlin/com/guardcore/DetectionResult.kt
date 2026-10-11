package com.guardcore

/**
 * Port of `guard_core/detection_result.py` (detection_result.py:5): the pipeline-facing detection
 * verdict. Threat dicts from the engine collapse into category/score summaries via
 * `com.guardcore.util.DetectionResultBuilders`.
 */
public class DetectionResult(
    public val isThreat: Boolean,
    public val triggerInfo: String,
    public val threatCategories: List<String> = emptyList(),
    public val threatScores: Map<String, Double> = emptyMap(),
)
