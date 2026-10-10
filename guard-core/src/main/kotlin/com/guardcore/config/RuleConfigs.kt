package com.guardcore.config

import com.guardcore.errors.ConfigValidationError

/** Python `Literal` for BehaviorRuleConfig.rule_type (_security_config_field_validators.py:90). */
public enum class RuleType(val pythonName: String) {
  USAGE("usage"),
  RETURN_PATTERN("return_pattern"),
  FREQUENCY("frequency"),
}

/** Python `Literal` for BehaviorRuleConfig.action (_security_config_field_validators.py:94). */
public enum class RuleAction(val pythonName: String) {
  BAN("ban"),
  LOG("log"),
  THROTTLE("throttle"),
  ALERT("alert"),
}

/**
 * Port of `ThreatBanConfig` (_security_config_field_validators.py:79-81): per-category threshold
 * and duration, both ge=1.
 */
public class ThreatBanConfig(
    public val threshold: Int,
    public val duration: Int,
) {
  init {
    if (threshold < 1) {
      throw ConfigValidationError(
          "Input should be greater than or equal to 1 [type=greater_than_equal]" +
              " (threshold=$threshold)",
      )
    }
    if (duration < 1) {
      throw ConfigValidationError(
          "Input should be greater than or equal to 1 [type=greater_than_equal]" +
              " (duration=$duration)",
      )
    }
  }

  override fun equals(other: Any?): Boolean =
      other is ThreatBanConfig && other.threshold == threshold && other.duration == duration

  override fun hashCode(): Int = threshold * 31 + duration
}

/**
 * Port of `BehaviorRuleConfig` (_security_config_field_validators.py:89-96), field-for-field with
 * the same defaults and constraints.
 */
public class BehaviorRuleConfig(
    public val ruleType: RuleType,
    public val threshold: Int,
    public val window: Int = 3600,
    public val pattern: String? = null,
    public val action: RuleAction = RuleAction.LOG,
    public val banDuration: Int? = null,
    public val correlateWithDetection: Boolean = false,
) {
  init {
    if (threshold < 1) {
      throw ConfigValidationError(
          "threshold: Input should be greater than or equal to 1 [type=greater_than_equal]",
      )
    }
    if (window < 1) {
      throw ConfigValidationError(
          "window: Input should be greater than or equal to 1 [type=greater_than_equal]",
      )
    }
    if (banDuration != null && banDuration < 1) {
      throw ConfigValidationError(
          "ban_duration: Input should be greater than or equal to 1 [type=greater_than_equal]",
      )
    }
  }

  override fun equals(other: Any?): Boolean =
      other is BehaviorRuleConfig &&
          other.ruleType == ruleType &&
          other.threshold == threshold &&
          other.window == window &&
          other.pattern == pattern &&
          other.action == action &&
          other.banDuration == banDuration &&
          other.correlateWithDetection == correlateWithDetection

  override fun hashCode(): Int {
    var result = ruleType.hashCode()
    result = result * 31 + threshold
    result = result * 31 + window
    result = result * 31 + (pattern?.hashCode() ?: 0)
    result = result * 31 + action.hashCode()
    result = result * 31 + (banDuration ?: 0)
    result = result * 31 + correlateWithDetection.hashCode()
    return result
  }
}

/** Port of `return_pattern_requires_response_body` (_security_config_field_validators.py:99). */
public fun returnPatternRequiresResponseBody(pattern: String): Boolean =
    !pattern.startsWith("status:")
