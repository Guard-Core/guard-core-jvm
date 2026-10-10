package com.guardcore.config

import com.guardcore.errors.ConfigValidationError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Ports of tests/test_models/test_behavior_rule_config.py construction rules, tests/test_protocols/
 * surface checks, and RuleConfigs helpers.
 */
class RuleConfigsTest {
  @Test
  fun testBehaviorRuleConfigDefaults() {
    val rule = BehaviorRuleConfig(ruleType = RuleType.USAGE, threshold = 3)
    assertEquals(3600, rule.window)
    assertEquals(null, rule.pattern)
    assertEquals(RuleAction.LOG, rule.action)
    assertEquals(null, rule.banDuration)
    assertEquals(false, rule.correlateWithDetection)
  }

  @Test
  fun testBehaviorRuleConfigBounds() {
    assertFailsWith<ConfigValidationError> {
      BehaviorRuleConfig(ruleType = RuleType.USAGE, threshold = 0)
    }
    assertFailsWith<ConfigValidationError> {
      BehaviorRuleConfig(ruleType = RuleType.USAGE, threshold = 1, window = 0)
    }
    assertFailsWith<ConfigValidationError> {
      BehaviorRuleConfig(ruleType = RuleType.USAGE, threshold = 1, banDuration = 0)
    }
  }

  @Test
  fun testThreatBanConfigBounds() {
    assertFailsWith<ConfigValidationError> { ThreatBanConfig(0, 10) }
    assertFailsWith<ConfigValidationError> { ThreatBanConfig(3, 0) }
    assertEquals(ThreatBanConfig(3, 60), ThreatBanConfig(3, 60))
  }

  @Test
  fun testReturnPatternRequiresResponseBody() {
    assertTrue(returnPatternRequiresResponseBody("regex:.*"))
    assertTrue(returnPatternRequiresResponseBody("json:$.secret"))
    assertTrue(returnPatternRequiresResponseBody("plain"))
    assertTrue(!returnPatternRequiresResponseBody("status:404"))
  }

  @Test
  fun testDetectionCategoriesConstant() {
    // _suspatterns_sources.py:89-110, verbatim 19 categories.
    assertEquals(19, DetectionCategories.ALL_DETECTION_CATEGORIES.size)
    assertTrue("xss" in DetectionCategories.ALL_DETECTION_CATEGORIES)
    assertTrue("deserialization" in DetectionCategories.ALL_DETECTION_CATEGORIES)
    // THREAT_BAN_CONFIG_CATEGORIES = ALL | {"rate_limit"}.
    assertEquals(20, DetectionCategories.THREAT_BAN_CONFIG_CATEGORIES.size)
    assertTrue("rate_limit" in DetectionCategories.THREAT_BAN_CONFIG_CATEGORIES)
  }

  @Test
  fun testCloudProvidersConstant() {
    // field_validators.py:37-38, verbatim.
    assertEquals(
        setOf("AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"),
        CloudProviders.VALID_CLOUD_PROVIDERS,
    )
  }

  @Test
  fun testEventTypeValuesConstant() {
    // event_types.py:46-88: 39 event types, verbatim membership spots.
    assertEquals(39, EventTypes.EVENT_TYPE_VALUES.size)
    assertTrue("penetration_attempt" in EventTypes.EVENT_TYPE_VALUES)
    assertTrue("pattern_anomaly_statistical_anomaly" in EventTypes.EVENT_TYPE_VALUES)
    // metric types (event_types.py:94-100).
    assertEquals(
        setOf("response_time", "request_count", "error_rate"),
        EventTypes.METRIC_TYPE_VALUES,
    )
    // check names (event_types.py:102-122): the 17 pipeline checks.
    assertEquals(17, EventTypes.CHECK_NAME_VALUES.size)
    assertTrue("ip_security" in EventTypes.CHECK_NAME_VALUES)
  }

  @Test
  fun testEventFilter() {
    val filter =
        EventFilter(mutedEventTypes = setOf("rate_limited"), mutedMetricTypes = setOf("error_rate"))
    assertEquals(false, filter.isEventAllowed("rate_limited"))
    assertEquals(true, filter.isEventAllowed("ip_blocked"))
    assertEquals(false, filter.isMetricAllowed("error_rate"))
    assertEquals(true, filter.isMetricAllowed("response_time"))
  }

  @Test
  fun testValidationErrorMessageTypeIsConfigValidationError() {
    // Python raises ValueError inside validators; the port raises
    // ConfigValidationError, a GuardCoreError subclass.
    val e =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder().apply { trustedProxyDepth = 0 }.build()
        }
    assertTrue(e is com.guardcore.errors.GuardCoreError)
  }
}
