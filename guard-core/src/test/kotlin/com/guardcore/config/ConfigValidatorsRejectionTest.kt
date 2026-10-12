package com.guardcore.config

import com.guardcore.errors.ConfigValidationError
import com.guardcore.handlers.VALID_CLOUD_PROVIDERS
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Port of the rejection arms of _security_config_field_validators.py and the typed validators
 * (_security_config_typed_validators.py, _config_field_revalidators.py): every validator's reject
 * message and arm that fromMap/builder sweeps never reach.
 */
class ConfigValidatorsRejectionTest {
  /** Asserts the block rejects with ConfigValidationError and returns the message. */
  private fun expectReject(name: String, block: () -> Unit): String {
    try {
      block()
      fail("expected ConfigValidationError for $name")
    } catch (e: ConfigValidationError) {
      return e.message ?: ""
    }
  }

  // ---- typed field helpers ----

  @Test
  fun typedFieldHelpersRejectWrongTypes() {
    assertTrue(
        "must be an int" in
            expectReject("int") { ConfigValidators.validateIntFieldValue("7", "f") },
    )
    assertTrue(
        "must be >= 1" in
            expectReject("positive") { ConfigValidators.validatePositiveIntFieldValue(0, "f") },
    )
    assertTrue(
        "must be a bool" in
            expectReject("bool") { ConfigValidators.validateBoolFieldValue("true", "f") },
    )
    assertTrue(
        "list of str" in
            expectReject("strlist") {
              ConfigValidators.validateStrListFieldValue(listOf(1, 2), "f")
            },
    )
    assertTrue(
        "must be a dict" in
            expectReject("endpoints") {
              ConfigValidators.validateEndpointRateLimitsValue(listOf<Any>())
            },
    )
    assertTrue(
        "keys must be str" in
            expectReject("endpoint keys") {
              ConfigValidators.validateEndpointRateLimitsValue(mapOf(1 to Pair(1, 2)))
            },
    )
    assertTrue(
        "(int, int) tuple" in
            expectReject("endpoint entry") {
              ConfigValidators.validateEndpointRateLimitsValue(mapOf("/x" to "nope"))
            },
    )
  }

  // ---- IP / CIDR lists ----

  @Test
  fun ipListValidatorsRejectNonListsAndBadEntries() {
    for (validator in
        listOf(
            Pair("whitelist") { v: Any? -> ConfigValidators.validateWhitelistValue(v) },
            Pair("blacklist") { v: Any? -> ConfigValidators.validateBlacklistValue(v) },
        )) {
      val err = expectReject(validator.first + " non-list") { validator.second("not-a-list") }
      assertTrue("Invalid IP or CIDR range" in err, err)
      val entryErr =
          expectReject(validator.first + " bad entry") { validator.second(listOf("nothost")) }
      assertTrue("Invalid IP or CIDR range" in entryErr, entryErr)
    }
    // trusted_proxies carries its own message prefix.
    val proxyErr =
        expectReject("trusted proxies non-list") {
          ConfigValidators.validateTrustedProxiesValue("not-a-list")
        }
    assertTrue("Invalid proxy IP or CIDR range" in proxyErr, proxyErr)
    val proxyEntry =
        expectReject("trusted proxies entry") {
          ConfigValidators.validateTrustedProxiesValue(listOf("nothost"))
        }
    assertTrue("Invalid proxy IP or CIDR range" in proxyEntry, proxyEntry)
    // allowUnix admits the unix sentinel.
    val withUnix =
        ConfigValidators.validateIpOrCidrList(listOf("unix", "10.0.0.1"), "m", allowUnix = true)
    assertEquals(listOf("unix", "10.0.0.1"), withUnix)
    // Without the flag unix is just a bad address.
    val unixErr =
        expectReject("unix without flag") {
          ConfigValidators.validateIpOrCidrList(listOf("unix"), "m")
        }
    assertTrue("m: unix" in unixErr)
  }

  // ---- membership sets ----

  @Test
  fun countrySetValidators() {
    val err = expectReject("country set") { ConfigValidators.validateCountrySetValue("US") }
    assertTrue("list/tuple/set/frozenset" in err, err)
    assertEquals(setOf("US", "CA"), ConfigValidators.validateCountrySetValue(listOf("us", "Ca")))
    // The normalized variant never rejects; non-collections collapse to empty.
    assertEquals(emptySet(), ConfigValidators.normalizedCountryValue("US"))
    assertEquals(setOf("BR"), ConfigValidators.normalizedCountryValue(listOf("br")))
  }

  @Test
  fun threatBanConfigValidators() {
    assertTrue(
        "must be a mapping" in
            expectReject("threat ban type") {
              ConfigValidators.validateThreatBanConfigValue(listOf<Any>())
            },
    )
    assertTrue(
        "keys must be str" in
            expectReject("threat ban key") {
              ConfigValidators.validateThreatBanConfigValue(mapOf(1 to "x"))
            },
    )
    assertTrue(
        "must be a ThreatBanConfig or mapping" in
            expectReject("threat ban entry") {
              ConfigValidators.validateThreatBanConfigValue(mapOf("sqli" to 5))
            },
    )
    assertTrue(
        "missing threshold" in
            expectReject("threat ban missing threshold") {
              ConfigValidators.validateThreatBanConfigValue(mapOf("sqli" to mapOf("duration" to 5)))
            },
    )
    assertTrue(
        "missing duration" in
            expectReject("threat ban missing duration") {
              ConfigValidators.validateThreatBanConfigValue(
                  mapOf("sqli" to mapOf("threshold" to 5)),
              )
            },
    )
    assertTrue(
        "Unknown threat categories" in
            expectReject("threat ban unknown category") {
              ConfigValidators.validateThreatBanConfigValue(
                  mapOf("not-a-cat" to ThreatBanConfig(5, 5)),
              )
            },
    )
    // A valid mapping with the rate_limit extension category round-trips.
    val config =
        ConfigValidators.validateThreatBanConfigValue(
            mapOf("rate_limit" to mapOf("threshold" to 3, "duration" to 9)),
        )
    assertEquals(ThreatBanConfig(3, 9), config["rate_limit"])
  }

  @Test
  fun detectionCategoryAndMuteValidators() {
    assertTrue(
        "Unknown detection categories" in
            expectReject("categories") {
              ConfigValidators.validateEnabledDetectionCategoriesValue(setOf("nonsense"))
            },
    )
    assertTrue(
        "Unknown event types" in
            expectReject("muted events") {
              ConfigValidators.validateMutedEventTypesValue(setOf("nonsense"))
            },
    )
    assertTrue(
        "Unknown metric types" in
            expectReject("muted metrics") {
              ConfigValidators.validateMutedMetricTypesValue(setOf("nonsense"))
            },
    )
    assertTrue(
        "Unknown check names" in
            expectReject("muted checks") {
              ConfigValidators.validateMutedCheckLogsValue(setOf("nonsense"))
            },
    )
  }

  @Test
  fun sensitiveNameSetValidators() {
    assertTrue(
        "not a bare string" in
            expectReject("sensitive bare string") {
              ConfigValidators.validateSensitiveNameSetValue("password", "sensitive_headers")
            },
    )
    assertTrue(
        "items must be strings" in
            expectReject("sensitive non-collection") {
              ConfigValidators.validateSensitiveNameSetValue(42, "sensitive_headers")
            },
    )
    // A collection with a non-string item rejects too.
    assertTrue(
        "items must be strings" in
            expectReject("sensitive list non-str") {
              ConfigValidators.validateSensitiveNameSetValue(listOf(1), "sensitive_headers")
            },
    )
    assertEquals(emptySet(), ConfigValidators.validateSensitiveNameSetValue(null, "f"))
  }

  @Test
  fun blockCloudProvidersValidators() {
    assertNullShape()
    assertTrue(
        "Unknown cloud providers" in
            expectReject("cloud providers") {
              ConfigValidators.validateBlockCloudProvidersValue(setOf("not-a-cloud"))
            },
    )
    // A bare valid provider and a :!region carve-out both validate.
    val provider = VALID_CLOUD_PROVIDERS.first()
    val ok =
        ConfigValidators.validateBlockCloudProvidersValue(setOf(provider, "$provider:!us-east-1"))
    assertNotNull(ok)
    assertEquals(2, ok!!.size)
  }

  private fun assertNullShape() {
    assertNull(ConfigValidators.validateBlockCloudProvidersValue(null))
  }

  @Test
  fun excludePathsValidators() {
    assertTrue(
        "list of str" in
            expectReject("exclude paths type") {
              ConfigValidators.validateExcludePathsValue("not-a-list")
            },
    )
    assertTrue(
        "could not be normalized" in
            expectReject("exclude paths malformed") {
              ConfigValidators.validateExcludePathsValue(listOf("%c0%af"))
            },
    )
    assertTrue(
        "normalizes to the root" in
            expectReject("exclude paths root") {
              ConfigValidators.validateExcludePathsValue(listOf("/x/../"))
            },
    )
    // The literal '/' is accepted with a warning.
    assertEquals(listOf("/"), ConfigValidators.validateExcludePathsValue(listOf("/")))
  }

  @Test
  fun dynamicRulesCachePathValidators() {
    assertTrue(
        "non-empty filesystem path" in
            expectReject("cache path type") {
              ConfigValidators.validateDynamicRulesCachePathValue(42)
            },
    )
    assertTrue(
        "must not be empty" in
            expectReject("cache path blank") {
              ConfigValidators.validateDynamicRulesCachePathValue("   ")
            },
    )
    assertEquals(
        Paths.get("/tmp/rules.json"),
        ConfigValidators.validateDynamicRulesCachePathValue("/tmp/rules.json"),
    )
    assertEquals(
        Paths.get("/tmp/rules.json"),
        ConfigValidators.validateDynamicRulesCachePathValue(Paths.get("/tmp/rules.json")),
    )
  }

  // ---- return_pattern rules ----

  private val patternRule =
      BehaviorRuleConfig(
          ruleType = RuleType.RETURN_PATTERN,
          threshold = 1,
          pattern = "secret-token",
      )

  @Test
  fun returnPatternScanValidation() {
    val err =
        expectReject("return pattern requires scan") {
          ConfigValidators.validateReturnPatternRequiresScan(
              "secret-token",
              scanResponseBody = false,
          )
        }
    assertTrue("behavior_scan_response_body" in err, err)
    // A status: pattern never requires the body.
    ConfigValidators.validateReturnPatternRequiresScan("status: 404", scanResponseBody = false)
    // The config-backed wrapper reads behaviorScanResponseBody.
    val permissive = SecurityConfigBuilder.fromMap(mapOf("behavior_scan_response_body" to true))
    ConfigValidators.validateReturnPatternBodyScan("secret-token", permissive)
    val strict =
        SecurityConfigBuilder.fromMap(mapOf<String, Any?>("exclude_paths" to listOf("/ok")))
    val bodyErr =
        expectReject("body scan wrapper") {
          ConfigValidators.validateReturnPatternBodyScan("secret-token", strict)
        }
    assertTrue("behavior_scan_response_body" in bodyErr)
    // The assignment-time coercion revalidates return_pattern rules against the
    // scan flag, so the poisoned pair rejects right in fromMap.
    val revalidateErr =
        expectReject("assign poisoned pair") {
          SecurityConfigBuilder.fromMap(
              mapOf(
                  "behavior_scan_response_body" to false,
                  "global_behavior_rules" to listOf(patternRule),
              ),
              warnUnknown = false,
          )
        }
    assertTrue("behavior_scan_response_body" in revalidateErr)
    // The same pair with the flag on assigns cleanly.
    val ok =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "behavior_scan_response_body" to true,
                "global_behavior_rules" to listOf(patternRule),
            ),
            warnUnknown = false,
        )
    assertTrue(ok.globalBehaviorRules.isNotEmpty())
  }

  @Test
  fun globalBehaviorRuleAssignmentValidation() {
    val config =
        SecurityConfigBuilder.fromMap(mapOf<String, Any?>("exclude_paths" to listOf("/ok")))
    // The default global list is empty, so the plain assignment passes.
    ConfigValidators.validateGlobalBehaviorRuleAssignment(
        config,
        "behavior_scan_response_body",
        false,
    )
    val ok = runCatching {
      ConfigValidators.validateGlobalBehaviorRuleAssignment(
          config,
          "behavior_scan_response_body",
          true,
      )
    }
    assertTrue(ok.isSuccess)
    // Assigning a rule list through the global name validates each rule.
    val assignErr =
        expectReject("rule list assignment") {
          val mutated = SecurityConfigBuilder.fromMap(mapOf("behavior_scan_response_body" to false))
          ConfigValidators.validateGlobalBehaviorRuleAssignment(
              mutated,
              "global_behavior_rules",
              listOf(patternRule),
          )
        }
    assertTrue(assignErr.isNotEmpty())
  }

  // ---- typed collection validators ----

  @Test
  fun typedCollectionValidatorsRejectWrongShapes() {
    assertTrue(
        "keys must be int" in
            expectReject("int keyed") {
              ConfigValidators.validateIntKeyedStrDict(mapOf("x" to "y"), "f")
            },
    )
    assertTrue(
        "values must be str" in
            expectReject("int keyed values") {
              ConfigValidators.validateIntKeyedStrDict(mapOf(1 to 2), "f")
            },
    )
    assertTrue(
        "must be a dict of str keys and str values" in
            expectReject("str keyed") {
              ConfigValidators.validateStrKeyedStrDict(mapOf(1 to "y"), "f")
            },
    )
    assertTrue(
        "must be a dict of str keys and str values" in
            expectReject("str keyed values") {
              ConfigValidators.validateStrKeyedStrDict(mapOf("a" to 2), "f")
            },
    )
    // The optional str list runs the typed helper on the value.
    assertTrue(
        "list of str" in
            expectReject("optional str list") {
              @Suppress("UNCHECKED_CAST")
              ConfigValidators.validateOptionalStrList(listOf(1) as List<String>, "f")
            },
    )
  }

  // ---- warnings ----

  @Test
  fun prefixZeroWarningsFire() {
    val captured = mutableListOf<String>()
    val handler =
        object : java.util.logging.Handler() {
          override fun publish(record: java.util.logging.LogRecord) {
            captured.add(record.message)
          }

          override fun flush() {}

          override fun close() {}
        }
    val logger = ConfigWarnings.logger
    logger.addHandler(handler)
    try {
      ConfigValidators.warnTrustedProxiesPrefixZero()
      ConfigValidators.warnWhitelistPrefixZero()
      ConfigValidators.warnExemptIpsPrefixZero(listOf("0.0.0.0/0", "10.0.0.1"))
      ConfigValidators.warnEmptyEnabledDetectionCategories()
      assertTrue(captured.any { it.contains("trusted_proxies") })
      assertTrue(captured.any { it.contains("whitelist") })
      assertTrue(captured.any { it.contains("exempt_ips") })
      assertTrue(captured.any { it.contains("enabled_detection_categories") })
      // A non-prefix-zero exempt list stays silent.
      captured.clear()
      ConfigValidators.warnExemptIpsPrefixZero(listOf("10.0.0.1"))
      assertTrue(captured.isEmpty())
    } finally {
      logger.removeHandler(handler)
    }
  }
}
