package com.guardcore.core

import com.guardcore.config.LogLevel
import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.ChecksFactory
import com.guardcore.core.checks.SecurityCheckPipeline
import com.guardcore.core.checks.implementations.AuthenticationCheck
import com.guardcore.core.checks.implementations.CloudIpRefreshCheck
import com.guardcore.core.checks.implementations.CloudProviderCheck
import com.guardcore.core.checks.implementations.CustomValidatorsCheck
import com.guardcore.core.checks.implementations.EmergencyModeCheck
import com.guardcore.core.checks.implementations.HttpsEnforcementCheck
import com.guardcore.core.checks.implementations.RateLimitCheck
import com.guardcore.core.checks.implementations.ReferrerCheck
import com.guardcore.core.checks.implementations.RequestLoggingCheck
import com.guardcore.core.checks.implementations.RequestSizeContentCheck
import com.guardcore.core.checks.implementations.RequiredHeadersCheck
import com.guardcore.core.checks.implementations.SuspiciousActivityCheck
import com.guardcore.core.checks.implementations.TimeWindowCheck
import com.guardcore.core.checks.implementations.UserAgentCheck
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.BehaviorRule
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_check_applies_to.py: the exhaustive applies-to matrix over the
 * config-driven checks, the dynamic-rules keep flag, the route-driven checks, and the
 * behaviour-rules-can-ban ip_security survival.
 */
class CheckAppliesToTest {
  private fun routeConfig(apply: RouteConfig.() -> Unit = {}): RouteConfig {
    val rc = RouteConfig()
    rc.apply()
    return rc
  }

  private data class ConfigCase(
      val id: String,
      val factory: com.guardcore.core.checks.SecurityCheckFactory,
      val config: SecurityConfig,
      val routeConfigs: List<RouteConfig>,
      val expected: Boolean,
  )

  private val configDrivenCases: List<ConfigCase> =
      listOf(
          ConfigCase(
              "emergency_mode-keep",
              EmergencyModeCheck,
              coreTestConfig { emergencyMode = true },
              emptyList(),
              true,
          ),
          ConfigCase(
              "emergency_mode-drop",
              EmergencyModeCheck,
              coreTestConfig(),
              emptyList(),
              false,
          ),
          ConfigCase(
              "https_enforcement-keep",
              HttpsEnforcementCheck,
              coreTestConfig { enforceHttps = true },
              emptyList(),
              true,
          ),
          ConfigCase(
              "https_enforcement-drop",
              HttpsEnforcementCheck,
              coreTestConfig(),
              emptyList(),
              false,
          ),
          ConfigCase(
              "request_logging-keep",
              RequestLoggingCheck,
              coreTestConfig { logRequestLevel = LogLevel.INFO },
              emptyList(),
              true,
          ),
          ConfigCase(
              "request_logging-drop",
              RequestLoggingCheck,
              coreTestConfig(),
              emptyList(),
              false,
          ),
          ConfigCase(
              "cloud_ip_refresh-keep",
              CloudIpRefreshCheck,
              coreTestConfig { blockCloudProviders = setOf("AWS") },
              emptyList(),
              true,
          ),
          ConfigCase(
              "cloud_ip_refresh-drop",
              CloudIpRefreshCheck,
              coreTestConfig(),
              emptyList(),
              false,
          ),
          ConfigCase(
              "cloud_provider-keep",
              CloudProviderCheck,
              coreTestConfig { blockCloudProviders = setOf("AWS") },
              emptyList(),
              true,
          ),
          ConfigCase(
              "cloud_provider-drop",
              CloudProviderCheck,
              coreTestConfig(),
              emptyList(),
              false,
          ),
          ConfigCase(
              "user_agent-keep",
              UserAgentCheck,
              coreTestConfig { blockedUserAgents = listOf("badbot") },
              emptyList(),
              true,
          ),
          ConfigCase("user_agent-drop", UserAgentCheck, coreTestConfig(), emptyList(), false),
          ConfigCase(
              "custom_request-keep",
              com.guardcore.core.checks.implementations.CustomRequestCheck,
              coreTestConfig {
                customRequestCheck = com.guardcore.config.CustomRequestCheck { _ -> null }
              },
              emptyList(),
              true,
          ),
          ConfigCase(
              "custom_request-drop",
              com.guardcore.core.checks.implementations.CustomRequestCheck,
              coreTestConfig(),
              emptyList(),
              false,
          ),
          ConfigCase(
              "rate_limit-keep",
              RateLimitCheck,
              coreTestConfig {
                enableRateLimiting = false
                endpointRateLimits = mapOf("/x" to Pair(5, 60))
              },
              emptyList(),
              true,
          ),
          ConfigCase(
              "rate_limit-drop",
              RateLimitCheck,
              coreTestConfig { enableRateLimiting = false },
              emptyList(),
              false,
          ),
          ConfigCase(
              "rate_limit-route-keep",
              RateLimitCheck,
              coreTestConfig { enableRateLimiting = false },
              listOf(routeConfig { rateLimit = 5 }),
              true,
          ),
          ConfigCase(
              "rate_limit-route-drop",
              RateLimitCheck,
              coreTestConfig { enableRateLimiting = false },
              listOf(routeConfig()),
              false,
          ),
          ConfigCase(
              "suspicious_activity-keep",
              SuspiciousActivityCheck,
              coreTestConfig { enablePenetrationDetection = false },
              listOf(routeConfig()),
              true,
          ),
          ConfigCase(
              "suspicious_activity-drop",
              SuspiciousActivityCheck,
              coreTestConfig { enablePenetrationDetection = false },
              emptyList(),
              false,
          ),
      )

  @Test
  fun configDrivenCheckAppliesToMatchesPredicate() {
    for (case in configDrivenCases) {
      assertEquals(
          case.expected,
          case.factory.appliesTo(case.config, case.routeConfigs),
          "applies_to drifted for ${case.id}",
      )
    }
  }

  private val dynamicRuleEscapeChecks =
      listOf(
          EmergencyModeCheck,
          CloudIpRefreshCheck,
          CloudProviderCheck,
          UserAgentCheck,
          RateLimitCheck,
          SuspiciousActivityCheck,
      )

  @Test
  fun dynamicRulesFlagForcesKeepRegardlessOfOtherFlags() {
    for (factory in dynamicRuleEscapeChecks) {
      val config = coreTestConfig {
        enableDynamicRules = true
        enableAgent = true
        agentApiKey = "test-key"
        enableIpBanning = false
        enableRateLimiting = false
        enablePenetrationDetection = false
      }
      assertEquals(
          true,
          factory.appliesTo(config, emptyList()),
          "dynamic rules must keep $factory",
      )
    }
  }

  private data class RouteCase(
      val id: String,
      val factory: com.guardcore.core.checks.SecurityCheckFactory,
      val routeConfigs: List<RouteConfig>?,
      val expected: Boolean,
  )

  private val routeDrivenCases: List<RouteCase> =
      listOf(
          RouteCase(
              "request_size_content-keep",
              RequestSizeContentCheck,
              listOf(routeConfig { maxRequestSize = 1000 }),
              true,
          ),
          RouteCase(
              "request_size_content-drop",
              RequestSizeContentCheck,
              listOf(routeConfig()),
              false,
          ),
          RouteCase("request_size_content-none-keeps", RequestSizeContentCheck, null, true),
          RouteCase(
              "required_headers-keep",
              RequiredHeadersCheck,
              listOf(
                  routeConfig { requiredHeaders["X-Api-Key"] = "required" },
              ),
              true,
          ),
          RouteCase("required_headers-drop", RequiredHeadersCheck, listOf(routeConfig()), false),
          RouteCase("required_headers-none-keeps", RequiredHeadersCheck, null, true),
          RouteCase(
              "authentication-keep",
              AuthenticationCheck,
              listOf(routeConfig { authRequired = "bearer" }),
              true,
          ),
          RouteCase("authentication-drop", AuthenticationCheck, listOf(routeConfig()), false),
          RouteCase("authentication-none-keeps", AuthenticationCheck, null, true),
          RouteCase(
              "referrer-keep",
              ReferrerCheck,
              listOf(routeConfig { requireReferrer = listOf("example.com") }),
              true,
          ),
          RouteCase("referrer-drop", ReferrerCheck, listOf(routeConfig()), false),
          RouteCase("referrer-none-keeps", ReferrerCheck, null, true),
          RouteCase(
              "custom_validators-keep",
              CustomValidatorsCheck,
              listOf(
                  routeConfig { customValidators.add { _ -> null } },
              ),
              true,
          ),
          RouteCase("custom_validators-drop", CustomValidatorsCheck, listOf(routeConfig()), false),
          RouteCase("custom_validators-none-keeps", CustomValidatorsCheck, null, true),
          RouteCase(
              "time_window-keep",
              TimeWindowCheck,
              listOf(
                  routeConfig { timeRestrictions = mapOf("start" to "00:00", "end" to "23:59") },
              ),
              true,
          ),
          RouteCase("time_window-drop", TimeWindowCheck, listOf(routeConfig()), false),
          RouteCase("time_window-none-keeps", TimeWindowCheck, null, true),
          RouteCase(
              "cloud_ip_refresh-route-keep",
              CloudIpRefreshCheck,
              listOf(routeConfig { blockCloudProviders = mutableSetOf("AWS") }),
              true,
          ),
          RouteCase(
              "cloud_ip_refresh-route-drop",
              CloudIpRefreshCheck,
              listOf(routeConfig()),
              false,
          ),
          RouteCase("cloud_ip_refresh-none-keeps", CloudIpRefreshCheck, null, true),
          RouteCase(
              "cloud_provider-route-keep",
              CloudProviderCheck,
              listOf(routeConfig { blockCloudProviders = mutableSetOf("AWS") }),
              true,
          ),
          RouteCase("cloud_provider-route-drop", CloudProviderCheck, listOf(routeConfig()), false),
          RouteCase("cloud_provider-none-keeps", CloudProviderCheck, null, true),
      )

  @Test
  fun routeDrivenCheckAppliesToMatchesPredicate() {
    val config = coreTestConfig()
    for (case in routeDrivenCases) {
      assertEquals(
          case.expected,
          case.factory.appliesTo(config, case.routeConfigs),
          "applies_to drifted for ${case.id}",
      )
    }
  }

  @Test
  fun ipSecuritySurvivesWhenOnlyBehaviourRulesCanBan() {
    val config = coreTestConfig {
      enableIpBanning = false
      enableDynamicRules = false
    }
    val routeConfig = routeConfig {
      behaviorRules.add(
          BehaviorRule(ruleType = "usage", threshold = 5, action = "ban"),
      )
    }
    val middleware = TestMiddleware(config)
    val routeResolver = RouteResolverStubForAppliesTo(mapOf("/api" to routeConfig))
    val withResolver = TestMiddleware(config, resolver = routeResolver)
    val pipeline: SecurityCheckPipeline = ChecksFactory.buildDefaultPipeline(withResolver)
    assertTrue(
        pipeline.getCheckNames().contains("ip_security"),
        "ip_security must survive when only behaviour rules can ban: " + pipeline.getCheckNames(),
    )
  }
}

/** Route resolver stub keyed on url path (the python middleware_for helper's fixed route). */
private class RouteResolverStubForAppliesTo(
    private val routes: Map<String, RouteConfig>,
) : com.guardcore.protocols.RouteConfigResolverProtocol {
  override fun getRouteConfig(request: com.guardcore.protocols.GuardRequest): Any? =
      routes[request.urlPath]

  override fun shouldBypassCheck(checkName: String, routeConfig: Any?): Boolean = false

  override fun getCloudProvidersToCheck(routeConfig: Any?): List<String> = emptyList()
}
