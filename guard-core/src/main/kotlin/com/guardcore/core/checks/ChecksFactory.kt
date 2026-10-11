package com.guardcore.core.checks

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.implementations.AuthenticationCheck
import com.guardcore.core.checks.implementations.CloudIpRefreshCheck
import com.guardcore.core.checks.implementations.CloudProviderCheck
import com.guardcore.core.checks.implementations.CustomRequestCheck
import com.guardcore.core.checks.implementations.CustomValidatorsCheck
import com.guardcore.core.checks.implementations.EmergencyModeCheck
import com.guardcore.core.checks.implementations.HttpsEnforcementCheck
import com.guardcore.core.checks.implementations.IpSecurityCheck
import com.guardcore.core.checks.implementations.RateLimitCheck
import com.guardcore.core.checks.implementations.ReferrerCheck
import com.guardcore.core.checks.implementations.RequestLoggingCheck
import com.guardcore.core.checks.implementations.RequestSizeContentCheck
import com.guardcore.core.checks.implementations.RequiredHeadersCheck
import com.guardcore.core.checks.implementations.RouteConfigCheck
import com.guardcore.core.checks.implementations.SuspiciousActivityCheck
import com.guardcore.core.checks.implementations.TimeWindowCheck
import com.guardcore.core.checks.implementations.UserAgentCheck
import com.guardcore.decorators.RouteConfig
import com.guardcore.decorators.RouteConfigProvider
import com.guardcore.protocols.GuardMiddlewareProtocol

/**
 * The JVM idiom for the python classmethod surface (factory.py:30-54): each check's companion
 * object carries `applies_to` (as [appliesTo]), the ClassVar `container_fields`, and the
 * constructor lambda.
 */
public interface SecurityCheckFactory {
  public val containerFields: List<String>
    get() = emptyList()

  public fun appliesTo(config: SecurityConfig, routeConfigs: Collection<RouteConfig>?): Boolean

  public fun create(middleware: GuardMiddlewareProtocol): SecurityCheck
}

/** Default carrier for check companions: python's base-class defaults (base.py:15-30). */
public abstract class CheckCompanion<T : SecurityCheck> : SecurityCheckFactory {
  override val containerFields: List<String> = emptyList()

  override fun appliesTo(config: SecurityConfig, routeConfigs: Collection<RouteConfig>?): Boolean =
      true
}

/**
 * Port of `guard_core/core/checks/factory.py`: the fixed check order (factory.py:30-48), the
 * watched container fields (factory.py:50-54), and `build_default_pipeline` (factory.py:86).
 */
public object ChecksFactory {
  /** Python `DEFAULT_CHECK_CLASSES` (factory.py:30). FIXED ORDER - parity-critical. */
  public val DEFAULT_CHECK_CLASSES: List<SecurityCheckFactory> =
      listOf(
          RouteConfigCheck,
          EmergencyModeCheck,
          HttpsEnforcementCheck,
          RequestLoggingCheck,
          RequestSizeContentCheck,
          RequiredHeadersCheck,
          AuthenticationCheck,
          ReferrerCheck,
          CustomValidatorsCheck,
          TimeWindowCheck,
          CloudIpRefreshCheck,
          IpSecurityCheck,
          CloudProviderCheck,
          UserAgentCheck,
          RateLimitCheck,
          SuspiciousActivityCheck,
          CustomRequestCheck,
      )

  /** Python `WATCHED_CONTAINER_FIELDS` (factory.py:50), de-duplicated in first-seen order. */
  public val WATCHED_CONTAINER_FIELDS: List<String> =
      DEFAULT_CHECK_CLASSES.flatMap { it.containerFields }.distinct()

  /** Python `_collect_route_configs` (factory.py:57): `decorator._route_configs.values()`. */
  public fun collectRouteConfigs(middleware: GuardMiddlewareProtocol): Collection<RouteConfig>? {
    val decorator = middleware.guardDecorator as? RouteConfigProvider ?: return null
    return decorator.getRouteConfigs().values.toList()
  }

  /** Python `_route_config_revision` (factory.py:66): `decorator.route_config_revision`. */
  public fun routeConfigRevision(middleware: GuardMiddlewareProtocol): Int? {
    val decorator = middleware.guardDecorator as? RouteConfigProvider ?: return null
    return decorator.getRevisionValue()
  }

  /** Python `_build_checks` (factory.py:74). */
  public fun buildChecks(middleware: GuardMiddlewareProtocol): List<SecurityCheck> {
    val config = middleware.config
    val routeConfigs = collectRouteConfigs(middleware)
    return DEFAULT_CHECK_CLASSES.filter { it.appliesTo(config, routeConfigs) }
        .map { it.create(middleware) }
  }

  /** Python `build_default_pipeline` (factory.py:86). */
  public fun buildDefaultPipeline(middleware: GuardMiddlewareProtocol): SecurityCheckPipeline {
    val config = middleware.config
    return SecurityCheckPipeline(
        buildChecks(middleware),
        mutedCheckLogs = config.mutedCheckLogs,
        config = config,
        rebuildChecks = { buildChecks(middleware) },
        watchedContainerFields = WATCHED_CONTAINER_FIELDS,
        routeConfigRevision = { routeConfigRevision(middleware) },
    )
  }
}
