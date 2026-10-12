package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.isIpBanned
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.AccessControl
import com.guardcore.util.RequestLogging
import com.guardcore.util.py.parseAddress as pyParseAddress

/** Python `_route_overrides_ip_lists` (ip_security.py:24). */
private fun routeOverridesIpLists(routeConfig: RouteConfig?): Boolean =
    !routeConfig?.ipWhitelist.isNullOrEmpty()

/** Python `_route_country_whitelist_matched` (ip_security.py:28). */
private fun routeCountryWhitelistMatched(
    clientIp: String,
    routeConfig: RouteConfig?,
    geoIpHandler: com.guardcore.protocols.GeoIPHandler?,
): Boolean {
  if (routeConfig == null) {
    return false
  }
  return ChecksHelpers.checkCountryAccess(clientIp, routeConfig, geoIpHandler) == true
}

/** Python `_resolve_is_whitelisted` (ip_security.py:36). */
private fun resolveIsWhitelisted(
    clientIp: String,
    routeConfig: RouteConfig?,
    config: SecurityConfig,
    isAllowed: Boolean,
    skipIpLists: Boolean,
): Boolean = isAllowed && !config.whitelist.isNullOrEmpty() && !skipIpLists

/** Python `_resolve_is_exempt` (ip_security.py:46). */
private fun resolveIsExempt(
    clientIp: String,
    config: SecurityConfig,
    isAllowed: Boolean,
    skipIpLists: Boolean,
): Boolean {
  if (!isAllowed || skipIpLists || config.exemptIps.isEmpty()) {
    return false
  }
  val clientIpAddr =
      try {
        pyParseAddress(clientIp)
      } catch (e: com.guardcore.errors.ConfigValidationError) {
        return false
      }
  return AccessControl.ipInList(clientIpAddr, clientIp, config.exemptIps)
}

/** Python `_classify_route_ip_denial` (ip_security.py:58). */
private fun classifyRouteIpDenial(
    routeConfig: RouteConfig,
    geoIpHandler: com.guardcore.protocols.GeoIPHandler?,
    clientIp: String,
    countryResult: Boolean?,
): Pair<String, String> {
  if (
      countryResult != false ||
          !routeConfig.ipWhitelist.isNullOrEmpty() ||
          !routeConfig.ipBlacklist.isNullOrEmpty()
  ) {
    return "access_control" to "ip_restriction"
  }
  val blockedCountries = routeConfig.blockedCountries
  if (!blockedCountries.isNullOrEmpty() && geoIpHandler?.getCountry(clientIp) in blockedCountries) {
    return "block_countries" to "country_restriction"
  }
  return "allow_countries" to "country_restriction"
}

/**
 * Port of `guard_core/core/checks/implementations/ip_security.py`: IpSecurityCheck
 * (ip_security.py:78).
 */
public class IpSecurityCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val enforcedOnExcludedPaths: Boolean = true

  /** Python `__init__` (ip_security.py:81): the module-singleton ban manager. */
  private val ipBanManager: IpBanManager = IpBanManager.getInstance()

  override val checkName: String = "ip_security"

  /** Python async `_check_banned_ip` (ip_security.py:91). */
  private suspend fun checkBannedIp(
      request: GuardRequest,
      clientIp: String,
      routeConfig: RouteConfig?,
  ): GuardResponse? {
    if (middleware.routeResolver?.shouldBypassCheck("ip_ban", routeConfig) == true) {
      return null
    }

    if (!ipBanManager.isIpBanned(clientIp)) {
      return null
    }

    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "Banned IP attempted access: $clientIp",
        level = config.logSuspiciousLevel?.pythonName,
        passiveMode = config.passiveMode,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    middleware.eventBus?.sendMiddlewareEvent(
        EventTypes.EVENT_IP_BLOCKED,
        request,
        if (!config.passiveMode) "request_blocked" else "logged_only",
        "Banned IP attempted access: $clientIp",
        linkedMapOf(
            "ip_address" to clientIp,
            "filter_type" to "banned",
        ),
    )

    if (!config.passiveMode) {
      return middleware.createErrorResponse(403, "IP address banned")
    }

    return null
  }

  /** Python async `_check_route_ip_restrictions` (ip_security.py:134). */
  private suspend fun checkRouteIpRestrictions(
      request: GuardRequest,
      clientIp: String,
      routeConfig: RouteConfig,
  ): GuardResponse? {
    val routeAllowed = ChecksHelpers.checkRouteIpAccess(clientIp, routeConfig, middleware)

    if (routeAllowed == null || routeAllowed) {
      return null
    }

    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "IP not allowed by route config: $clientIp",
        level = config.logSuspiciousLevel?.pythonName,
        passiveMode = config.passiveMode,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    val countryResult =
        ChecksHelpers.checkCountryAccess(clientIp, routeConfig, middleware.geoIpHandler)
    val (decoratorType, violationType) =
        classifyRouteIpDenial(routeConfig, middleware.geoIpHandler, clientIp, countryResult)

    ChecksHelpers.emitAccessDeniedEvent(
        middleware,
        request,
        eventType = EventTypes.EVENT_DECORATOR_VIOLATION,
        reason = "IP $clientIp blocked",
        decoratorType = decoratorType,
        passiveMode = config.passiveMode,
        linkedMapOf("violation_type" to violationType),
    )

    if (!config.passiveMode) {
      ChecksHelpers.escalateIdentityViolation(
          middleware,
          config,
          ipBanManager,
          request,
          clientIp,
          logger,
          checkName,
          config.mutedCheckLogs,
          "ip_restriction",
          "IP not allowed by route config: $clientIp",
      )
      return middleware.createErrorResponse(403, "Forbidden")
    }

    return null
  }

  /** Python async `_resolve_global_ip_access` (ip_security.py:196). */
  private suspend fun resolveGlobalIpAccess(
      clientIp: String,
      routeConfig: RouteConfig?,
  ): Triple<AccessControl.IpAccessResult, Boolean, Boolean> {
    val skipIpLists = routeOverridesIpLists(routeConfig)
    val skipCountries = routeCountryWhitelistMatched(clientIp, routeConfig, middleware.geoIpHandler)

    val accessResult =
        AccessControl.checkIpAccess(
            clientIp,
            config,
            middleware.geoIpHandler,
            skipIpLists = skipIpLists,
            skipCountries = skipCountries,
        )

    val isWhitelisted =
        resolveIsWhitelisted(clientIp, routeConfig, config, accessResult.allowed, skipIpLists)
    val isExempt = resolveIsExempt(clientIp, config, accessResult.allowed, skipIpLists)
    return Triple(accessResult, isWhitelisted, isExempt)
  }

  /** Python async `_check_global_ip_restrictions` (ip_security.py:222). */
  private suspend fun checkGlobalIpRestrictions(
      request: GuardRequest,
      clientIp: String,
      routeConfig: RouteConfig?,
      escalate: Boolean = true,
      precomputed: Triple<AccessControl.IpAccessResult, Boolean, Boolean>? = null,
  ): GuardResponse? {
    val (accessResult, isWhitelisted, isExempt) =
        precomputed ?: resolveGlobalIpAccess(clientIp, routeConfig)
    request.state.setAttr("is_whitelisted", isWhitelisted)
    request.state.setAttr("is_exempt", isExempt)

    if (accessResult.allowed) {
      return null
    }

    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "IP not allowed: $clientIp - ${accessResult.reason}",
        level = config.logSuspiciousLevel?.pythonName,
        passiveMode = config.passiveMode,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    val eventKwargs = LinkedHashMap<String, Any?>()
    if (accessResult.cloudProvider != null) {
      eventKwargs["cloud_provider"] = accessResult.cloudProvider
    }
    if (accessResult.network != null) {
      eventKwargs["network"] = accessResult.network
    }

    middleware.eventBus?.sendMiddlewareEvent(
        EventTypes.EVENT_IP_BLOCKED,
        request,
        if (!config.passiveMode) "request_blocked" else "logged_only",
        accessResult.reason,
        LinkedHashMap(eventKwargs).also {
          it["ip_address"] = clientIp
          it["filter_type"] = "global"
        },
    )

    if (!config.passiveMode) {
      if (escalate) {
        ChecksHelpers.escalateIdentityViolation(
            middleware,
            config,
            ipBanManager,
            request,
            clientIp,
            logger,
            checkName,
            config.mutedCheckLogs,
            "ip_blocked",
            accessResult.reason,
        )
      }
      return middleware.createErrorResponse(403, "Forbidden")
    }

    return null
  }

  /** Python async `check` (ip_security.py:294). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val clientIp = request.state.getAttr("client_ip") as? String
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig
    if (clientIp.isNullOrEmpty()) {
      return null
    }

    val banResponse = checkBannedIp(request, clientIp, routeConfig)
    if (banResponse != null) {
      return banResponse
    }

    if (request.state.getAttr("guard_exclusion_scoped") == true) {
      return checkGlobalIpRestrictions(request, clientIp, null, escalate = false)
    }

    if (middleware.routeResolver?.shouldBypassCheck("ip", routeConfig) == true) {
      return null
    }

    var precomputed: Triple<AccessControl.IpAccessResult, Boolean, Boolean>? = null
    if (routeConfig != null) {
      precomputed = resolveGlobalIpAccess(clientIp, routeConfig)
      val routeResponse = checkRouteIpRestrictions(request, clientIp, routeConfig)
      if (routeResponse != null) {
        return routeResponse
      }
    }

    return checkGlobalIpRestrictions(request, clientIp, routeConfig, precomputed = precomputed)
  }

  public companion object : CheckCompanion<IpSecurityCheck>() {
    override fun create(middleware: GuardMiddlewareProtocol): IpSecurityCheck =
        IpSecurityCheck(middleware)
  }
}
