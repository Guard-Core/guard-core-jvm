package com.guardcore.core.checks

import com.guardcore.DetectionResult
import com.guardcore.config.SecurityConfig
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.banIp
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.util.AccessControl
import com.guardcore.util.IpExtraction
import com.guardcore.util.RequestLogging
import com.guardcore.util.py.IpAddress as PyIpAddress
import com.guardcore.util.py.PyUrllib
import com.guardcore.util.py.parseAddress as pyParseAddress
import java.util.logging.Logger

/**
 * Port of `guard_core/core/checks/helpers.py`: the shared check utilities (helpers.py:32-544). G-9
 * closes here: `_resolve_and_apply_threshold_ban` (helpers.py:375) folds in from the W3
 * `handlers/ThresholdBans.kt` slice with the rest of the file.
 */
public object ChecksHelpers {
  /** Python `_MAX_TRACKED_SUSPICIOUS_IPS` (helpers.py:27). */
  public const val MAX_TRACKED_SUSPICIOUS_IPS: Int = 10_000

  /** Python `_DETECTION_RESULT_STATE_ATTR` (helpers.py:28). */
  public const val DETECTION_RESULT_STATE_ATTR: String = "_guard_detection_result_cache"

  private val suspiciousCountsLock = Any()

  /** Python `get_guard_decorator` (helpers.py:32). */
  public fun getGuardDecorator(middleware: Any?, request: GuardRequest?): BaseSecurityDecorator? {
    val resolver = (middleware as? GuardMiddlewareProtocol)?.routeResolver
    val context = (resolver as? com.guardcore.core.routing.RouteConfigResolver)?.context
    var guardDecorator = context?.guardDecorator
    if (guardDecorator !is BaseSecurityDecorator && request != null) {
      guardDecorator = request.state.getAttr("guard_decorator") as? BaseSecurityDecorator
    }
    return guardDecorator as? BaseSecurityDecorator
  }

  /** Python async `emit_access_denied_event` (helpers.py:43). */
  public suspend fun emitAccessDeniedEvent(
      middleware: GuardMiddlewareProtocol,
      request: GuardRequest,
      eventType: String,
      reason: String,
      decoratorType: String,
      passiveMode: Boolean,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    val guardDecorator = getGuardDecorator(middleware, request)
    if (guardDecorator != null) {
      guardDecorator.sendAccessDeniedEvent(request, reason, decoratorType, metadata)
      return
    }
    middleware.eventBus?.sendMiddlewareEvent(
        eventType,
        request,
        if (!passiveMode) "request_blocked" else "logged_only",
        reason,
        LinkedHashMap(metadata).also { it["decorator_type"] = decoratorType },
    )
  }

  /** Python async `emit_authentication_failed_event` (helpers.py:69). */
  public suspend fun emitAuthenticationFailedEvent(
      middleware: GuardMiddlewareProtocol,
      request: GuardRequest,
      eventType: String,
      reason: String,
      authType: String,
      violationType: String,
      passiveMode: Boolean,
  ) {
    val guardDecorator = getGuardDecorator(middleware, request)
    if (guardDecorator != null) {
      guardDecorator.sendAuthenticationFailedEvent(request, reason, authType)
      return
    }
    middleware.eventBus?.sendMiddlewareEvent(
        eventType,
        request,
        if (!passiveMode) "request_blocked" else "logged_only",
        reason,
        linkedMapOf(
            "decorator_type" to "authentication",
            "violation_type" to violationType,
            "auth_type" to authType,
        ),
    )
  }

  /** Python async `emit_rate_limit_event` (helpers.py:96). */
  public suspend fun emitRateLimitEvent(
      middleware: GuardMiddlewareProtocol,
      request: GuardRequest,
      eventType: String,
      limit: Int,
      window: Int,
      reason: String,
      passiveMode: Boolean,
  ) {
    val guardDecorator = getGuardDecorator(middleware, request)
    if (guardDecorator != null) {
      guardDecorator.sendRateLimitEvent(request, limit, window)
      return
    }
    middleware.eventBus?.sendMiddlewareEvent(
        eventType,
        request,
        if (!passiveMode) "request_blocked" else "logged_only",
        reason,
        linkedMapOf(
            "decorator_type" to "rate_limiting",
            "violation_type" to "rate_limit",
            "rate_limit" to limit,
            "window" to window,
        ),
    )
  }

  /** Python async `emit_decorator_event` (helpers.py:122). */
  public suspend fun emitDecoratorEvent(
      middleware: GuardMiddlewareProtocol,
      request: GuardRequest,
      eventType: String,
      actionTaken: String,
      reason: String,
      decoratorType: String,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    val guardDecorator = getGuardDecorator(middleware, request)
    if (guardDecorator != null) {
      guardDecorator.sendDecoratorEvent(
          eventType,
          request,
          actionTaken,
          reason,
          decoratorType,
          metadata,
      )
      return
    }
    middleware.eventBus?.sendMiddlewareEvent(
        eventType,
        request,
        actionTaken,
        reason,
        LinkedHashMap(metadata).also { it["decorator_type"] = decoratorType },
    )
  }

  /** Python `route_config_applies` (helpers.py:153). */
  public fun routeConfigApplies(
      routeConfigs: Collection<RouteConfig>?,
      predicate: (RouteConfig) -> Boolean,
  ): Boolean {
    if (routeConfigs == null) {
      return true
    }
    for (routeConfig in routeConfigs) {
      if (predicate(routeConfig)) {
        return true
      }
    }
    return false
  }

  /** Python `is_ip_in_blacklist` (helpers.py:165). */
  public fun isIpInBlacklist(
      clientIp: String,
      ipAddr: PyIpAddress,
      blacklist: List<String>,
  ): Boolean = AccessControl.ipInList(ipAddr, clientIp, blacklist)

  /** Python `is_ip_in_whitelist` (helpers.py:169). */
  public fun isIpInWhitelist(
      clientIp: String,
      ipAddr: PyIpAddress,
      whitelist: List<String>,
  ): Boolean? {
    if (whitelist.isEmpty()) {
      return null
    }
    return AccessControl.ipInList(ipAddr, clientIp, whitelist)
  }

  /** Python `check_country_access` (helpers.py:177). */
  public fun checkCountryAccess(
      clientIp: String,
      routeConfig: RouteConfig,
      geoIpHandler: com.guardcore.protocols.GeoIPHandler?,
  ): Boolean? {
    if (geoIpHandler == null) {
      return null
    }

    var country: String? = null

    val blocked = routeConfig.blockedCountries
    if (!blocked.isNullOrEmpty()) {
      country = geoIpHandler.getCountry(clientIp)
      if (country != null && country in blocked) {
        return false
      }
    }

    val whitelisted = routeConfig.whitelistCountries
    if (!whitelisted.isNullOrEmpty()) {
      if (country == null) {
        country = geoIpHandler.getCountry(clientIp)
      }
      return if (country != null) {
        country in whitelisted
      } else {
        false
      }
    }

    return null
  }

  /** Python `_check_ip_blacklist` (helpers.py:201). */
  private fun checkIpBlacklist(
      clientIp: String,
      ipAddr: PyIpAddress,
      routeConfig: RouteConfig,
  ): Boolean {
    val blacklist = routeConfig.ipBlacklist
    if (blacklist.isNullOrEmpty()) {
      return false
    }
    return isIpInBlacklist(clientIp, ipAddr, blacklist)
  }

  /** Python `_check_ip_whitelist` (helpers.py:209). */
  private fun checkIpWhitelist(
      clientIp: String,
      ipAddr: PyIpAddress,
      routeConfig: RouteConfig,
  ): Boolean? = isIpInWhitelist(clientIp, ipAddr, routeConfig.ipWhitelist ?: emptyList())

  /** Python `_route_whitelist_configured` (helpers.py:215). */
  private fun routeWhitelistConfigured(routeConfig: RouteConfig): Boolean =
      !routeConfig.ipWhitelist.isNullOrEmpty() || !routeConfig.whitelistCountries.isNullOrEmpty()

  /** Python async `check_route_ip_access` (helpers.py:219). */
  public suspend fun checkRouteIpAccess(
      clientIp: String,
      routeConfig: RouteConfig,
      middleware: GuardMiddlewareProtocol,
  ): Boolean? {
    if (clientIp == IpExtraction.UNKNOWN_CLIENT_IDENTITY) {
      return if (routeWhitelistConfigured(routeConfig)) false else null
    }

    return try {
      val ipAddr = pyParseAddress(clientIp)

      var ipResult = checkIpWhitelist(clientIp, ipAddr, routeConfig)
      if (ipResult == null && checkIpBlacklist(clientIp, ipAddr, routeConfig)) {
        ipResult = false
      }

      val countryResult = checkCountryAccess(clientIp, routeConfig, middleware.geoIpHandler)

      if (ipResult == false || countryResult == false) {
        return false
      }
      if (ipResult == true || countryResult == true) {
        return true
      }
      null
    } catch (e: com.guardcore.errors.ConfigValidationError) {
      // Python catches ValueError from ip_address(); ConfigValidationError is the ValueError port.
      false
    }
  }

  /** Python async `check_user_agent_allowed` (helpers.py:245). */
  public suspend fun checkUserAgentAllowed(
      userAgent: String,
      routeConfig: RouteConfig?,
      config: SecurityConfig,
  ): Boolean {
    if (routeConfig != null && routeConfig.blockedUserAgents.isNotEmpty()) {
      // _user_agent_matches_blocked_pattern (detection_scan.py:197) via the G-5 seam: the matcher
      // truncates to _MAX_USER_AGENT_MATCH_LENGTH and runs each pattern through the inline safe
      // finder.
      if (
          AccessControl.userAgentBlockedPatternMatcher?.invoke(
              userAgent,
              routeConfig.blockedUserAgents,
          ) == true
      ) {
        return false
      }
    }
    return AccessControl.isUserAgentAllowed(userAgent, config)
  }

  /** Python `extract_credential` (helpers.py:259). */
  public fun extractCredential(authHeader: String, authType: String): Pair<String?, String> {
    if (authType == "bearer") {
      if (!authHeader.startsWith("Bearer ")) {
        return null to "Missing or invalid Bearer token"
      }
      return authHeader.substring("Bearer ".length) to ""
    }
    if (authType == "basic") {
      if (!authHeader.startsWith("Basic ")) {
        return null to "Missing or invalid Basic authentication"
      }
      return authHeader.substring("Basic ".length) to ""
    }
    if (authHeader.isEmpty()) {
      return null to "Missing $authType authentication"
    }
    return authHeader to ""
  }

  /** Python `_normalize_allowed_referrer_domain` (helpers.py:273). */
  private fun normalizeAllowedReferrerDomain(entry: String): String {
    if ("://" in entry) {
      return PyUrllib.urlsplit(entry).netloc.lowercase()
    }
    val normalized = entry.lowercase()
    val slashIndex = normalized.indexOf('/')
    return if (slashIndex != -1) normalized.substring(0, slashIndex) else normalized
  }

  /** Python `is_referrer_domain_allowed` (helpers.py:281). */
  public fun isReferrerDomainAllowed(referrer: String, allowedDomains: List<String>): Boolean {
    return try {
      val referrerDomain = PyUrllib.urlsplit(referrer).netloc.lowercase()
      for (allowedDomain in allowedDomains) {
        val normalizedAllowed = normalizeAllowedReferrerDomain(allowedDomain)
        if (referrerDomain == normalizedAllowed || referrerDomain.endsWith(".$normalizedAllowed")) {
          return true
        }
      }
      false
    } catch (e: Exception) {
      false
    }
  }

  /** Python `_get_effective_penetration_setting` (helpers.py:295). */
  private fun getEffectivePenetrationSetting(
      config: SecurityConfig,
      routeConfig: RouteConfig?,
  ): Pair<Boolean, Boolean?> {
    var routeSpecificDetection: Boolean? = null
    var penetrationEnabled = config.enablePenetrationDetection

    if (routeConfig != null) {
      routeSpecificDetection = routeConfig.enableSuspiciousDetection
      penetrationEnabled = routeSpecificDetection
    }

    return penetrationEnabled to routeSpecificDetection
  }

  /** Python `_get_detection_disabled_reason` (helpers.py:308). */
  private fun getDetectionDisabledReason(
      config: SecurityConfig,
      routeSpecificDetection: Boolean?,
  ): String {
    if (routeSpecificDetection == false && config.enablePenetrationDetection) {
      return "disabled_by_decorator"
    }
    return "not_enabled"
  }

  /** Python async `detect_penetration_patterns` (helpers.py:316). */
  public suspend fun detectPenetrationPatterns(
      request: GuardRequest,
      routeConfig: RouteConfig?,
      config: SecurityConfig,
      shouldBypassCheckFn: (String, RouteConfig?) -> Boolean,
  ): DetectionResult {
    val (penetrationEnabled, routeSpecificDetection) =
        getEffectivePenetrationSetting(config, routeConfig)

    if (penetrationEnabled && !shouldBypassCheckFn("penetration", routeConfig)) {
      return com.guardcore.util.PenetrationDetection.detectPenetrationAttempt(
          request,
          config,
          routeConfig,
      )
    }

    val reason = getDetectionDisabledReason(config, routeSpecificDetection)
    return DetectionResult(isThreat = false, triggerInfo = reason)
  }

  /** Python async `get_cached_detection_result` (helpers.py:333). */
  public suspend fun getCachedDetectionResult(
      request: GuardRequest,
      routeConfig: RouteConfig?,
      config: SecurityConfig,
      shouldBypassCheckFn: (String, RouteConfig?) -> Boolean,
  ): DetectionResult {
    @Suppress("UNCHECKED_CAST")
    val cached =
        request.state.getAttr(DETECTION_RESULT_STATE_ATTR)
            as? Triple<GuardRequest, RouteConfig?, DetectionResult>
    if (cached != null && cached.first === request && cached.second === routeConfig) {
      return cached.third
    }

    val result = detectPenetrationPatterns(request, routeConfig, config, shouldBypassCheckFn)
    request.state.setAttr(DETECTION_RESULT_STATE_ATTR, Triple(request, routeConfig, result))
    return result
  }

  /** Python `_increment_suspicious_counts` (helpers.py:352). */
  public fun incrementSuspiciousCounts(
      middleware: GuardMiddlewareProtocol,
      clientIp: String,
      categories: Collection<String>,
  ) {
    synchronized(suspiciousCountsLock) {
      val counts = middleware.suspiciousRequestCounts
      val ipCounts = counts.remove(clientIp)
      val mutable =
          ipCounts
              ?: run {
                if (counts.size >= MAX_TRACKED_SUSPICIOUS_IPS) {
                  val oldestIp = counts.keys.first()
                  counts.remove(oldestIp)
                }
                mutableMapOf<String, Int>()
              }
      for (category in categories) {
        mutable[category] = (mutable[category] ?: 0) + 1
      }
      counts[clientIp] = mutable
    }
  }

  /** String-category convenience mirroring the python `str | Collection[str]` union. */
  public fun incrementSuspiciousCounts(
      middleware: GuardMiddlewareProtocol,
      clientIp: String,
      category: String,
  ) {
    incrementSuspiciousCounts(middleware, clientIp, listOf(category))
  }

  /**
   * Python async `_resolve_and_apply_threshold_ban` (helpers.py:375). Folded from the W3
   * `handlers/ThresholdBans.kt` (G-9).
   */
  public suspend fun resolveAndApplyThresholdBan(
      ipCounts: Map<String, Int>,
      config: SecurityConfig,
      ipBanManager: IpBanManager,
      clientIp: String,
      threatCategories: Collection<String>,
      reason: String,
  ): Triple<Int, String, String?>? {
    if (!config.enableIpBanning) {
      return null
    }
    for (category in threatCategories) {
      val entry = config.threatBanConfig[category] ?: continue
      val count = ipCounts[category] ?: 0
      if (count < entry.threshold) {
        continue
      }
      val banReason = "$reason:$category"
      val applied = ipBanManager.banIp(clientIp, entry.duration, banReason)
      if (!applied) {
        return null
      }
      return Triple(entry.duration, banReason, category)
    }
    val total = ipCounts.values.sum()
    if (total < config.autoBanThreshold) {
      return null
    }
    val applied = ipBanManager.banIp(clientIp, config.autoBanDuration, reason)
    if (!applied) {
      return null
    }
    return Triple(config.autoBanDuration, reason, null)
  }

  /** Python async `_try_threshold_ban` (helpers.py:414). */
  public suspend fun tryThresholdBan(
      request: GuardRequest,
      config: SecurityConfig,
      ipBanManager: IpBanManager,
      middleware: GuardMiddlewareProtocol,
      clientIp: String,
      triggerInfo: String,
      logger: Logger,
      checkName: String,
      mutedCheckLogs: Set<String>,
      threatCategories: Collection<String>,
      reason: String = "penetration_attempt",
  ): Boolean {
    val ipCounts = middleware.suspiciousRequestCounts[clientIp] ?: emptyMap()
    val result =
        resolveAndApplyThresholdBan(
            ipCounts,
            config,
            ipBanManager,
            clientIp,
            threatCategories,
            reason,
        )
    if (result == null) {
      return false
    }
    val (_, _, category) = result
    val logReason =
        if (category != null) {
          "IP banned due to $category threshold: $clientIp - $triggerInfo"
        } else {
          "IP banned due to suspicious activity: $clientIp - $triggerInfo"
        }
    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = logReason,
        level = config.logSuspiciousLevel?.pythonName,
        checkName = checkName,
        mutedCheckLogs = mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )
    return true
  }

  /** Python async `_emit_ban_escalation_failed` (helpers.py:455). */
  public suspend fun emitBanEscalationFailed(
      middleware: GuardMiddlewareProtocol,
      request: GuardRequest,
      clientIp: String,
      error: Throwable,
  ) {
    middleware.eventBus?.sendMiddlewareEvent(
        EventTypes.EVENT_IP_BAN_FAILED,
        request,
        "ban_not_applied",
        "Escalation ban failed for $clientIp: $error",
        linkedMapOf("ip_address" to clientIp),
    )
  }

  /** Python `_log_exception_safely` (helpers.py:470): logger.exception logs with the traceback. */
  private fun logExceptionSafely(logger: Logger, message: String, error: Throwable) {
    try {
      logger.log(java.util.logging.Level.SEVERE, message, error)
    } catch (e: Exception) {
      Logger.getLogger("guard_core.core.checks.helpers")
          .log(java.util.logging.Level.SEVERE, message, error)
    }
  }

  /** Python async `escalate_identity_violation` (helpers.py:477). */
  public suspend fun escalateIdentityViolation(
      middleware: GuardMiddlewareProtocol,
      config: SecurityConfig,
      ipBanManager: IpBanManager,
      request: GuardRequest,
      clientIp: String,
      logger: Logger,
      checkName: String,
      mutedCheckLogs: Set<String>,
      violationCategory: String,
      triggerInfo: String,
  ) {
    if (clientIp.isEmpty()) {
      return
    }

    if (request.state.getAttr("is_whitelisted") == true) {
      return
    }

    try {
      val routeConfig = request.state.getAttr("route_config") as? RouteConfig
      val result =
          getCachedDetectionResult(
              request,
              routeConfig,
              config,
          ) { name, rc ->
            middleware.routeResolver?.shouldBypassCheck(name, rc) ?: false
          }
      if (!result.isThreat || result.triggerInfo == "disabled_by_decorator") {
        return
      }

      val threatCategories = result.threatCategories.ifEmpty { listOf("uncategorized") }
      incrementSuspiciousCounts(middleware, clientIp, threatCategories)

      val banned =
          tryThresholdBan(
              request,
              config,
              ipBanManager,
              middleware,
              clientIp,
              triggerInfo,
              logger,
              checkName,
              mutedCheckLogs,
              threatCategories,
          )

      middleware.eventBus?.sendMiddlewareEvent(
          EventTypes.EVENT_PENETRATION_ATTEMPT,
          request,
          if (banned) "banned" else "tracked",
          "Identity violation escalated: $triggerInfo",
          linkedMapOf(
              "request_count" to (middleware.suspiciousRequestCounts[clientIp]?.values?.sum() ?: 0),
              "trigger_info" to triggerInfo,
              "violation_category" to violationCategory,
          ),
      )
    } catch (exc: Exception) {
      logExceptionSafely(logger, "escalate_identity_violation failed for $clientIp", exc)
      try {
        emitBanEscalationFailed(middleware, request, clientIp, exc)
      } catch (e: Exception) {
        logExceptionSafely(logger, "Failed to report ban escalation failure for $clientIp", e)
      }
    }
  }
}
