package com.guardcore.util

import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardRequest
import com.guardcore.util.py.IpNetwork
import com.guardcore.util.py.parseAddress

/**
 * Port of `guard_core/_utils/access_control.py` (access_control.py:1-299): user-agent allowance,
 * country verdicts and the IP access decision.
 *
 * Two seams depend on later waves and are registered by their owners:
 * - `userAgentBlockedPatternMatcher`: the W2 detection engine's
 *   `_user_agent_matches_blocked_pattern` (access_control.py:16).
 * - `cloudIpChecker`: the W3 cloud handler's `is_cloud_ip` / `get_cloud_provider_details`
 *   (access_control.py:197-215).
 */
public object AccessControl {
  /** Seam for the W2 user-agent pattern matcher: true when the UA matches a blocked pattern. */
  @Volatile
  public var userAgentBlockedPatternMatcher:
      (suspend (userAgent: String, blockedUserAgents: List<String>) -> Boolean)? =
      null

  /** Seam result for the W3 cloud-provider check. */
  public class CloudProviderDetails(
      public val provider: String,
      public val network: String,
  )

  /** Seam for the W3 cloud handler: details when the IP belongs to a blocked provider. */
  @Volatile
  public var cloudIpChecker: ((ip: String, providers: Set<String>) -> CloudProviderDetails?)? = null

  /** Port of `is_user_agent_allowed` (access_control.py:15). */
  public suspend fun isUserAgentAllowed(
      userAgent: String,
      config: com.guardcore.config.SecurityConfig,
  ): Boolean {
    val matcher = userAgentBlockedPatternMatcher ?: return true
    return !matcher(userAgent, config.blockedUserAgents)
  }

  /** Port of `_extract_ip_from_request` (access_control.py:22). */
  internal fun extractIpFromRequest(request: Any): String =
      when (request) {
        is String -> request
        is GuardRequest ->
            if (request.clientHost != null) {
              IpExtraction.canonicalizeIp(request.clientHost!!)
            } else {
              IpExtraction.UNKNOWN_CLIENT_IDENTITY
            }
        else -> IpExtraction.UNKNOWN_CLIENT_IDENTITY
      }

  /** Port of `_has_country_rules` (access_control.py:32). */
  internal fun hasCountryRules(config: com.guardcore.config.SecurityConfig): Boolean =
      config.blockedCountries.isNotEmpty() || config.whitelistCountries.isNotEmpty()

  /** Port of `_is_loopback` (access_control.py:36). */
  internal fun isLoopback(ip: String): Boolean =
      try {
        parseAddress(ip).isLoopback
      } catch (_: com.guardcore.errors.ConfigValidationError) {
        false
      }

  /** Port of `_log_country_check_result` (access_control.py:43). */
  private fun logCountryCheckResult(
      ip: String,
      country: String?,
      resultType: String,
      config: com.guardcore.config.SecurityConfig,
  ) {
    val logger = DetectionScanContext.guardLogger
    when (resultType) {
      "no_rules" ->
          logger.fine(
              "No countries blocked or whitelisted $ip - No countries blocked or whitelisted",
          )
      "no_geolocation" -> logger.fine("IP not geolocated $ip - IP geolocation failed")
      "loopback_exempt" -> logger.fine("Loopback IP exempt from country allowlist check $ip")
      "blocked" -> {
        val level = config.logSuspiciousLevel
        if (level == null) return
        LoggingUtils.logAtLevel(
            logger,
            level.pythonName,
            "IP from blocked country $ip - $country - IP from blocked country",
        )
      }
      "whitelisted",
      "not_affected" -> {
        val level = config.logCountryCheckLevel
        if (level == null) return
        if (resultType == "whitelisted") {
          LoggingUtils.logAtLevel(
              logger,
              level.pythonName,
              "IP from whitelisted country $ip - $country - IP from whitelisted country",
          )
        } else {
          LoggingUtils.logAtLevel(
              logger,
              level.pythonName,
              "IP not from blocked or whitelisted country $ip - $country - " +
                  "IP not from blocked or whitelisted country",
          )
        }
      }
    }
  }

  /** Port of `_evaluate_country_access` (access_control.py:84). */
  internal fun evaluateCountryAccess(
      country: String,
      config: com.guardcore.config.SecurityConfig,
  ): Pair<Boolean, String> =
      if (config.whitelistCountries.isNotEmpty()) {
        if (country in config.whitelistCountries) false to "whitelisted" else true to "blocked"
      } else {
        if (config.blockedCountries.isNotEmpty() && country in config.blockedCountries) {
          true to "blocked"
        } else {
          false to "not_affected"
        }
      }

  /** Port of `_resolve_country_verdict` (access_control.py:96-119). */
  internal suspend fun resolveCountryVerdict(
      ip: String,
      config: com.guardcore.config.SecurityConfig,
      geoIpHandler: GeoIPHandler,
  ): Pair<Boolean, String?> {
    if (!hasCountryRules(config)) {
      logCountryCheckResult(ip, null, "no_rules", config)
      return false to null
    }
    if (isLoopback(ip)) {
      logCountryCheckResult(ip, null, "loopback_exempt", config)
      return false to null
    }
    if (!geoIpHandler.isInitialized) {
      geoIpHandler.initialize()
    }
    val country = geoIpHandler.getCountry(ip)
    if (country == null) {
      logCountryCheckResult(ip, null, "no_geolocation", config)
      return config.whitelistCountries.isNotEmpty() to null
    }
    val (isBlocked, resultType) = evaluateCountryAccess(country, config)
    logCountryCheckResult(ip, country, resultType, config)
    return isBlocked to country
  }

  /** Port of `check_ip_country` (access_control.py:122). */
  public suspend fun checkIpCountry(
      request: Any,
      config: com.guardcore.config.SecurityConfig,
      geoIpHandler: GeoIPHandler,
  ): Boolean {
    val ip = extractIpFromRequest(request)
    val (isBlocked, _) = resolveCountryVerdict(ip, config, geoIpHandler)
    return isBlocked
  }

  /** Port of `_ip_in_list` (access_control.py:132). */
  internal fun ipInList(
      ipAddr: com.guardcore.util.py.IpAddress,
      ip: String,
      entries: List<String>?,
  ): Boolean {
    if (entries.isNullOrEmpty()) return false
    val canonicalIp = IpExtraction.canonicalizeIp(ip)
    for (entry in entries) {
      if ("/" in entry) {
        if (IpNetwork.parse(entry).contains(ipAddr)) return true
      } else if (canonicalIp == IpExtraction.canonicalizeIp(entry)) {
        return true
      }
    }
    return false
  }

  /** Port of `_check_blacklist` (access_control.py:145). */
  private fun checkBlacklist(
      ipAddr: com.guardcore.util.py.IpAddress,
      ip: String,
      config: com.guardcore.config.SecurityConfig,
  ): Boolean = !ipInList(ipAddr, ip, config.blacklist)

  /** Port of `_check_whitelist` (access_control.py:149). */
  private fun checkWhitelist(
      ipAddr: com.guardcore.util.py.IpAddress,
      ip: String,
      config: com.guardcore.config.SecurityConfig,
  ): Boolean = if (config.whitelist != null) ipInList(ipAddr, ip, config.whitelist) else true

  /** Port of `IpAccessResult` (access_control.py:165-170). */
  public class IpAccessResult(
      public val allowed: Boolean,
      public val reason: String,
      public val cloudProvider: String? = null,
      public val network: String? = null,
  )

  private const val GENERIC_LIST_BLOCK_REASON = "IP {ip} not in global allowlist/blocklist"

  private fun genericListBlockReason(ip: String): String =
      GENERIC_LIST_BLOCK_REASON.replace("{ip}", ip)

  /** Port of `_check_blocked_countries_detail` (access_control.py:176). */
  private suspend fun checkBlockedCountriesDetail(
      ip: String,
      config: com.guardcore.config.SecurityConfig,
      geoIpHandler: GeoIPHandler?,
  ): IpAccessResult? {
    if (
        (config.blockedCountries.isEmpty() && config.whitelistCountries.isEmpty()) ||
            geoIpHandler == null
    ) {
      return null
    }
    val (isBlocked, country) = resolveCountryVerdict(ip, config, geoIpHandler)
    if (!isBlocked) return null
    val reason =
        if (country != null) {
          "IP from blocked country: $country"
        } else {
          genericListBlockReason(ip)
        }
    return IpAccessResult(false, reason)
  }

  /** Port of `_check_cloud_providers_detail` (access_control.py:197). */
  private fun checkCloudProvidersDetail(
      ip: String,
      config: com.guardcore.config.SecurityConfig,
  ): IpAccessResult? {
    if (config.blockCloudProviders.isNullOrEmpty()) return null
    val checker = cloudIpChecker ?: return null
    val providers = config.blockCloudProviders!!
    val details = checker(ip, providers) ?: return null
    return IpAccessResult(
        false,
        "IP belongs to blocked cloud provider: ${details.provider}",
        cloudProvider = details.provider,
        network = details.network,
    )
  }

  /** Port of `_check_unknown_identity_access` (access_control.py:218). */
  private fun checkUnknownIdentityAccess(
      ip: String,
      config: com.guardcore.config.SecurityConfig,
      skipIpLists: Boolean,
      skipCountries: Boolean,
  ): IpAccessResult? {
    if (ip != IpExtraction.UNKNOWN_CLIENT_IDENTITY) return null
    val whitelistBlocks = !skipIpLists && config.whitelist != null
    val countryWhitelistBlocks = !skipCountries && config.whitelistCountries.isNotEmpty()
    return if (whitelistBlocks || countryWhitelistBlocks) {
      IpAccessResult(false, genericListBlockReason(ip))
    } else {
      IpAccessResult(true, "")
    }
  }

  /** Port of `_check_ip_lists_detail` (access_control.py:230). */
  private fun checkIpListsDetail(
      ipAddr: com.guardcore.util.py.IpAddress,
      ip: String,
      config: com.guardcore.config.SecurityConfig,
  ): IpAccessResult? =
      if (config.whitelist != null) {
        if (!checkWhitelist(ipAddr, ip, config)) IpAccessResult(false, genericListBlockReason(ip))
        else null
      } else {
        if (!checkBlacklist(ipAddr, ip, config)) IpAccessResult(false, genericListBlockReason(ip))
        else null
      }

  /** Port of `check_ip_access` (access_control.py:241-281). */
  public suspend fun checkIpAccess(
      ip: String,
      config: com.guardcore.config.SecurityConfig,
      geoIpHandler: GeoIPHandler? = null,
      skipIpLists: Boolean = false,
      skipCountries: Boolean = false,
  ): IpAccessResult {
    var skipCountriesLocal = skipCountries
    val unknownResult = checkUnknownIdentityAccess(ip, config, skipIpLists, skipCountries)
    if (unknownResult != null) return unknownResult
    return try {
      val ipAddr = parseAddress(ip)
      if (!skipIpLists) {
        val listResult = checkIpListsDetail(ipAddr, ip, config)
        if (listResult != null) return listResult
        if (ipInList(ipAddr, ip, config.whitelist)) {
          skipCountriesLocal = true
        }
      }
      if (!skipCountriesLocal) {
        val countryResult = checkBlockedCountriesDetail(ip, config, geoIpHandler)
        if (countryResult != null) return countryResult
      }
      val cloudResult = checkCloudProvidersDetail(ip, config)
      if (cloudResult != null) return cloudResult
      IpAccessResult(true, "")
    } catch (_: com.guardcore.errors.ConfigValidationError) {
      IpAccessResult(false, genericListBlockReason(ip))
    } catch (e: Exception) {
      DetectionScanContext.guardLogger.severe("Error checking IP $ip: $e")
      IpAccessResult(true, "")
    }
  }

  /** Port of `is_ip_allowed` (access_control.py:284-299). */
  public suspend fun isIpAllowed(
      ip: String,
      config: com.guardcore.config.SecurityConfig,
      geoIpHandler: GeoIPHandler? = null,
      skipIpLists: Boolean = false,
      skipCountries: Boolean = false,
  ): Boolean = checkIpAccess(ip, config, geoIpHandler, skipIpLists, skipCountries).allowed
}
