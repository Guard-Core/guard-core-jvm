package com.guardcore.decorators

import com.guardcore.config.ConfigValidators
import com.guardcore.config.SecurityConfig
import com.guardcore.handlers.BehaviorRule
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import java.util.logging.Logger

/**
 * Port of `guard_core/decorators/` beyond the W4a route/base slice: the per-feature decorator
 * factories as Kotlin methods carrying the SAME parameter surface 1:1.
 *
 * The python idiom is `@decorator_factory(args)` applied to a function; the factory closes over the
 * args, resolves the function's RouteConfig through `_ensure_route_config` and mutates it. The JVM
 * idiom (adapters consume this) is the same factory as a method taking the route key first:
 * `securityDecorator.requireAuth(routeKey, "bearer")`. Every factory applies the same ensure ->
 * mutate -> apply sequence over [BaseSecurityDecorator.ensureRouteConfig], with the python
 * validation and warning behavior byte-for-byte.
 *
 * File anchors: access_control.py:14 (AccessControlMixin), rate_limiting.py:9 (RateLimitingMixin),
 * behavioral.py:13 (BehavioralMixin), authentication.py:13 (AuthenticationMixin),
 * content_filtering.py:15 (ContentFilteringMixin), advanced.py:50 (AdvancedMixin), __init__.py:16
 * (SecurityDecorator).
 */
public open class SecurityDecorator(
    config: SecurityConfig,
) : BaseSecurityDecorator(config) {
  public val decoratorLogger: Logger = Logger.getLogger("guard_core.decorators")

  // -------------------------------------------------- access_control.py (AccessControlMixin)

  /** Python `require_ip` (access_control.py:16). */
  public fun requireIp(
      routeKey: Any,
      whitelist: List<String>? = null,
      blacklist: List<String>? = null,
  ) {
    val routeConfig = ensureRouteConfig(routeKey)
    if (!whitelist.isNullOrEmpty()) {
      routeConfig.ipWhitelist = whitelist
    }
    if (!blacklist.isNullOrEmpty()) {
      routeConfig.ipBlacklist = blacklist
    }
    applyRouteConfig(routeKey)
  }

  /** Python `block_countries` (access_control.py:30): upper-cased like the python list comp. */
  public fun blockCountries(routeKey: Any, countries: List<String>) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.blockedCountries = countries.map { it.uppercase() }
    applyRouteConfig(routeKey)
  }

  /** Python `allow_countries` (access_control.py:42). */
  public fun allowCountries(routeKey: Any, countries: List<String>) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.whitelistCountries = countries.map { it.uppercase() }
    applyRouteConfig(routeKey)
  }

  /**
   * Python `block_clouds` (access_control.py:54): selector validation + unknown-provider warning.
   */
  public fun blockClouds(routeKey: Any, providers: List<String>? = null) {
    val routeConfig = ensureRouteConfig(routeKey)
    if (providers == null) {
      routeConfig.blockCloudProviders =
          com.guardcore.config.CloudProviders.VALID_CLOUD_PROVIDERS.toMutableSet()
    } else {
      val valid =
          providers
              .filter {
                it.substringBefore(":!") in
                    com.guardcore.config.CloudProviders.VALID_CLOUD_PROVIDERS
              }
              .toSet()
      routeConfig.blockCloudProviders = valid.toMutableSet()
      val invalid = providers.toSet() - valid
      if (invalid.isNotEmpty()) {
        decoratorLogger.warning(
            "@block_clouds: ignored unknown cloud providers ${invalid.toSortedSet()}",
        )
      }
    }
    applyRouteConfig(routeKey)
  }

  /** Python `bypass` (access_control.py:71): VALID_BYPASS_CHECKS filtering + warning. */
  public fun bypass(routeKey: Any, checks: List<String>) {
    val routeConfig = ensureRouteConfig(routeKey)
    val valid =
        com.guardcore.config.ConfigFieldRegistry.VALID_BYPASS_CHECKS.filter { it in checks }.toSet()
    routeConfig.bypassedChecks.addAll(valid)
    val invalid = checks.toSet() - valid
    if (invalid.isNotEmpty()) {
      decoratorLogger.warning("@bypass: ignored unknown checks ${invalid.toSortedSet()}")
    }
    applyRouteConfig(routeKey)
  }

  // -------------------------------------------------- rate_limiting.py (RateLimitingMixin)

  /** Python `rate_limit` (rate_limiting.py:11). */
  public fun rateLimit(
      routeKey: Any,
      requests: Int,
      window: Int = 60,
  ) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.rateLimit = requests
    routeConfig.rateLimitWindow = window
    applyRouteConfig(routeKey)
  }

  /** Python `geo_rate_limit` (rate_limiting.py:20). */
  public fun geoRateLimit(routeKey: Any, limits: Map<String, Pair<Int, Int>>) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.geoRateLimits = limits
    applyRouteConfig(routeKey)
  }

  // -------------------------------------------------- behavioral.py (BehavioralMixin)

  /** Python `usage_monitor` (behavioral.py:18). */
  public fun usageMonitor(
      routeKey: Any,
      maxCalls: Int,
      window: Int = 3600,
      action: String = "ban",
  ) {
    val routeConfig = ensureRouteConfig(routeKey)
    val rule =
        BehaviorRule(
            ruleType = "usage",
            threshold = maxCalls,
            window = window,
            action = action,
        )
    routeConfig.behaviorRules.add(rule)
    applyRouteConfig(routeKey)
  }

  /** Python `return_monitor` (behavioral.py:34): validated like the python factory. */
  public fun returnMonitor(
      routeKey: Any,
      pattern: String,
      maxOccurrences: Int,
      window: Int = 86400,
      action: String = "ban",
  ) {
    ConfigValidators.validateReturnPatternBodyScan(pattern, config)
    val routeConfig = ensureRouteConfig(routeKey)
    val rule =
        BehaviorRule(
            ruleType = "return_pattern",
            threshold = maxOccurrences,
            window = window,
            pattern = pattern,
            action = action,
        )
    routeConfig.behaviorRules.add(rule)
    applyRouteConfig(routeKey)
  }

  /** Python `behavior_analysis` (behavioral.py:52). */
  public fun behaviorAnalysis(routeKey: Any, rules: List<BehaviorRule>) {
    for (rule in rules) {
      if (rule.ruleType == "return_pattern" && rule.pattern != null) {
        ConfigValidators.validateReturnPatternBodyScan(rule.pattern!!, config)
      }
    }
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.behaviorRules.addAll(rules)
    applyRouteConfig(routeKey)
  }

  /** Python `suspicious_frequency` (behavioral.py:70): frequency -> threshold conversion. */
  public fun suspiciousFrequency(
      routeKey: Any,
      maxFrequency: Double,
      window: Int = 300,
      action: String = "ban",
  ) {
    val routeConfig = ensureRouteConfig(routeKey)
    val maxCalls = (maxFrequency * window).toInt()
    val rule =
        BehaviorRule(
            ruleType = "frequency",
            threshold = maxCalls,
            window = window,
            action = action,
        )
    routeConfig.behaviorRules.add(rule)
    applyRouteConfig(routeKey)
  }

  // -------------------------------------------------- authentication.py (AuthenticationMixin)

  /** Python `require_https` (authentication.py:15). */
  public fun requireHttps(routeKey: Any) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.requireHttps = true
    applyRouteConfig(routeKey)
  }

  /** Python `require_auth` (authentication.py:22): mutually exclusive with the header check. */
  public fun requireAuth(
      routeKey: Any,
      type: String = "bearer",
      verifier: RouteAuthVerifier? = null,
  ) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.authRequired = type
    routeConfig.authVerifier = verifier
    if (routeConfig.authorizationHeaderRequired != null) {
      throw IllegalArgumentException(
          "require_auth cannot be combined with require_authorization_header;" +
              " the latter is presence-only and mutually exclusive with" +
              " authenticated routes",
      )
    }
    applyRouteConfig(routeKey)
  }

  /** Python `api_key_auth` (authentication.py:44). */
  public fun apiKeyAuth(
      routeKey: Any,
      headerName: String = "X-API-Key",
      verifier: RouteAuthVerifier? = null,
  ) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.apiKeyRequired = true
    routeConfig.requiredHeaders[headerName] = "required"
    routeConfig.apiKeyHeader = headerName
    routeConfig.apiKeyVerifier = verifier
    if (routeConfig.authorizationHeaderRequired != null) {
      throw IllegalArgumentException(
          "api_key_auth cannot be combined with require_authorization_header;" +
              " the latter is presence-only and mutually exclusive with" +
              " authenticated routes",
      )
    }
    applyRouteConfig(routeKey)
  }

  /** Python `require_authorization_header` (authentication.py:68): presence-only check. */
  public fun requireAuthorizationHeader(routeKey: Any, scheme: String = "bearer") {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.authorizationHeaderRequired = scheme
    if (routeConfig.authRequired != null || routeConfig.apiKeyRequired) {
      throw IllegalArgumentException(
          "require_authorization_header cannot be combined with" +
              " require_auth or api_key_auth; it is presence-only and" +
              " mutually exclusive with authenticated routes",
      )
    }
    applyRouteConfig(routeKey)
  }

  /** Python `require_headers` (authentication.py:82). */
  public fun requireHeaders(routeKey: Any, headers: Map<String, String>) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.requiredHeaders.putAll(headers)
    applyRouteConfig(routeKey)
  }

  // -------------------------------------------------- content_filtering.py (ContentFilteringMixin)

  /**
   * Python `block_user_agents` (content_filtering.py:17): every pattern passes the ReDoS validator
   * BEFORE the route mutation, exactly like the python factory raising ValueError.
   */
  public fun blockUserAgents(routeKey: Any, patterns: List<String>) {
    val compiler = com.guardcore.engine.detection.PatternCompiler()
    for (pattern in patterns) {
      val (isSafe, reason) =
          compiler.validatePatternSafety(
              pattern,
              maxContentLength = config.detectionMaxBodyInspectBytes,
          )
      if (!isSafe) {
        val redacted = com.guardcore.handlers.DetectionScanRedaction.redactPatternSource(pattern)
        throw IllegalArgumentException(
            "block_user_agents pattern rejected by ReDoS validator: '$redacted' ($reason)",
        )
      }
    }
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.blockedUserAgents.addAll(patterns)
    applyRouteConfig(routeKey)
  }

  /** Python `content_type_filter` (content_filtering.py:40). */
  public fun contentTypeFilter(routeKey: Any, allowedTypes: List<String>) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.allowedContentTypes = allowedTypes
    applyRouteConfig(routeKey)
  }

  /** Python `max_request_size` (content_filtering.py:50). */
  public fun maxRequestSize(routeKey: Any, sizeBytes: Int) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.maxRequestSize = sizeBytes
    applyRouteConfig(routeKey)
  }

  /** Python `require_referrer` (content_filtering.py:60). */
  public fun requireReferrer(routeKey: Any, allowedDomains: List<String>) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.requireReferrer = allowedDomains
    applyRouteConfig(routeKey)
  }

  /** Python `custom_validation` (content_filtering.py:70). */
  public fun customValidation(
      routeKey: Any,
      validator: suspend (GuardRequest) -> Any?,
  ) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.customValidators.add(validator)
    applyRouteConfig(routeKey)
  }

  /** Python `detection_exclusion` (content_filtering.py:79). */
  public fun detectionExclusion(
      routeKey: Any,
      headers: Set<String>? = null,
      params: Set<String>? = null,
      bodyFields: Set<String>? = null,
      categories: Set<String>? = null,
      scanBody: Boolean? = null,
  ) {
    val routeConfig = ensureRouteConfig(routeKey)
    if (headers != null) {
      routeConfig.excludedDetectionHeaders = headers
    }
    if (params != null) {
      routeConfig.excludedDetectionParams = params
    }
    if (bodyFields != null) {
      routeConfig.excludedDetectionBodyFields = bodyFields
    }
    if (categories != null) {
      routeConfig.enabledDetectionCategories = categories
    }
    if (scanBody != null) {
      routeConfig.detectionScanBody = scanBody
    }
    applyRouteConfig(routeKey)
  }

  // -------------------------------------------------- advanced.py (AdvancedMixin)

  /** Python `time_window` (advanced.py:52). */
  public fun timeWindow(
      routeKey: Any,
      startTime: String,
      endTime: String,
      timezone: String = "UTC",
  ) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.timeRestrictions =
        mapOf(
            "start" to startTime,
            "end" to endTime,
            "timezone" to timezone,
        )
    applyRouteConfig(routeKey)
  }

  /** Python `suspicious_detection` (advanced.py:64). */
  public fun suspiciousDetection(routeKey: Any, enabled: Boolean = true) {
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.enableSuspiciousDetection = enabled
    applyRouteConfig(routeKey)
  }

  /**
   * Python `honeypot_detection` (advanced.py:72): appends the honeypot validator closure over the
   * trap fields; form and JSON bodies with a filled trap field reject with 403.
   */
  public fun honeypotDetection(routeKey: Any, trapFields: List<String>) {
    val honeypotValidator: suspend (GuardRequest) -> Any? =
        honeypotValidatorClosure(trapFields, config)
    val routeConfig = ensureRouteConfig(routeKey)
    routeConfig.customValidators.add(honeypotValidator)
    applyRouteConfig(routeKey)
  }
}

/**
 * Port of the `honeypot_validator` closure (advanced.py:75-122) and `_SimpleResponse`
 * (advanced.py:22): reads the capped body, parses form/JSON payloads, rejects filled trap fields.
 */
internal fun honeypotValidatorClosure(
    trapFields: List<String>,
    config: SecurityConfig,
): suspend (GuardRequest) -> Any? {
  fun hasTrapFieldFilled(data: Map<String, Any?>): Boolean = trapFields.any { field ->
    val value = data[field]
    value != null && value.toString().isNotEmpty()
  }

  fun forbidden(): GuardResponse = SimpleDecoratorResponse(403, "Forbidden")

  fun validateFormData(rawBody: ByteArray): GuardResponse? {
    val parsed = com.guardcore.util.py.PyUrllib.parseQs(rawBody.decodeToString())
    val flat = parsed.mapValues { (_, v) -> v.firstOrNull() }.filterValues { it != null }
    return if (hasTrapFieldFilled(flat)) forbidden() else null
  }

  fun validateJsonData(rawBody: ByteArray): GuardResponse? {
    try {
      val jsonData = com.guardcore.util.py.PyJson.loads(rawBody.decodeToString())
      @Suppress("UNCHECKED_CAST")
      if (jsonData is Map<*, *> && hasTrapFieldFilled(jsonData as Map<String, Any?>)) {
        return forbidden()
      }
    } catch (e: Exception) {
      // advanced.py:97: unparsable JSON bodies are skipped.
    }
    return null
  }

  return { request: GuardRequest ->
    if (request.method !in listOf("POST", "PUT", "PATCH")) {
      null
    } else {
      val rawBody = com.guardcore.util.BodyReader.readCappedBody(request, config)
      when {
        rawBody == null -> null
        "application/x-www-form-urlencoded" in (request.headers["content-type"] ?: "") ->
            validateFormData(rawBody)
        "application/json" in (request.headers["content-type"] ?: "") -> validateJsonData(rawBody)
        else -> null
      }
    }
  }
}

/** Port of `_SimpleResponse` (advanced.py:22). */
public class SimpleDecoratorResponse(
    statusCode: Int,
    content: String,
) : GuardResponse {
  private val bodyBytes: ByteArray = content.encodeToByteArray()
  override val headers: MutableMap<String, String> = linkedMapOf()
  override val statusCode: Int = statusCode
  override val body: ByteArray
    get() = bodyBytes
}
