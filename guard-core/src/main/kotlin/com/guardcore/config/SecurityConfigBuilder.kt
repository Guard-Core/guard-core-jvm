package com.guardcore.config

import com.guardcore.errors.ConfigValidationError
import com.guardcore.util.py.PyDiffLib
import java.util.logging.Logger

/**
 * Builder and map-construction surface for [SecurityConfig].
 *
 * `applyTo` runs the pydantic field-validation pass in python field order (bounds + field
 * validators, guard_core/_security_config_fields.py:22 through guard_core/models.py:315);
 * `SecurityConfig.runModelValidators` then runs the model validators in declaration order
 * (guard_core/models.py:182-275).
 *
 * `fromMap` is the port of the Python kwargs constructor including the unknown-field warning with
 * the difflib "Did you mean" hint (guard_core/models.py:133-152).
 */
public class SecurityConfigBuilder {
  private val logger: Logger = Logger.getLogger("guard_core.models")

  internal var validateFields: Boolean = true

  // Builder inputs: null means "not provided, use the python default".
  public var trustedProxies: List<String>? = null
  public var trustedProxyDepth: Int? = null
  public var trustXForwardedProto: Boolean? = null
  public var passiveMode: Boolean? = null
  internal var geoIpHandlerProvided: Boolean = false

  public var geoIpHandler: com.guardcore.protocols.GeoIPHandler? = null
    set(value) {
      field = value
      geoIpHandlerProvided = true
    }

  public var enableRedis: Boolean? = null
  internal var redisUrlProvided: Boolean = false

  public var redisUrl: String? = null
    set(value) {
      field = value
      redisUrlProvided = true
    }

  public var redisPrefix: String? = null
  internal var redisSocketConnectTimeoutProvided: Boolean = false

  public var redisSocketConnectTimeout: Double? = null
    set(value) {
      field = value
      redisSocketConnectTimeoutProvided = true
    }

  internal var redisSocketTimeoutProvided: Boolean = false

  public var redisSocketTimeout: Double? = null
    set(value) {
      field = value
      redisSocketTimeoutProvided = true
    }

  public var redisHealthCheckInterval: Int? = null
  internal var redisMaxConnectionsProvided: Boolean = false

  public var redisMaxConnections: Int? = null
    set(value) {
      field = value
      redisMaxConnectionsProvided = true
    }

  public var redisRetries: Int? = null
  internal var whitelistProvided: Boolean = false

  public var whitelist: List<String>? = null
    set(value) {
      field = value
      whitelistProvided = true
    }

  public var blacklist: List<String>? = null
  public var exemptIps: List<String>? = null
  public var whitelistCountries: Set<String>? = null
  public var blockedCountries: Set<String>? = null
  public var blockedUserAgents: List<String>? = null
  public var autoBanThreshold: Int? = null
  public var autoBanDuration: Int? = null
  public var threatBanConfig: Map<String, ThreatBanConfig>? = null
  public var enableRateLimitAutoBan: Boolean? = null
  public var globalBehaviorRules: List<BehaviorRuleConfig>? = null
  public var behaviorScanResponseBody: Boolean? = null
  public var behaviorMaxResponseBodyInspectBytes: Int? = null
  public var bodyReadTimeout: Double? = null
  public var syncBodyReadMaxConcurrent: Int? = null
  internal var customLogFileProvided: Boolean = false

  public var customLogFile: String? = null
    set(value) {
      field = value
      customLogFileProvided = true
    }

  internal var logSuspiciousLevelProvided: Boolean = false

  public var logSuspiciousLevel: LogLevel? = null
    set(value) {
      field = value
      logSuspiciousLevelProvided = true
    }

  internal var logRequestLevelProvided: Boolean = false

  public var logRequestLevel: LogLevel? = null
    set(value) {
      field = value
      logRequestLevelProvided = true
    }

  internal var logCountryCheckLevelProvided: Boolean = false

  public var logCountryCheckLevel: LogLevel? = null
    set(value) {
      field = value
      logCountryCheckLevelProvided = true
    }

  public var logFormat: LogFormat? = null
  public var customErrorResponses: Map<Int, String>? = null
  public var rateLimit: Int? = null
  public var rateLimitWindow: Int? = null
  public var enforceHttps: Boolean? = null
  internal var securityHeadersProvided: Boolean = false

  public var securityHeaders: Map<String, Any?>? = null
    set(value) {
      field = value
      securityHeadersProvided = true
    }

  public var customRequestCheck: CustomRequestCheck? = null
  public var authVerifier: AuthVerifier? = null
  public var customResponseModifier: CustomResponseModifier? = null
  public var enableCors: Boolean? = null
  public var corsAllowOrigins: List<String>? = null
  public var corsAllowMethods: List<String>? = null
  public var corsAllowHeaders: List<String>? = null
  public var corsAllowCredentials: Boolean? = null
  public var corsExposeHeaders: List<String>? = null
  public var corsMaxAge: Int? = null
  internal var blockCloudProvidersProvided: Boolean = false

  public var blockCloudProviders: Set<String>? = null
    set(value) {
      field = value
      blockCloudProvidersProvided = true
    }

  public var cloudIpRefreshInterval: Int? = null
  public var lazyInit: Boolean? = null
  public var geoIpDbMaxAge: Int? = null
  internal var cloudIpStoreProvided: Boolean = false

  public var cloudIpStore: Any? = null
    set(value) {
      field = value
      cloudIpStoreProvided = true
    }

  public var excludePaths: List<String>? = null
  public var enableIpBanning: Boolean? = null
  public var enableRateLimiting: Boolean? = null
  public var enablePenetrationDetection: Boolean? = null
  public var failSecure: Boolean? = null
  public var redisFailOpen: Boolean? = null
  public var routeResolutionStrict: Boolean? = null
  internal var ipinfoTokenProvided: Boolean = false

  public var ipinfoToken: String? = null
    set(value) {
      field = value
      ipinfoTokenProvided = true
    }

  internal var ipinfoDbPathProvided: Boolean = false

  public var ipinfoDbPath: java.nio.file.Path? = null
    set(value) {
      field = value
      ipinfoDbPathProvided = true
    }

  public var enableAgent: Boolean? = null
  internal var agentApiKeyProvided: Boolean = false

  public var agentApiKey: String? = null
    set(value) {
      field = value
      agentApiKeyProvided = true
    }

  public var agentStrict: Boolean? = null
  public var onError: OnErrorHook? = null
  public var onBlock: BlockHook? = null
  public var agentEndpoint: String? = null
  internal var agentProjectIdProvided: Boolean = false

  public var agentProjectId: String? = null
    set(value) {
      field = value
      agentProjectIdProvided = true
    }

  public var agentBufferSize: Int? = null
  public var agentFlushInterval: Int? = null
  public var agentEnableEvents: Boolean? = null
  public var agentEnableMetrics: Boolean? = null
  public var agentTimeout: Int? = null
  public var agentRetryAttempts: Int? = null
  internal var agentProjectEncryptionKeyProvided: Boolean = false

  public var agentProjectEncryptionKey: String? = null
    set(value) {
      field = value
      agentProjectEncryptionKeyProvided = true
    }

  internal var agentGuardVersionProvided: Boolean = false

  public var agentGuardVersion: String? = null
    set(value) {
      field = value
      agentGuardVersionProvided = true
    }

  internal var agentHighWatermarkRatioProvided: Boolean = false

  public var agentHighWatermarkRatio: Double? = null
    set(value) {
      field = value
      agentHighWatermarkRatioProvided = true
    }

  internal var agentMaxConcurrentFlushesProvided: Boolean = false

  public var agentMaxConcurrentFlushes: Int? = null
    set(value) {
      field = value
      agentMaxConcurrentFlushesProvided = true
    }

  internal var agentBufferOverflowPolicyProvided: Boolean = false

  public var agentBufferOverflowPolicy: BufferOverflowPolicy? = null
    set(value) {
      field = value
      agentBufferOverflowPolicyProvided = true
    }

  internal var agentBackoffFactorProvided: Boolean = false

  public var agentBackoffFactor: Double? = null
    set(value) {
      field = value
      agentBackoffFactorProvided = true
    }

  internal var agentSensitiveHeadersProvided: Boolean = false

  public var agentSensitiveHeaders: List<String>? = null
    set(value) {
      field = value
      agentSensitiveHeadersProvided = true
    }

  internal var agentMaxPayloadSizeProvided: Boolean = false

  public var agentMaxPayloadSize: Int? = null
    set(value) {
      field = value
      agentMaxPayloadSizeProvided = true
    }

  internal var agentCompressionEnabledProvided: Boolean = false

  public var agentCompressionEnabled: Boolean? = null
    set(value) {
      field = value
      agentCompressionEnabledProvided = true
    }

  internal var agentCompressionThresholdProvided: Boolean = false

  public var agentCompressionThreshold: Int? = null
    set(value) {
      field = value
      agentCompressionThresholdProvided = true
    }

  internal var agentInstallIdProvided: Boolean = false

  public var agentInstallId: String? = null
    set(value) {
      field = value
      agentInstallIdProvided = true
    }

  internal var agentPayloadSigningSecretProvided: Boolean = false

  public var agentPayloadSigningSecret: String? = null
    set(value) {
      field = value
      agentPayloadSigningSecretProvided = true
    }

  public var enableDynamicRules: Boolean? = null
  public var dynamicRuleInterval: Int? = null
  internal var dynamicRulesCachePathProvided: Boolean = false

  public var dynamicRulesCachePath: java.nio.file.Path? = null
    set(value) {
      field = value
      dynamicRulesCachePathProvided = true
    }

  /** Raw fromMap value; lets the ported validator emit the python message. */
  public var dynamicRulesCachePathRaw: Any? = null
  public var agentStatusInterval: Int? = null
  public var emergencyMode: Boolean? = null
  public var emergencyWhitelist: List<String>? = null
  public var endpointRateLimits: Map<String, Pair<Int, Int>>? = null
  public var detectionCompilerTimeout: Double? = null
  internal var detectionPatternValidationCachePathProvided: Boolean = false

  public var detectionPatternValidationCachePath: String? = null
    set(value) {
      field = value
      detectionPatternValidationCachePathProvided = true
    }

  public var detectionMaxContentLength: Int? = null
  public var detectionMaxBodyInspectBytes: Int? = null
  public var detectionMaxScanValues: Int? = null
  public var detectionMaxScanChars: Int? = null
  public var detectionMaxJsonDepth: Int? = null
  public var detectionBinaryMinRunLength: Int? = null
  public var detectionPreserveAttackPatterns: Boolean? = null
  public var detectionSemanticThreshold: Double? = null
  public var detectionAnomalyThreshold: Double? = null
  public var detectionSlowPatternThreshold: Double? = null
  public var detectionMonitorHistorySize: Int? = null
  public var detectionMaxTrackedPatterns: Int? = null
  public var detectionAnomalyEmissionCooldown: Double? = null
  public var detectionMinSamplesForAnomaly: Int? = null
  public var detectionThreatScoreThreshold: Double? = null
  public var mutedEventTypes: Set<String>? = null
  public var mutedMetricTypes: Set<String>? = null
  public var mutedCheckLogs: Set<String>? = null
  public var logSensitiveHeaders: Set<String>? = null

  /** Raw fromMap value; lets the ported validator emit the python message. */
  public var logSensitiveHeadersRaw: Any? = null
  public var logSensitiveParams: Set<String>? = null
  public var logSensitiveParamsRaw: Any? = null
  public var logSensitiveBodyFields: Set<String>? = null
  public var logSensitiveBodyFieldsRaw: Any? = null
  public var enableOtel: Boolean? = null
  public var otelServiceName: String? = null
  internal var otelExporterEndpointProvided: Boolean = false

  public var otelExporterEndpoint: String? = null
    set(value) {
      field = value
      otelExporterEndpointProvided = true
    }

  public var otelResourceAttributes: Map<String, String>? = null
  public var enableLogfire: Boolean? = null
  public var logfireServiceName: String? = null
  public var enableEnrichment: Boolean? = null
  public var excludedDetectionHeaders: Set<String>? = null
  public var excludedSemanticDetectionHeaders: Set<String>? = null
  public var excludedDetectionParams: Set<String>? = null
  public var excludedDetectionBodyFields: Set<String>? = null
  public var detectionScanBody: Boolean? = null
  public var enabledDetectionCategories: Set<String>? = null

  /** Build a fully validated config (python kwargs-construction parity). */
  public fun build(): SecurityConfig = SecurityConfig(this, forCopy = false)

  /** Build without field validation (python model_copy parity). */
  internal fun buildInternal(skipBounds: Boolean): SecurityConfig {
    val previous = validateFields
    validateFields = !skipBounds
    try {
      return SecurityConfig(this, forCopy = true)
    } finally {
      validateFields = previous
    }
  }

  /**
   * The pydantic field-validation pass: bounds then field validators, in python field declaration
   * order, assigning raw values onto the config.
   */
  internal fun applyTo(config: SecurityConfig) {
    val v = validateFields

    // trusted_proxies (_security_config_fields.py:22).
    config.setRawTrustedProxies(
        if (v) {
          ConfigValidators.validateIpOrCidrList(
                  trustedProxies ?: emptyList<String>(),
                  invalidMessage = "Invalid proxy IP or CIDR range",
                  allowUnix = true,
              )
              .orEmpty()
        } else {
          trustedProxies ?: emptyList<String>()
        },
    )

    // trusted_proxy_depth (models.py:164-168).
    val depth = trustedProxyDepth ?: 1
    if (v && depth < 1) {
      throw ConfigValidationError("trusted_proxy_depth must be at least 1")
    }
    config.setRawTrustedProxyDepth(depth)

    config.setRawTrustXForwardedProto(trustXForwardedProto ?: false)
    config.setRawPassiveMode(passiveMode ?: false)
    if (geoIpHandlerProvided) config.setRawGeoIpHandler(geoIpHandler)

    config.setRawEnableRedis(enableRedis ?: true)
    if (redisUrlProvided) config.setRawRedisUrl(redisUrl)
    config.setRawRedisPrefix(redisPrefix ?: "guard_core:")

    val connectTimeout = if (redisSocketConnectTimeoutProvided) redisSocketConnectTimeout else 2.0
    if (v && connectTimeout != null && connectTimeout <= 0.0) {
      throw ConfigValidationError(
          "redis_socket_connect_timeout: Input should be greater than 0 " +
              "[type=greater_than, input_value=$connectTimeout]",
      )
    }
    config.setRawRedisSocketConnectTimeout(connectTimeout)

    val socketTimeout = if (redisSocketTimeoutProvided) redisSocketTimeout else 2.0
    if (v && socketTimeout != null && socketTimeout <= 0.0) {
      throw ConfigValidationError(
          "redis_socket_timeout: Input should be greater than 0 " +
              "[type=greater_than, input_value=$socketTimeout]",
      )
    }
    config.setRawRedisSocketTimeout(socketTimeout)

    val healthInterval = redisHealthCheckInterval ?: 30
    if (v) ConfigValidators.checkGe(healthInterval, 0, "redis_health_check_interval")
    config.setRawRedisHealthCheckInterval(healthInterval)

    val maxConnections = if (redisMaxConnectionsProvided) redisMaxConnections else null
    if (v && maxConnections != null)
        ConfigValidators.checkGe(maxConnections, 1, "redis_max_connections")
    config.setRawRedisMaxConnections(maxConnections)

    val retries = redisRetries ?: 1
    if (v) ConfigValidators.checkGe(retries, 0, "redis_retries")
    config.setRawRedisRetries(retries)

    // whitelist / blacklist / exempt_ips (models.py:154-156).
    config.setRawWhitelist(
        if (v) ConfigValidators.validateIpOrCidrList(whitelist, "Invalid IP or CIDR range")
        else whitelist,
    )
    config.setRawBlacklist(
        if (v) {
          ConfigValidators.validateIpOrCidrList(
                  blacklist ?: emptyList<String>(),
                  "Invalid IP or CIDR range",
              )
              .orEmpty()
        } else {
          blacklist ?: emptyList<String>()
        },
    )
    config.setRawExemptIps(
        if (v) {
          ConfigValidators.validateIpOrCidrList(
                  exemptIps ?: emptyList<String>(),
                  "Invalid IP or CIDR range",
              )
              .orEmpty()
        } else {
          exemptIps ?: emptyList<String>()
        },
    )

    // whitelist_countries / blocked_countries (models.py:170-172).
    config.setRawWhitelistCountries(
        if (v) ConfigValidators.validateCountrySetValue(whitelistCountries)
        else whitelistCountries ?: emptySet<String>(),
    )
    config.setRawBlockedCountries(
        if (v) ConfigValidators.validateCountrySetValue(blockedCountries)
        else blockedCountries ?: emptySet<String>(),
    )

    // blocked_user_agents (models.py:178-180).
    config.setRawBlockedUserAgents(
        if (v) {
          ConfigValidators.validateBlockedUserAgentsValue(blockedUserAgents ?: emptyList<String>())
        } else {
          blockedUserAgents ?: emptyList<String>()
        },
    )

    val banThreshold = autoBanThreshold ?: 10
    if (v) ConfigValidators.checkGe(banThreshold, 1, "auto_ban_threshold")
    config.setRawAutoBanThreshold(banThreshold)

    val banDuration = autoBanDuration ?: 3600
    if (v) ConfigValidators.checkGe(banDuration, 1, "auto_ban_duration")
    config.setRawAutoBanDuration(banDuration)

    config.setRawThreatBanConfig(
        if (v) {
          ConfigValidators.validateThreatBanConfigValue(
              threatBanConfig ?: emptyMap<String, ThreatBanConfig>(),
          )
        } else {
          threatBanConfig ?: emptyMap<String, ThreatBanConfig>()
        },
    )

    config.setRawEnableRateLimitAutoBan(enableRateLimitAutoBan ?: false)
    config.setRawGlobalBehaviorRules(globalBehaviorRules ?: emptyList<BehaviorRuleConfig>())
    config.setRawBehaviorScanResponseBody(behaviorScanResponseBody ?: false)

    val behaviorMax = behaviorMaxResponseBodyInspectBytes ?: 262144
    if (v) {
      ConfigValidators.checkGe(behaviorMax, 1024, "behavior_max_response_body_inspect_bytes")
      ConfigValidators.checkLe(behaviorMax, 10485760, "behavior_max_response_body_inspect_bytes")
    }
    config.setRawBehaviorMaxResponseBodyInspectBytes(behaviorMax)

    val readTimeout = bodyReadTimeout ?: 3.0
    if (v) {
      ConfigValidators.checkGt(readTimeout, 0.0, "body_read_timeout")
      ConfigValidators.checkLe(readTimeout, 30.0, "body_read_timeout")
    }
    config.setRawBodyReadTimeout(readTimeout)

    val maxConcurrent = syncBodyReadMaxConcurrent ?: 64
    if (v) {
      ConfigValidators.checkGe(maxConcurrent, 1, "sync_body_read_max_concurrent")
      ConfigValidators.checkLe(maxConcurrent, 10000, "sync_body_read_max_concurrent")
    }
    config.setRawSyncBodyReadMaxConcurrent(maxConcurrent)

    if (customLogFileProvided) config.setRawCustomLogFile(customLogFile)

    if (logSuspiciousLevelProvided) config.setRawLogSuspiciousLevel(logSuspiciousLevel)
    if (logRequestLevelProvided) config.setRawLogRequestLevel(logRequestLevel)
    if (logCountryCheckLevelProvided) config.setRawLogCountryCheckLevel(logCountryCheckLevel)

    config.setRawLogFormat(logFormat ?: LogFormat.TEXT)

    config.setRawCustomErrorResponses(
        if (v) {
          ConfigValidators.validateIntKeyedStrDict(
              customErrorResponses ?: emptyMap<Int, String>(),
              "custom_error_responses",
          )
        } else {
          customErrorResponses ?: emptyMap<Int, String>()
        },
    )

    config.setRawRateLimit(
        if (v) ConfigValidators.validateIntFieldValue(rateLimit ?: 10, "rate_limit")
        else rateLimit ?: 10,
    )
    config.setRawRateLimitWindow(
        if (v) {
          ConfigValidators.validateIntFieldValue(rateLimitWindow ?: 60, "rate_limit_window")
        } else {
          rateLimitWindow ?: 60
        },
    )

    config.setRawEnforceHttps(enforceHttps ?: false)

    config.setRawSecurityHeaders(
        if (v) {
          ConfigValidators.validateOptionalStrAnyDict(
              if (securityHeadersProvided) securityHeaders
              else SecurityConfig.defaultSecurityHeaders(),
              "security_headers",
          )
        } else if (securityHeadersProvided) {
          securityHeaders
        } else {
          SecurityConfig.defaultSecurityHeaders()
        },
    )

    if (customRequestCheck != null) config.setRawCustomRequestCheck(customRequestCheck)
    if (authVerifier != null) config.setRawAuthVerifier(authVerifier)
    if (customResponseModifier != null) config.setRawCustomResponseModifier(customResponseModifier)

    config.setRawEnableCors(enableCors ?: false)

    config.setRawCorsAllowOrigins(
        if (v)
            ConfigValidators.validateStrList(corsAllowOrigins ?: listOf("*"), "cors_allow_origins")
        else corsAllowOrigins ?: listOf("*"),
    )
    config.setRawCorsAllowMethods(
        if (v) {
          ConfigValidators.validateStrList(
              corsAllowMethods ?: listOf("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"),
              "cors_allow_methods",
          )
        } else {
          corsAllowMethods ?: listOf("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
        },
    )
    config.setRawCorsAllowHeaders(
        if (v)
            ConfigValidators.validateStrList(corsAllowHeaders ?: listOf("*"), "cors_allow_headers")
        else corsAllowHeaders ?: listOf("*"),
    )
    config.setRawCorsAllowCredentials(corsAllowCredentials ?: false)
    config.setRawCorsExposeHeaders(
        if (v)
            ConfigValidators.validateStrList(
                corsExposeHeaders ?: emptyList<String>(),
                "cors_expose_headers",
            )
        else corsExposeHeaders ?: emptyList<String>(),
    )
    config.setRawCorsMaxAge(corsMaxAge ?: 600)

    config.setRawBlockCloudProviders(
        if (v) {
          ConfigValidators.validateBlockCloudProvidersValue(
              if (blockCloudProvidersProvided) blockCloudProviders else null,
          )
        } else if (blockCloudProvidersProvided) {
          blockCloudProviders
        } else {
          null
        },
    )

    val refreshInterval = cloudIpRefreshInterval ?: 3600
    if (v) {
      ConfigValidators.checkGe(refreshInterval, 60, "cloud_ip_refresh_interval")
      ConfigValidators.checkLe(refreshInterval, 86400, "cloud_ip_refresh_interval")
    }
    config.setRawCloudIpRefreshInterval(refreshInterval)

    config.setRawLazyInit(lazyInit ?: true)

    val dbMaxAge = geoIpDbMaxAge ?: 86400
    if (v) {
      ConfigValidators.checkGe(dbMaxAge, 3600, "geo_ip_db_max_age")
      ConfigValidators.checkLe(dbMaxAge, 604800, "geo_ip_db_max_age")
    }
    config.setRawGeoIpDbMaxAge(dbMaxAge)

    if (cloudIpStoreProvided) config.setRawCloudIpStore(cloudIpStore)

    config.setRawExcludePaths(
        if (v) {
          ConfigValidators.validateExcludePathsValue(
              excludePaths
                  ?: listOf(
                      "/docs",
                      "/redoc",
                      "/openapi.json",
                      "/openapi.yaml",
                      "/favicon.ico",
                      "/static",
                  ),
          )
        } else {
          excludePaths
              ?: listOf(
                  "/docs",
                  "/redoc",
                  "/openapi.json",
                  "/openapi.yaml",
                  "/favicon.ico",
                  "/static",
              )
        },
    )

    config.setRawEnableIpBanning(enableIpBanning ?: true)
    config.setRawEnableRateLimiting(enableRateLimiting ?: true)
    config.setRawEnablePenetrationDetection(enablePenetrationDetection ?: true)
    config.setRawFailSecure(failSecure ?: true)
    config.setRawRedisFailOpen(redisFailOpen ?: false)
    config.setRawRouteResolutionStrict(routeResolutionStrict ?: false)

    if (ipinfoTokenProvided) config.setRawIpinfoToken(ipinfoToken)
    config.setRawIpinfoDbPath(
        if (v && !ipinfoDbPathProvided) java.nio.file.Paths.get("data/ipinfo/country_asn.mmdb")
        else ipinfoDbPath,
    )

    config.setRawEnableAgent(enableAgent ?: false)
    if (agentApiKeyProvided) config.setRawAgentApiKey(agentApiKey)
    config.setRawAgentStrict(agentStrict ?: false)
    if (onError != null) config.setRawOnError(onError)
    if (onBlock != null) config.setRawOnBlock(onBlock)

    config.setRawAgentEndpoint(agentEndpoint ?: "https://api.guard-core.com")
    if (agentProjectIdProvided) config.setRawAgentProjectId(agentProjectId)
    config.setRawAgentBufferSize(agentBufferSize ?: 100)
    config.setRawAgentFlushInterval(agentFlushInterval ?: 30)
    config.setRawAgentEnableEvents(agentEnableEvents ?: true)
    config.setRawAgentEnableMetrics(agentEnableMetrics ?: true)
    config.setRawAgentTimeout(agentTimeout ?: 30)
    config.setRawAgentRetryAttempts(agentRetryAttempts ?: 3)
    if (agentProjectEncryptionKeyProvided)
        config.setRawAgentProjectEncryptionKey(agentProjectEncryptionKey)
    if (agentGuardVersionProvided) config.setRawAgentGuardVersion(agentGuardVersion)
    if (agentHighWatermarkRatioProvided)
        config.setRawAgentHighWatermarkRatio(agentHighWatermarkRatio)
    if (agentMaxConcurrentFlushesProvided)
        config.setRawAgentMaxConcurrentFlushes(agentMaxConcurrentFlushes)
    if (agentBufferOverflowPolicyProvided)
        config.setRawAgentBufferOverflowPolicy(agentBufferOverflowPolicy)
    if (agentBackoffFactorProvided) config.setRawAgentBackoffFactor(agentBackoffFactor)
    if (agentSensitiveHeadersProvided) config.setRawAgentSensitiveHeaders(agentSensitiveHeaders)
    if (agentMaxPayloadSizeProvided) config.setRawAgentMaxPayloadSize(agentMaxPayloadSize)
    if (agentCompressionEnabledProvided)
        config.setRawAgentCompressionEnabled(agentCompressionEnabled)
    if (agentCompressionThresholdProvided)
        config.setRawAgentCompressionThreshold(agentCompressionThreshold)
    if (agentInstallIdProvided) config.setRawAgentInstallId(agentInstallId)
    if (agentPayloadSigningSecretProvided)
        config.setRawAgentPayloadSigningSecret(agentPayloadSigningSecret)

    config.setRawEnableDynamicRules(enableDynamicRules ?: false)

    val ruleInterval = dynamicRuleInterval ?: 300
    if (v) ConfigValidators.checkGe(ruleInterval, 60, "dynamic_rule_interval")
    config.setRawDynamicRuleInterval(ruleInterval)

    config.setRawDynamicRulesCachePath(
        if (v) {
          ConfigValidators.validateDynamicRulesCachePathValue(
              dynamicRulesCachePathRaw
                  ?: if (dynamicRulesCachePathProvided) dynamicRulesCachePath else null,
          )
        } else if (dynamicRulesCachePathProvided) {
          dynamicRulesCachePath
        } else {
          null
        },
    )

    val statusInterval = agentStatusInterval ?: 300
    if (v) {
      ConfigValidators.checkGe(statusInterval, 60, "agent_status_interval")
      ConfigValidators.checkLe(statusInterval, 86400, "agent_status_interval")
    }
    config.setRawAgentStatusInterval(statusInterval)

    config.setRawEmergencyMode(emergencyMode ?: false)
    config.setRawEmergencyWhitelist(
        if (v) {
          ConfigValidators.validateStrListFieldValue(
              emergencyWhitelist ?: emptyList<String>(),
              "emergency_whitelist",
          )
        } else {
          emergencyWhitelist ?: emptyList<String>()
        },
    )
    config.setRawEndpointRateLimits(
        if (v) {
          ConfigValidators.validateEndpointRateLimitsValue(
              endpointRateLimits ?: emptyMap<String, Pair<Int, Int>>(),
          )
        } else {
          endpointRateLimits ?: emptyMap<String, Pair<Int, Int>>()
        },
    )

    val compilerTimeout = detectionCompilerTimeout ?: 2.0
    if (v) {
      ConfigValidators.checkGe(compilerTimeout, 0.1, "detection_compiler_timeout")
      ConfigValidators.checkLe(compilerTimeout, 10.0, "detection_compiler_timeout")
    }
    config.setRawDetectionCompilerTimeout(compilerTimeout)

    if (detectionPatternValidationCachePathProvided) {
      config.setRawDetectionPatternValidationCachePath(detectionPatternValidationCachePath)
    }

    val maxContentLength = detectionMaxContentLength ?: 10000
    if (v) {
      ConfigValidators.checkGe(maxContentLength, 1000, "detection_max_content_length")
      ConfigValidators.checkLe(maxContentLength, 100000, "detection_max_content_length")
    }
    config.setRawDetectionMaxContentLength(maxContentLength)

    val maxBodyBytes = detectionMaxBodyInspectBytes ?: 262144
    if (v) {
      ConfigValidators.checkGe(maxBodyBytes, 1024, "detection_max_body_inspect_bytes")
      ConfigValidators.checkLe(maxBodyBytes, 10485760, "detection_max_body_inspect_bytes")
    }
    config.setRawDetectionMaxBodyInspectBytes(maxBodyBytes)

    val maxScanValues = detectionMaxScanValues ?: 512
    if (v) {
      ConfigValidators.checkGe(maxScanValues, 2, "detection_max_scan_values")
      ConfigValidators.checkLe(maxScanValues, 100000, "detection_max_scan_values")
    }
    config.setRawDetectionMaxScanValues(maxScanValues)

    val maxScanChars = detectionMaxScanChars ?: 65536
    if (v) {
      ConfigValidators.checkGe(maxScanChars, 1024, "detection_max_scan_chars")
      ConfigValidators.checkLe(maxScanChars, 262144, "detection_max_scan_chars")
    }
    config.setRawDetectionMaxScanChars(maxScanChars)

    val maxJsonDepth = detectionMaxJsonDepth ?: 32
    if (v) {
      ConfigValidators.checkGe(maxJsonDepth, 1, "detection_max_json_depth")
      ConfigValidators.checkLe(maxJsonDepth, 1000, "detection_max_json_depth")
    }
    config.setRawDetectionMaxJsonDepth(maxJsonDepth)

    val binaryMinRun = detectionBinaryMinRunLength ?: 16
    if (v) {
      ConfigValidators.checkGe(binaryMinRun, 4, "detection_binary_min_run_length")
      ConfigValidators.checkLe(binaryMinRun, 1024, "detection_binary_min_run_length")
    }
    config.setRawDetectionBinaryMinRunLength(binaryMinRun)

    config.setRawDetectionPreserveAttackPatterns(detectionPreserveAttackPatterns ?: true)

    val semanticThreshold = detectionSemanticThreshold ?: 0.7
    if (v) {
      ConfigValidators.checkGe(semanticThreshold, 0.0, "detection_semantic_threshold")
      ConfigValidators.checkLe(semanticThreshold, 1.0, "detection_semantic_threshold")
    }
    config.setRawDetectionSemanticThreshold(semanticThreshold)

    val anomalyThreshold = detectionAnomalyThreshold ?: 3.0
    if (v) {
      ConfigValidators.checkGe(anomalyThreshold, 1.0, "detection_anomaly_threshold")
      ConfigValidators.checkLe(anomalyThreshold, 10.0, "detection_anomaly_threshold")
    }
    config.setRawDetectionAnomalyThreshold(anomalyThreshold)

    val slowThreshold = detectionSlowPatternThreshold ?: 0.1
    if (v) {
      ConfigValidators.checkGe(slowThreshold, 0.01, "detection_slow_pattern_threshold")
      ConfigValidators.checkLe(slowThreshold, 1.0, "detection_slow_pattern_threshold")
    }
    config.setRawDetectionSlowPatternThreshold(slowThreshold)

    val historySize = detectionMonitorHistorySize ?: 1000
    if (v) {
      ConfigValidators.checkGe(historySize, 100, "detection_monitor_history_size")
      ConfigValidators.checkLe(historySize, 10000, "detection_monitor_history_size")
    }
    config.setRawDetectionMonitorHistorySize(historySize)

    val maxTracked = detectionMaxTrackedPatterns ?: 1000
    if (v) {
      ConfigValidators.checkGe(maxTracked, 100, "detection_max_tracked_patterns")
      ConfigValidators.checkLe(maxTracked, 5000, "detection_max_tracked_patterns")
    }
    config.setRawDetectionMaxTrackedPatterns(maxTracked)

    val cooldown = detectionAnomalyEmissionCooldown ?: 60.0
    if (v) {
      ConfigValidators.checkGe(cooldown, 1.0, "detection_anomaly_emission_cooldown")
      ConfigValidators.checkLe(cooldown, 3600.0, "detection_anomaly_emission_cooldown")
    }
    config.setRawDetectionAnomalyEmissionCooldown(cooldown)

    val minSamples = detectionMinSamplesForAnomaly ?: 30
    if (v) {
      ConfigValidators.checkGe(minSamples, 10, "detection_min_samples_for_anomaly")
      ConfigValidators.checkLe(minSamples, 1000, "detection_min_samples_for_anomaly")
    }
    config.setRawDetectionMinSamplesForAnomaly(minSamples)

    val threatThreshold = detectionThreatScoreThreshold ?: 1.0
    if (v) {
      ConfigValidators.checkGe(threatThreshold, 0.0, "detection_threat_score_threshold")
      ConfigValidators.checkLe(threatThreshold, 10.0, "detection_threat_score_threshold")
    }
    config.setRawDetectionThreatScoreThreshold(threatThreshold)

    config.setRawMutedEventTypes(
        if (v) ConfigValidators.validateMutedEventTypesValue(mutedEventTypes ?: emptySet<String>())
        else mutedEventTypes ?: emptySet<String>(),
    )
    config.setRawMutedMetricTypes(
        if (v)
            ConfigValidators.validateMutedMetricTypesValue(mutedMetricTypes ?: emptySet<String>())
        else mutedMetricTypes ?: emptySet<String>(),
    )
    config.setRawMutedCheckLogs(
        if (v) ConfigValidators.validateMutedCheckLogsValue(mutedCheckLogs ?: emptySet<String>())
        else mutedCheckLogs ?: emptySet<String>(),
    )
    config.setRawLogSensitiveHeaders(
        if (v) {
          ConfigValidators.validateSensitiveNameSetValue(
              logSensitiveHeadersRaw ?: logSensitiveHeaders ?: emptySet<String>(),
              "log_sensitive_headers",
          )
        } else {
          logSensitiveHeaders ?: emptySet<String>()
        },
    )
    config.setRawLogSensitiveParams(
        if (v) {
          ConfigValidators.validateSensitiveNameSetValue(
              logSensitiveParamsRaw ?: logSensitiveParams ?: emptySet<String>(),
              "log_sensitive_params",
          )
        } else {
          logSensitiveParams ?: emptySet<String>()
        },
    )
    config.setRawLogSensitiveBodyFields(
        if (v) {
          ConfigValidators.validateSensitiveNameSetValue(
              logSensitiveBodyFieldsRaw ?: logSensitiveBodyFields ?: emptySet<String>(),
              "log_sensitive_body_fields",
          )
        } else {
          logSensitiveBodyFields ?: emptySet<String>()
        },
    )

    config.setRawEnableOtel(enableOtel ?: false)
    config.setRawOtelServiceName(otelServiceName ?: "guard-core")
    if (otelExporterEndpointProvided) config.setRawOtelExporterEndpoint(otelExporterEndpoint)
    config.setRawOtelResourceAttributes(
        if (v) {
          ConfigValidators.validateStrKeyedStrDict(
              otelResourceAttributes ?: emptyMap<String, String>(),
              "otel_resource_attributes",
          )
        } else {
          otelResourceAttributes ?: emptyMap<String, String>()
        },
    )
    config.setRawEnableLogfire(enableLogfire ?: false)
    config.setRawLogfireServiceName(logfireServiceName ?: "guard-core")
    config.setRawEnableEnrichment(enableEnrichment ?: false)

    config.setRawExcludedDetectionHeaders(
        if (v)
            ConfigValidators.validateStrSet(
                excludedDetectionHeaders ?: emptySet<String>(),
                "excluded_detection_headers",
            )
        else excludedDetectionHeaders ?: emptySet<String>(),
    )
    config.setRawExcludedSemanticDetectionHeaders(
        if (v)
            ConfigValidators.validateStrSet(
                excludedSemanticDetectionHeaders ?: emptySet<String>(),
                "excluded_semantic_detection_headers",
            )
        else excludedSemanticDetectionHeaders ?: emptySet<String>(),
    )
    config.setRawExcludedDetectionParams(
        if (v)
            ConfigValidators.validateStrSet(
                excludedDetectionParams ?: emptySet<String>(),
                "excluded_detection_params",
            )
        else excludedDetectionParams ?: emptySet<String>(),
    )
    config.setRawExcludedDetectionBodyFields(
        if (v) {
          ConfigValidators.validateStrSet(
              excludedDetectionBodyFields ?: emptySet<String>(),
              "excluded_detection_body_fields",
          )
        } else {
          excludedDetectionBodyFields ?: emptySet<String>()
        },
    )
    config.setRawDetectionScanBody(detectionScanBody ?: true)

    config.setRawEnabledDetectionCategories(
        if (v) {
          ConfigValidators.validateEnabledDetectionCategoriesValue(
              enabledDetectionCategories ?: DetectionCategories.ALL_DETECTION_CATEGORIES,
          )
        } else {
          enabledDetectionCategories ?: DetectionCategories.ALL_DETECTION_CATEGORIES
        },
    )
  }

  // ------------------------------------------------------ helpers

  // ------------------------------------------------------- factories

  public companion object {
    /**
     * Populate a builder from an existing config (python model_copy source values). `deep`
     * deep-copies the mutable containers.
     */
    public fun fromConfig(config: SecurityConfig, deep: Boolean = false): SecurityConfigBuilder {
      fun <T> cp(list: List<T>): List<T> = if (deep) list.map { it }.toMutableList() else list
      fun cpSet(set: Set<String>): Set<String> = if (deep) set.toMutableSet() else set
      fun <K, V> cpMap(map: Map<K, V>): Map<K, V> = if (deep) map.toMutableMap() else map

      val b = SecurityConfigBuilder()
      b.validateFields = false
      b.trustedProxies = cp(config.trustedProxies)
      b.trustedProxyDepth = config.trustedProxyDepth
      b.trustXForwardedProto = config.trustXForwardedProto
      b.passiveMode = config.passiveMode
      if (config.geoIpHandler != null) {
        b.geoIpHandler = config.geoIpHandler
        b.geoIpHandlerProvided = true
      }
      b.enableRedis = config.enableRedis
      b.redisUrl = config.redisUrl
      b.redisUrlProvided = true
      b.redisPrefix = config.redisPrefix
      b.redisSocketConnectTimeout = config.redisSocketConnectTimeout
      b.redisSocketConnectTimeoutProvided = true
      b.redisSocketTimeout = config.redisSocketTimeout
      b.redisSocketTimeoutProvided = true
      b.redisHealthCheckInterval = config.redisHealthCheckInterval
      b.redisMaxConnections = config.redisMaxConnections
      b.redisMaxConnectionsProvided = true
      b.redisRetries = config.redisRetries
      b.whitelist = config.whitelist?.let { cp(it) }
      b.whitelistProvided = true
      b.blacklist = cp(config.blacklist)
      b.exemptIps = cp(config.exemptIps)
      b.whitelistCountries = cpSet(config.whitelistCountries)
      b.blockedCountries = cpSet(config.blockedCountries)
      b.blockedUserAgents = cp(config.blockedUserAgents)
      b.autoBanThreshold = config.autoBanThreshold
      b.autoBanDuration = config.autoBanDuration
      b.threatBanConfig = cpMap(config.threatBanConfig)
      b.enableRateLimitAutoBan = config.enableRateLimitAutoBan
      b.globalBehaviorRules = cp(config.globalBehaviorRules)
      b.behaviorScanResponseBody = config.behaviorScanResponseBody
      b.behaviorMaxResponseBodyInspectBytes = config.behaviorMaxResponseBodyInspectBytes
      b.bodyReadTimeout = config.bodyReadTimeout
      b.syncBodyReadMaxConcurrent = config.syncBodyReadMaxConcurrent
      b.customLogFile = config.customLogFile
      b.customLogFileProvided = true
      b.logSuspiciousLevel = config.logSuspiciousLevel
      b.logSuspiciousLevelProvided = true
      b.logRequestLevel = config.logRequestLevel
      b.logRequestLevelProvided = true
      b.logCountryCheckLevel = config.logCountryCheckLevel
      b.logCountryCheckLevelProvided = true
      b.logFormat = config.logFormat
      b.customErrorResponses = cpMap(config.customErrorResponses)
      b.rateLimit = config.rateLimit
      b.rateLimitWindow = config.rateLimitWindow
      b.enforceHttps = config.enforceHttps
      b.securityHeaders = config.securityHeaders?.let { cpMap(it) }
      b.securityHeadersProvided = true
      b.customRequestCheck = config.customRequestCheck
      b.authVerifier = config.authVerifier
      b.customResponseModifier = config.customResponseModifier
      b.enableCors = config.enableCors
      b.corsAllowOrigins = cp(config.corsAllowOrigins)
      b.corsAllowMethods = cp(config.corsAllowMethods)
      b.corsAllowHeaders = cp(config.corsAllowHeaders)
      b.corsAllowCredentials = config.corsAllowCredentials
      b.corsExposeHeaders = cp(config.corsExposeHeaders)
      b.corsMaxAge = config.corsMaxAge
      b.blockCloudProviders = config.blockCloudProviders?.let { cpSet(it) }
      b.blockCloudProvidersProvided = true
      b.cloudIpRefreshInterval = config.cloudIpRefreshInterval
      b.lazyInit = config.lazyInit
      b.geoIpDbMaxAge = config.geoIpDbMaxAge
      b.cloudIpStore = config.cloudIpStore
      b.cloudIpStoreProvided = true
      b.excludePaths = cp(config.excludePaths)
      b.enableIpBanning = config.enableIpBanning
      b.enableRateLimiting = config.enableRateLimiting
      b.enablePenetrationDetection = config.enablePenetrationDetection
      b.failSecure = config.failSecure
      b.redisFailOpen = config.redisFailOpen
      b.routeResolutionStrict = config.routeResolutionStrict
      b.ipinfoToken = config.ipinfoToken
      b.ipinfoTokenProvided = true
      b.ipinfoDbPath = config.ipinfoDbPath
      b.ipinfoDbPathProvided = true
      b.enableAgent = config.enableAgent
      b.agentApiKey = config.agentApiKey
      b.agentApiKeyProvided = true
      b.agentStrict = config.agentStrict
      b.onError = config.onError
      b.onBlock = config.onBlock
      b.agentEndpoint = config.agentEndpoint
      b.agentProjectId = config.agentProjectId
      b.agentProjectIdProvided = true
      b.agentBufferSize = config.agentBufferSize
      b.agentFlushInterval = config.agentFlushInterval
      b.agentEnableEvents = config.agentEnableEvents
      b.agentEnableMetrics = config.agentEnableMetrics
      b.agentTimeout = config.agentTimeout
      b.agentRetryAttempts = config.agentRetryAttempts
      b.agentProjectEncryptionKey = config.agentProjectEncryptionKey
      b.agentProjectEncryptionKeyProvided = true
      b.agentGuardVersion = config.agentGuardVersion
      b.agentGuardVersionProvided = true
      b.agentHighWatermarkRatio = config.agentHighWatermarkRatio
      b.agentHighWatermarkRatioProvided = true
      b.agentMaxConcurrentFlushes = config.agentMaxConcurrentFlushes
      b.agentMaxConcurrentFlushesProvided = true
      b.agentBufferOverflowPolicy = config.agentBufferOverflowPolicy
      b.agentBufferOverflowPolicyProvided = true
      b.agentBackoffFactor = config.agentBackoffFactor
      b.agentBackoffFactorProvided = true
      b.agentSensitiveHeaders = config.agentSensitiveHeaders?.let { cp(it) }
      b.agentSensitiveHeadersProvided = true
      b.agentMaxPayloadSize = config.agentMaxPayloadSize
      b.agentMaxPayloadSizeProvided = true
      b.agentCompressionEnabled = config.agentCompressionEnabled
      b.agentCompressionEnabledProvided = true
      b.agentCompressionThreshold = config.agentCompressionThreshold
      b.agentCompressionThresholdProvided = true
      b.agentInstallId = config.agentInstallId
      b.agentInstallIdProvided = true
      b.agentPayloadSigningSecret = config.agentPayloadSigningSecret
      b.agentPayloadSigningSecretProvided = true
      b.enableDynamicRules = config.enableDynamicRules
      b.dynamicRuleInterval = config.dynamicRuleInterval
      b.dynamicRulesCachePath = config.dynamicRulesCachePath
      b.dynamicRulesCachePathProvided = true
      b.agentStatusInterval = config.agentStatusInterval
      b.emergencyMode = config.emergencyMode
      b.emergencyWhitelist = cp(config.emergencyWhitelist)
      b.endpointRateLimits = cpMap(config.endpointRateLimits)
      b.detectionCompilerTimeout = config.detectionCompilerTimeout
      b.detectionPatternValidationCachePath = config.detectionPatternValidationCachePath
      b.detectionPatternValidationCachePathProvided = true
      b.detectionMaxContentLength = config.detectionMaxContentLength
      b.detectionMaxBodyInspectBytes = config.detectionMaxBodyInspectBytes
      b.detectionMaxScanValues = config.detectionMaxScanValues
      b.detectionMaxScanChars = config.detectionMaxScanChars
      b.detectionMaxJsonDepth = config.detectionMaxJsonDepth
      b.detectionBinaryMinRunLength = config.detectionBinaryMinRunLength
      b.detectionPreserveAttackPatterns = config.detectionPreserveAttackPatterns
      b.detectionSemanticThreshold = config.detectionSemanticThreshold
      b.detectionAnomalyThreshold = config.detectionAnomalyThreshold
      b.detectionSlowPatternThreshold = config.detectionSlowPatternThreshold
      b.detectionMonitorHistorySize = config.detectionMonitorHistorySize
      b.detectionMaxTrackedPatterns = config.detectionMaxTrackedPatterns
      b.detectionAnomalyEmissionCooldown = config.detectionAnomalyEmissionCooldown
      b.detectionMinSamplesForAnomaly = config.detectionMinSamplesForAnomaly
      b.detectionThreatScoreThreshold = config.detectionThreatScoreThreshold
      b.mutedEventTypes = cpSet(config.mutedEventTypes)
      b.mutedMetricTypes = cpSet(config.mutedMetricTypes)
      b.mutedCheckLogs = cpSet(config.mutedCheckLogs)
      b.logSensitiveHeaders = cpSet(config.logSensitiveHeaders)
      b.logSensitiveParams = cpSet(config.logSensitiveParams)
      b.logSensitiveBodyFields = cpSet(config.logSensitiveBodyFields)
      b.enableOtel = config.enableOtel
      b.otelServiceName = config.otelServiceName
      b.otelExporterEndpoint = config.otelExporterEndpoint
      b.otelExporterEndpointProvided = true
      b.otelResourceAttributes = cpMap(config.otelResourceAttributes)
      b.enableLogfire = config.enableLogfire
      b.logfireServiceName = config.logfireServiceName
      b.enableEnrichment = config.enableEnrichment
      b.excludedDetectionHeaders = cpSet(config.excludedDetectionHeaders)
      b.excludedSemanticDetectionHeaders = cpSet(config.excludedSemanticDetectionHeaders)
      b.excludedDetectionParams = cpSet(config.excludedDetectionParams)
      b.excludedDetectionBodyFields = cpSet(config.excludedDetectionBodyFields)
      b.detectionScanBody = config.detectionScanBody
      b.enabledDetectionCategories = cpSet(config.enabledDetectionCategories)
      return b
    }

    /**
     * Port of the Python kwargs constructor (guard_core/models.py SecurityConfig(**kwargs))
     * including the unknown-field warning with the difflib "Did you mean" hint (models.py:133-152).
     * Values use python field names.
     */
    public fun fromMap(values: Map<String, Any?>, warnUnknown: Boolean = true): SecurityConfig {
      val builder = SecurityConfigBuilder()
      if (warnUnknown) {
        val known = ConfigFieldRegistry.fields.map { it.pythonName }.toSet()
        val unknown = values.keys.filter { it !in known }.distinct()
        for (key in unknown) {
          val match = PyDiffLib.getCloseMatches(key, known.toList(), n = 1)
          val hint = if (match.isNotEmpty()) " Did you mean '${match[0]}'?" else ""
          builder.logger.warning(
              "SecurityConfig received unknown field '$key'; it was ignored " +
                  "and had no effect.$hint",
          )
        }
      }
      MapApplier.apply(builder, values)
      return builder.build()
    }
  }
}

/** Internal applier translating python field names to builder properties. */
private object MapApplier {
  fun apply(b: SecurityConfigBuilder, values: Map<String, Any?>) {
    for ((name, value) in values) {
      applyOne(b, name, value)
    }
  }

  private fun applyOne(b: SecurityConfigBuilder, name: String, value: Any?) {
    when (name) {
      "trusted_proxies" -> b.trustedProxies = strList(value, name)
      "trusted_proxy_depth" -> b.trustedProxyDepth = intValue(value, name)
      "trust_x_forwarded_proto" -> b.trustXForwardedProto = boolValue(value, name)
      "passive_mode" -> b.passiveMode = boolValue(value, name)
      "geo_ip_handler" -> {
        b.geoIpHandler = value as? com.guardcore.protocols.GeoIPHandler
        b.geoIpHandlerProvided = true
      }
      "enable_redis" -> b.enableRedis = boolValue(value, name)
      "redis_url" -> {
        b.redisUrl = strOrNullValue(value, name)
        b.redisUrlProvided = true
      }
      "redis_prefix" -> b.redisPrefix = strValue(value, name)
      "redis_socket_connect_timeout" -> {
        b.redisSocketConnectTimeout = floatOrNullValue(value, name)
        b.redisSocketConnectTimeoutProvided = true
      }
      "redis_socket_timeout" -> {
        b.redisSocketTimeout = floatOrNullValue(value, name)
        b.redisSocketTimeoutProvided = true
      }
      "redis_health_check_interval" -> b.redisHealthCheckInterval = intValue(value, name)
      "redis_max_connections" -> {
        b.redisMaxConnections = intOrNullValue(value, name)
        b.redisMaxConnectionsProvided = true
      }
      "redis_retries" -> b.redisRetries = intValue(value, name)
      "whitelist" -> {
        b.whitelist = strListOrNull(value, name)
        b.whitelistProvided = true
      }
      "blacklist" -> b.blacklist = strList(value, name)
      "exempt_ips" -> b.exemptIps = strList(value, name)
      "whitelist_countries" -> b.whitelistCountries = collectionValue(value, name)
      "blocked_countries" -> b.blockedCountries = collectionValue(value, name)
      "blocked_user_agents" -> b.blockedUserAgents = strList(value, name)
      "auto_ban_threshold" -> b.autoBanThreshold = intValue(value, name)
      "auto_ban_duration" -> b.autoBanDuration = intValue(value, name)
      "threat_ban_config" -> b.threatBanConfig = threatBanValue(value, name)
      "enable_rate_limit_auto_ban" -> b.enableRateLimitAutoBan = boolValue(value, name)
      "global_behavior_rules" -> b.globalBehaviorRules = behaviorRulesValue(value, name)
      "behavior_scan_response_body" -> b.behaviorScanResponseBody = boolValue(value, name)
      "behavior_max_response_body_inspect_bytes" ->
          b.behaviorMaxResponseBodyInspectBytes = intValue(value, name)
      "body_read_timeout" -> b.bodyReadTimeout = floatValue(value, name)
      "sync_body_read_max_concurrent" -> b.syncBodyReadMaxConcurrent = intValue(value, name)
      "custom_log_file" -> {
        b.customLogFile = strOrNullValue(value, name)
        b.customLogFileProvided = true
      }
      "log_suspicious_level" -> {
        b.logSuspiciousLevel = levelValue(value, name)
        b.logSuspiciousLevelProvided = true
      }
      "log_request_level" -> {
        b.logRequestLevel = levelValue(value, name)
        b.logRequestLevelProvided = true
      }
      "log_country_check_level" -> {
        b.logCountryCheckLevel = levelValue(value, name)
        b.logCountryCheckLevelProvided = true
      }
      "log_format" -> b.logFormat = logFormatValue(value, name)
      "custom_error_responses" -> b.customErrorResponses = intKeyedStrDict(value, name)
      "rate_limit" -> b.rateLimit = intValue(value, name)
      "rate_limit_window" -> b.rateLimitWindow = intValue(value, name)
      "enforce_https" -> b.enforceHttps = boolValue(value, name)
      "security_headers" -> {
        b.securityHeaders = strAnyDictOrNull(value, name)
        b.securityHeadersProvided = true
      }
      "custom_request_check" -> b.customRequestCheck = value as? CustomRequestCheck
      "auth_verifier" -> b.authVerifier = value as? AuthVerifier
      "custom_response_modifier" -> b.customResponseModifier = value as? CustomResponseModifier
      "enable_cors" -> b.enableCors = boolValue(value, name)
      "cors_allow_origins" -> b.corsAllowOrigins = strList(value, name)
      "cors_allow_methods" -> b.corsAllowMethods = strList(value, name)
      "cors_allow_headers" -> b.corsAllowHeaders = strList(value, name)
      "cors_allow_credentials" -> b.corsAllowCredentials = boolValue(value, name)
      "cors_expose_headers" -> b.corsExposeHeaders = strList(value, name)
      "cors_max_age" -> b.corsMaxAge = intValue(value, name)
      "block_cloud_providers" -> {
        b.blockCloudProviders = collectionOrNull(value, name)
        b.blockCloudProvidersProvided = true
      }
      "cloud_ip_refresh_interval" -> b.cloudIpRefreshInterval = intValue(value, name)
      "lazy_init" -> b.lazyInit = boolValue(value, name)
      "geo_ip_db_max_age" -> b.geoIpDbMaxAge = intValue(value, name)
      "cloud_ip_store" -> {
        b.cloudIpStore = value
        b.cloudIpStoreProvided = true
      }
      "exclude_paths" -> b.excludePaths = strList(value, name)
      "enable_ip_banning" -> b.enableIpBanning = boolValue(value, name)
      "enable_rate_limiting" -> b.enableRateLimiting = boolValue(value, name)
      "enable_penetration_detection" -> b.enablePenetrationDetection = boolValue(value, name)
      "fail_secure" -> b.failSecure = boolValue(value, name)
      "redis_fail_open" -> b.redisFailOpen = boolValue(value, name)
      "route_resolution_strict" -> b.routeResolutionStrict = boolValue(value, name)
      "ipinfo_token" -> {
        b.ipinfoToken = strOrNullValue(value, name)
        b.ipinfoTokenProvided = true
      }
      "ipinfo_db_path" -> {
        b.ipinfoDbPath = pathOrNullValue(value, name)
        b.ipinfoDbPathProvided = true
      }
      "enable_agent" -> b.enableAgent = boolValue(value, name)
      "agent_api_key" -> {
        b.agentApiKey = strOrNullValue(value, name)
        b.agentApiKeyProvided = true
      }
      "agent_strict" -> b.agentStrict = boolValue(value, name)
      "on_error" -> b.onError = value as? OnErrorHook
      "on_block" -> b.onBlock = value as? BlockHook
      "agent_endpoint" -> b.agentEndpoint = strValue(value, name)
      "agent_project_id" -> {
        b.agentProjectId = strOrNullValue(value, name)
        b.agentProjectIdProvided = true
      }
      "agent_buffer_size" -> b.agentBufferSize = intValue(value, name)
      "agent_flush_interval" -> b.agentFlushInterval = intValue(value, name)
      "agent_enable_events" -> b.agentEnableEvents = boolValue(value, name)
      "agent_enable_metrics" -> b.agentEnableMetrics = boolValue(value, name)
      "agent_timeout" -> b.agentTimeout = intValue(value, name)
      "agent_retry_attempts" -> b.agentRetryAttempts = intValue(value, name)
      "agent_project_encryption_key" -> {
        b.agentProjectEncryptionKey = strOrNullValue(value, name)
        b.agentProjectEncryptionKeyProvided = true
      }
      "agent_guard_version" -> {
        b.agentGuardVersion = strOrNullValue(value, name)
        b.agentGuardVersionProvided = true
      }
      "agent_high_watermark_ratio" -> {
        b.agentHighWatermarkRatio = floatOrNullValue(value, name)
        b.agentHighWatermarkRatioProvided = true
      }
      "agent_max_concurrent_flushes" -> {
        b.agentMaxConcurrentFlushes = intOrNullValue(value, name)
        b.agentMaxConcurrentFlushesProvided = true
      }
      "agent_buffer_overflow_policy" -> {
        b.agentBufferOverflowPolicy = policyValue(value, name)
        b.agentBufferOverflowPolicyProvided = true
      }
      "agent_backoff_factor" -> {
        b.agentBackoffFactor = floatOrNullValue(value, name)
        b.agentBackoffFactorProvided = true
      }
      "agent_sensitive_headers" -> {
        b.agentSensitiveHeaders = strListOrNull(value, name)
        b.agentSensitiveHeadersProvided = true
      }
      "agent_max_payload_size" -> {
        b.agentMaxPayloadSize = intOrNullValue(value, name)
        b.agentMaxPayloadSizeProvided = true
      }
      "agent_compression_enabled" -> {
        b.agentCompressionEnabled = boolOrNullValue(value, name)
        b.agentCompressionEnabledProvided = true
      }
      "agent_compression_threshold" -> {
        b.agentCompressionThreshold = intOrNullValue(value, name)
        b.agentCompressionThresholdProvided = true
      }
      "agent_install_id" -> {
        b.agentInstallId = strOrNullValue(value, name)
        b.agentInstallIdProvided = true
      }
      "agent_payload_signing_secret" -> {
        b.agentPayloadSigningSecret = strOrNullValue(value, name)
        b.agentPayloadSigningSecretProvided = true
      }
      "enable_dynamic_rules" -> b.enableDynamicRules = boolValue(value, name)
      "dynamic_rule_interval" -> b.dynamicRuleInterval = intValue(value, name)
      "dynamic_rules_cache_path" -> b.dynamicRulesCachePathRaw = value
      "agent_status_interval" -> b.agentStatusInterval = intValue(value, name)
      "emergency_mode" -> b.emergencyMode = boolValue(value, name)
      "emergency_whitelist" -> b.emergencyWhitelist = strList(value, name)
      "endpoint_rate_limits" -> b.endpointRateLimits = endpointRateLimitsValue(value, name)
      "detection_compiler_timeout" -> b.detectionCompilerTimeout = floatValue(value, name)
      "detection_pattern_validation_cache_path" -> {
        b.detectionPatternValidationCachePath = strOrNullValue(value, name)
        b.detectionPatternValidationCachePathProvided = true
      }
      "detection_max_content_length" -> b.detectionMaxContentLength = intValue(value, name)
      "detection_max_body_inspect_bytes" -> b.detectionMaxBodyInspectBytes = intValue(value, name)
      "detection_max_scan_values" -> b.detectionMaxScanValues = intValue(value, name)
      "detection_max_scan_chars" -> b.detectionMaxScanChars = intValue(value, name)
      "detection_max_json_depth" -> b.detectionMaxJsonDepth = intValue(value, name)
      "detection_binary_min_run_length" -> b.detectionBinaryMinRunLength = intValue(value, name)
      "detection_preserve_attack_patterns" ->
          b.detectionPreserveAttackPatterns = boolValue(value, name)
      "detection_semantic_threshold" -> b.detectionSemanticThreshold = floatValue(value, name)
      "detection_anomaly_threshold" -> b.detectionAnomalyThreshold = floatValue(value, name)
      "detection_slow_pattern_threshold" ->
          b.detectionSlowPatternThreshold = floatValue(value, name)
      "detection_monitor_history_size" -> b.detectionMonitorHistorySize = intValue(value, name)
      "detection_max_tracked_patterns" -> b.detectionMaxTrackedPatterns = intValue(value, name)
      "detection_anomaly_emission_cooldown" ->
          b.detectionAnomalyEmissionCooldown = floatValue(value, name)
      "detection_min_samples_for_anomaly" -> b.detectionMinSamplesForAnomaly = intValue(value, name)
      "detection_threat_score_threshold" ->
          b.detectionThreatScoreThreshold = floatValue(value, name)
      "muted_event_types" -> b.mutedEventTypes = setValue(value, name)
      "muted_metric_types" -> b.mutedMetricTypes = setValue(value, name)
      "muted_check_logs" -> b.mutedCheckLogs = setValue(value, name)
      "log_sensitive_headers" -> b.logSensitiveHeadersRaw = value
      "log_sensitive_params" -> b.logSensitiveParamsRaw = value
      "log_sensitive_body_fields" -> b.logSensitiveBodyFieldsRaw = value
      "enable_otel" -> b.enableOtel = boolValue(value, name)
      "otel_service_name" -> b.otelServiceName = strValue(value, name)
      "otel_exporter_endpoint" -> {
        b.otelExporterEndpoint = strOrNullValue(value, name)
        b.otelExporterEndpointProvided = true
      }
      "otel_resource_attributes" -> b.otelResourceAttributes = strKeyedStrDict(value, name)
      "enable_logfire" -> b.enableLogfire = boolValue(value, name)
      "logfire_service_name" -> b.logfireServiceName = strValue(value, name)
      "enable_enrichment" -> b.enableEnrichment = boolValue(value, name)
      "excluded_detection_headers" -> b.excludedDetectionHeaders = setValue(value, name)
      "excluded_semantic_detection_headers" ->
          b.excludedSemanticDetectionHeaders = setValue(value, name)
      "excluded_detection_params" -> b.excludedDetectionParams = setValue(value, name)
      "excluded_detection_body_fields" -> b.excludedDetectionBodyFields = setValue(value, name)
      "detection_scan_body" -> b.detectionScanBody = boolValue(value, name)
      "enabled_detection_categories" -> b.enabledDetectionCategories = setValue(value, name)
    // Unknown fields are warned about in fromMap and ignored here.
    }
  }

  private fun reject(name: String, value: Any?, expected: String): Nothing =
      throw ConfigValidationError(
          "$name: $expected (got ${ConfigValidators.typeName(value)})",
      )

  private fun intValue(value: Any?, name: String): Int =
      when (value) {
        is Int -> value
        is Boolean -> reject(name, value, "Input should be a valid integer")
        else -> reject(name, value, "Input should be a valid integer")
      }

  private fun intOrNullValue(value: Any?, name: String): Int? =
      if (value == null) null else intValue(value, name)

  private fun floatValue(value: Any?, name: String): Double =
      when (value) {
        is Double -> value
        is Float -> value.toDouble()
        is Int -> value.toDouble()
        is Boolean -> reject(name, value, "Input should be a valid number")
        else -> reject(name, value, "Input should be a valid number")
      }

  private fun floatOrNullValue(value: Any?, name: String): Double? =
      if (value == null) null else floatValue(value, name)

  private fun boolValue(value: Any?, name: String): Boolean =
      when (value) {
        is Boolean -> value
        else -> reject(name, value, "Input should be a valid boolean")
      }

  private fun boolOrNullValue(value: Any?, name: String): Boolean? =
      if (value == null) null else boolValue(value, name)

  private fun strValue(value: Any?, name: String): String =
      when (value) {
        is String -> value
        else -> reject(name, value, "Input should be a valid string")
      }

  private fun strOrNullValue(value: Any?, name: String): String? =
      if (value == null) null else strValue(value, name)

  private fun strList(value: Any?, name: String): List<String> =
      when (value) {
        is List<*> -> value.map { strValue(it, name) }
        else -> reject(name, value, "Input should be a valid list")
      }

  private fun strListOrNull(value: Any?, name: String): List<String>? =
      if (value == null) null else strList(value, name)

  private fun setValue(value: Any?, name: String): Set<String> =
      when (value) {
        is Set<*> -> value.map { strValue(it, name) }.toSet()
        is Collection<*> -> value.map { strValue(it, name) }.toSet()
        else -> reject(name, value, "Input should be a valid set")
      }

  private fun collectionValue(value: Any?, name: String): Set<String> = setValue(value, name)

  private fun collectionOrNull(value: Any?, name: String): Set<String>? =
      if (value == null) null else setValue(value, name)

  private fun strAnyDictOrNull(value: Any?, name: String): Map<String, Any?>? =
      when (value) {
        null -> null
        is Map<*, *> -> value.entries.associate { (k, v) -> strValue(k, name) to v }
        else -> reject(name, value, "Input should be a valid dictionary")
      }

  private fun intKeyedStrDict(value: Any?, name: String): Map<Int, String> =
      when (value) {
        is Map<*, *> -> value.entries.associate { (k, v) -> intValue(k, name) to strValue(v, name) }
        else -> reject(name, value, "Input should be a valid dictionary")
      }

  private fun strKeyedStrDict(value: Any?, name: String): Map<String, String> =
      when (value) {
        is Map<*, *> -> value.entries.associate { (k, v) -> strValue(k, name) to strValue(v, name) }
        else -> reject(name, value, "Input should be a valid dictionary")
      }

  private fun pathOrNullValue(value: Any?, name: String): java.nio.file.Path? =
      when (value) {
        null -> null
        is java.nio.file.Path -> value
        is String -> java.nio.file.Paths.get(value)
        else -> reject(name, value, "Input should be a valid path")
      }

  private fun levelValue(value: Any?, name: String): LogLevel? =
      when (value) {
        null -> null
        is LogLevel -> value
        is String ->
            LogLevel.entries.firstOrNull { it.pythonName == value }
                ?: reject(
                    name,
                    value,
                    "Input should be 'INFO', 'DEBUG', 'WARNING', 'ERROR' or 'CRITICAL'",
                )
        else ->
            reject(name, value, "Input should be 'INFO', 'DEBUG', 'WARNING', 'ERROR' or 'CRITICAL'")
      }

  private fun logFormatValue(value: Any?, name: String): LogFormat =
      when (value) {
        is LogFormat -> value
        is String ->
            LogFormat.entries.firstOrNull { it.pythonName == value }
                ?: reject(name, value, "Input should be 'text' or 'json'")
        else -> reject(name, value, "Input should be 'text' or 'json'")
      }

  private fun policyValue(value: Any?, name: String): BufferOverflowPolicy? =
      when (value) {
        null -> null
        is BufferOverflowPolicy -> value
        is String ->
            BufferOverflowPolicy.entries.firstOrNull { it.pythonName == value }
                ?: reject(name, value, "Input should be 'drop', 'block' or 'raise'")
        else -> reject(name, value, "Input should be 'drop', 'block' or 'raise'")
      }

  private fun threatBanValue(value: Any?, name: String): Map<String, ThreatBanConfig> =
      when (value) {
        is Map<*, *> ->
            value.entries.associate { (k, v) ->
              val category = strValue(k, name)
              category to
                  when (v) {
                    is ThreatBanConfig -> v
                    is Map<*, *> ->
                        ThreatBanConfig(
                            intValue(v["threshold"] ?: reject(name, v, "missing threshold"), name),
                            intValue(v["duration"] ?: reject(name, v, "missing duration"), name),
                        )
                    else -> reject(name, v, "Input should be a valid dictionary or ThreatBanConfig")
                  }
            }
        else -> reject(name, value, "Input should be a valid dictionary")
      }

  private fun behaviorRulesValue(value: Any?, name: String): List<BehaviorRuleConfig> =
      when (value) {
        is List<*> ->
            value.map { item ->
              when (item) {
                is BehaviorRuleConfig -> item
                is Map<*, *> -> behaviorRuleFromMap(item, name)
                else -> reject(name, item, "Input should be a valid BehaviorRuleConfig")
              }
            }
        else -> reject(name, value, "Input should be a valid list")
      }

  private fun behaviorRuleFromMap(map: Map<*, *>, name: String): BehaviorRuleConfig {
    val ruleTypeRaw = strValue(map["rule_type"] ?: reject(name, map, "rule_type is required"), name)
    val ruleType =
        RuleType.entries.firstOrNull { it.pythonName == ruleTypeRaw }
            ?: reject(name, ruleTypeRaw, "Input should be 'usage', 'return_pattern' or 'frequency'")
    val actionRaw = (map["action"] as? String) ?: "log"
    val action =
        RuleAction.entries.firstOrNull { it.pythonName == actionRaw }
            ?: reject(name, actionRaw, "Input should be 'ban', 'log', 'throttle' or 'alert'")
    return BehaviorRuleConfig(
        ruleType = ruleType,
        threshold = intValue(map["threshold"] ?: reject(name, map, "threshold is required"), name),
        window = (map["window"] as? Int) ?: 3600,
        pattern = map["pattern"] as? String,
        action = action,
        banDuration = map["ban_duration"] as? Int,
        correlateWithDetection = (map["correlate_with_detection"] as? Boolean) ?: false,
    )
  }

  private fun endpointRateLimitsValue(value: Any?, name: String): Map<String, Pair<Int, Int>> =
      when (value) {
        is Map<*, *> ->
            value.entries.associate { (k, v) ->
              val key = strValue(k, name)
              val pair =
                  if (v is Pair<*, *>) {
                    v
                  } else if (v is List<*> && v.size == 2) {
                    v[0] to v[1]
                  } else {
                    reject(name, v, "must be a (int, int) tuple")
                  }
              key to (intValue(pair.first, name) to intValue(pair.second, name))
            }
        else -> reject(name, value, "must be a dict")
      }
}
