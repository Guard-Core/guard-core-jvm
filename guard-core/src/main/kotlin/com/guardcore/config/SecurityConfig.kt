package com.guardcore.config

import com.guardcore.errors.AgentPackageNotInstalledError
import com.guardcore.errors.ConfigValidationError
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import java.nio.file.Path
import java.nio.file.Paths

/** Python `Literal["INFO","DEBUG","WARNING","ERROR","CRITICAL"]` for log levels. */
public enum class LogLevel(val pythonName: String) {
  INFO("INFO"),
  DEBUG("DEBUG"),
  WARNING("WARNING"),
  ERROR("ERROR"),
  CRITICAL("CRITICAL"),
}

/** Python `Literal["text","json"]` for log_format. */
public enum class LogFormat(val pythonName: String) {
  TEXT("text"),
  JSON("json"),
}

/** Python `Literal["drop","block","raise"]` for agent_buffer_overflow_policy. */
public enum class BufferOverflowPolicy(val pythonName: String) {
  DROP("drop"),
  BLOCK("block"),
  RAISE("raise"),
}

/** Best-effort `on_error` callback (models.py:542): (stage, exception, context). */
public fun interface OnErrorHook {
  public fun invoke(stage: String, exc: Throwable, context: Map<String, Any?>)
}

/**
 * Best-effort `on_block` callback (models.py:552): (request, payload). May return a
 * `java.util.concurrent.CompletionStage` for the async form; the invoker awaits it, mirroring
 * `inspect.isawaitable`.
 */
public fun interface BlockHook {
  public fun invoke(request: GuardRequest, payload: Map<String, Any?>): Any?
}

/**
 * `custom_request_check` (models.py:347): async check returning a response to block with, or null
 * to allow.
 */
public fun interface CustomRequestCheck {
  public suspend fun invoke(request: GuardRequest): GuardResponse?
}

/** `custom_response_modifier` (models.py:361): async response transformer. */
public fun interface CustomResponseModifier {
  public suspend fun invoke(response: GuardResponse): GuardResponse
}

/** `auth_verifier` (models.py:351): verifier(request, credential) -> Principal. */
public fun interface AuthVerifier {
  public fun invoke(request: GuardRequest, credential: String): Any?
}

/**
 * Port of `guard_core/models.py` SecurityConfig, field-for-field against `_SecurityConfigFields`
 * (guard_core/_security_config_fields.py:19) and the validators in guard_core/models.py:87-365.
 *
 * Construction runs the pydantic field validators and bounds in field order, then the model
 * validators in declaration order; every public setter mirrors `SecurityConfig.__setattr__`
 * (models.py:98): geo-state hook, field revalidator (`_FIELD_REVALIDATORS`), global-behavior-rule
 * validation, country-shadow warning decision, assignment, revision bump, warning.
 *
 * Every property documents its python_name mapping; default values are byte-exact with the Python
 * defaults.
 */
public class SecurityConfig
internal constructor(
    builder: SecurityConfigBuilder,
    internal val forCopy: Boolean,
) {
  private var revisionCounter: Int = 0

  /**
   * True while the construction pass runs; suppresses setter-time warnings that the model
   * validators own (models.py model_validator order).
   */
  private var constructing = true

  // ------------------------------------------------------------- fields

  private var _trustedProxies: List<String> = emptyList()

  /** python_name: trusted_proxies (models.py:22). */
  public var trustedProxies: List<String>
    get() = _trustedProxies
    set(value) {
      val validated = ConfigValidators.validateTrustedProxiesValue(value)
      if (geoStateHook("trusted_proxies", validated)) return
      _trustedProxies = validated
      bumpRevision()
    }

  private var _trustedProxyDepth: Int = 1

  /** python_name: trusted_proxy_depth (models.py:27). */
  public var trustedProxyDepth: Int
    get() = _trustedProxyDepth
    set(value) {
      if (geoStateHook("trusted_proxy_depth", value)) return
      _trustedProxyDepth = value
      bumpRevision()
    }

  private var _trustXForwardedProto: Boolean = false

  /** python_name: trust_x_forwarded_proto (models.py:32). */
  public var trustXForwardedProto: Boolean
    get() = _trustXForwardedProto
    set(value) {
      if (geoStateHook("trust_x_forwarded_proto", value)) return
      _trustXForwardedProto = value
      bumpRevision()
    }

  private var _passiveMode: Boolean = false

  /** python_name: passive_mode (models.py:37). */
  public var passiveMode: Boolean
    get() = _passiveMode
    set(value) {
      if (geoStateHook("passive_mode", value)) return
      _passiveMode = value
      bumpRevision()
    }

  private var _geoIpHandler: GeoIPHandler? = null

  /** python_name: geo_ip_handler (models.py:42). */
  public var geoIpHandler: GeoIPHandler?
    get() = _geoIpHandler
    set(value) {
      val resolved = applyGeoIpHandlerAssignment("geo_ip_handler", value)
      @Suppress("UNCHECKED_CAST") val validated = resolved as GeoIPHandler?
      if (geoStateHook("geo_ip_handler", validated, skipGeoHook = true)) return
      _geoIpHandler = validated
      bumpRevision()
    }

  private var _enableRedis: Boolean = true

  /** python_name: enable_redis (models.py:47). */
  public var enableRedis: Boolean
    get() = _enableRedis
    set(value) {
      if (geoStateHook("enable_redis", value)) return
      _enableRedis = value
      bumpRevision()
    }

  private var _redisUrl: String? = "redis://localhost:6379"

  /** python_name: redis_url (models.py:52). */
  public var redisUrl: String?
    get() = _redisUrl
    set(value) {
      if (geoStateHook("redis_url", value)) return
      _redisUrl = value
      bumpRevision()
    }

  private var _redisPrefix: String = "guard_core:"

  /** python_name: redis_prefix (models.py:57). */
  public var redisPrefix: String
    get() = _redisPrefix
    set(value) {
      if (geoStateHook("redis_prefix", value)) return
      _redisPrefix = value
      bumpRevision()
    }

  private var _redisSocketConnectTimeout: Double? = 2.0

  /** python_name: redis_socket_connect_timeout (models.py:62). */
  public var redisSocketConnectTimeout: Double?
    get() = _redisSocketConnectTimeout
    set(value) {
      if (geoStateHook("redis_socket_connect_timeout", value)) return
      _redisSocketConnectTimeout = value
      bumpRevision()
    }

  private var _redisSocketTimeout: Double? = 2.0

  /** python_name: redis_socket_timeout (models.py:74). */
  public var redisSocketTimeout: Double?
    get() = _redisSocketTimeout
    set(value) {
      if (geoStateHook("redis_socket_timeout", value)) return
      _redisSocketTimeout = value
      bumpRevision()
    }

  private var _redisHealthCheckInterval: Int = 30

  /** python_name: redis_health_check_interval (models.py:85). */
  public var redisHealthCheckInterval: Int
    get() = _redisHealthCheckInterval
    set(value) {
      if (geoStateHook("redis_health_check_interval", value)) return
      _redisHealthCheckInterval = value
      bumpRevision()
    }

  private var _redisMaxConnections: Int? = null

  /** python_name: redis_max_connections (models.py:95). */
  public var redisMaxConnections: Int?
    get() = _redisMaxConnections
    set(value) {
      if (geoStateHook("redis_max_connections", value)) return
      _redisMaxConnections = value
      bumpRevision()
    }

  private var _redisRetries: Int = 1

  /** python_name: redis_retries (models.py:103). */
  public var redisRetries: Int
    get() = _redisRetries
    set(value) {
      if (geoStateHook("redis_retries", value)) return
      _redisRetries = value
      bumpRevision()
    }

  private var _whitelist: List<String>? = null

  /** python_name: whitelist (models.py:112). */
  public var whitelist: List<String>?
    get() = _whitelist
    set(value) {
      @Suppress("UNCHECKED_CAST")
      val validated = ConfigValidators.validateWhitelistValue(value) as List<String>?
      if (geoStateHook("whitelist", validated)) return
      _whitelist = validated
      bumpRevision()
    }

  private var _blacklist: List<String> = emptyList()

  /** python_name: blacklist (models.py:121). */
  public var blacklist: List<String>
    get() = _blacklist
    set(value) {
      val validated = ConfigValidators.validateBlacklistValue(value)
      if (geoStateHook("blacklist", validated)) return
      _blacklist = validated
      bumpRevision()
    }

  private var _exemptIps: List<String> = emptyList()

  /** python_name: exempt_ips (models.py:129). */
  public var exemptIps: List<String>
    get() = _exemptIps
    set(value) {
      val validated =
          ConfigValidators.validateIpOrCidrList(
                  value,
                  invalidMessage = "Invalid IP or CIDR range",
              )
              .orEmpty()
      if (geoStateHook("exempt_ips", validated)) return
      _exemptIps = validated
      bumpRevision()
    }

  private var _whitelistCountries: Set<String> = emptySet()

  /** python_name: whitelist_countries (models.py:139). */
  public var whitelistCountries: Set<String>
    get() = _whitelistCountries
    set(value) {
      val validated = ConfigValidators.validateCountrySetValue(value)
      if (geoStateHook("whitelist_countries", validated)) return
      val warn = countryShadowShouldWarn("whitelist_countries", validated)
      _whitelistCountries = validated
      bumpRevision()
      if (warn) warnCountryShadow()
    }

  private var _blockedCountries: Set<String> = emptySet()

  /** python_name: blocked_countries (models.py:149). */
  public var blockedCountries: Set<String>
    get() = _blockedCountries
    set(value) {
      val validated = ConfigValidators.validateCountrySetValue(value)
      if (geoStateHook("blocked_countries", validated)) return
      val warn = countryShadowShouldWarn("blocked_countries", validated)
      _blockedCountries = validated
      bumpRevision()
      if (warn) warnCountryShadow()
    }

  private var _blockedUserAgents: List<String> = emptyList()

  /** python_name: blocked_user_agents (models.py:154). */
  public var blockedUserAgents: List<String>
    get() = _blockedUserAgents
    set(value) {
      val validated = ConfigValidators.validateBlockedUserAgentsValue(value)
      if (geoStateHook("blocked_user_agents", validated)) return
      _blockedUserAgents = validated
      bumpRevision()
    }

  private var _autoBanThreshold: Int = 10

  /** python_name: auto_ban_threshold (models.py:158). */
  public var autoBanThreshold: Int
    get() = _autoBanThreshold
    set(value) {
      val validated = ConfigValidators.validatePositiveIntFieldValue(value, "auto_ban_threshold")
      if (geoStateHook("auto_ban_threshold", validated)) return
      _autoBanThreshold = validated
      bumpRevision()
    }

  private var _autoBanDuration: Int = 3600

  /** python_name: auto_ban_duration (models.py:164). */
  public var autoBanDuration: Int
    get() = _autoBanDuration
    set(value) {
      val validated = ConfigValidators.validatePositiveIntFieldValue(value, "auto_ban_duration")
      if (geoStateHook("auto_ban_duration", validated)) return
      _autoBanDuration = validated
      bumpRevision()
    }

  private var _threatBanConfig: Map<String, ThreatBanConfig> = emptyMap()

  /** python_name: threat_ban_config (models.py:170). */
  public var threatBanConfig: Map<String, ThreatBanConfig>
    get() = _threatBanConfig
    set(value) {
      val validated = ConfigValidators.validateThreatBanConfigValue(value)
      if (geoStateHook("threat_ban_config", validated)) return
      _threatBanConfig = validated
      bumpRevision()
    }

  private var _enableRateLimitAutoBan: Boolean = false

  /** python_name: enable_rate_limit_auto_ban (models.py:180). */
  public var enableRateLimitAutoBan: Boolean
    get() = _enableRateLimitAutoBan
    set(value) {
      val validated = ConfigValidators.validateBoolFieldValue(value, "enable_rate_limit_auto_ban")
      if (geoStateHook("enable_rate_limit_auto_ban", validated)) return
      if (globalBehaviorRuleHook("enable_rate_limit_auto_ban", validated)) return
      _enableRateLimitAutoBan = validated
      bumpRevision()
    }

  private var _globalBehaviorRules: List<BehaviorRuleConfig> = emptyList()

  /** python_name: global_behavior_rules (models.py:193). */
  public var globalBehaviorRules: List<BehaviorRuleConfig>
    get() = _globalBehaviorRules
    set(value) {
      // python revalidator: _validate_typed_collection_field_value with
      // _GLOBAL_BEHAVIOR_RULES_ADAPTER (coerces dicts to models at assignment).
      val validated =
          ConfigValidators.validateGlobalBehaviorRulesFieldValue(
              value,
              "global_behavior_rules",
          )
      if (geoStateHook("global_behavior_rules", validated)) return
      if (globalBehaviorRuleHook("global_behavior_rules", validated)) return
      _globalBehaviorRules = validated
      bumpRevision()
    }

  private var _behaviorScanResponseBody: Boolean = false

  /** python_name: behavior_scan_response_body (models.py:201). */
  public var behaviorScanResponseBody: Boolean
    get() = _behaviorScanResponseBody
    set(value) {
      if (geoStateHook("behavior_scan_response_body", value)) return
      if (globalBehaviorRuleHook("behavior_scan_response_body", value)) return
      _behaviorScanResponseBody = value
      bumpRevision()
    }

  private var _behaviorMaxResponseBodyInspectBytes: Int = 262144

  /** python_name: behavior_max_response_body_inspect_bytes (models.py:220). */
  public var behaviorMaxResponseBodyInspectBytes: Int
    get() = _behaviorMaxResponseBodyInspectBytes
    set(value) {
      if (geoStateHook("behavior_max_response_body_inspect_bytes", value)) return
      _behaviorMaxResponseBodyInspectBytes = value
      bumpRevision()
    }

  private var _bodyReadTimeout: Double = 3.0

  /** python_name: body_read_timeout (models.py:241). */
  public var bodyReadTimeout: Double
    get() = _bodyReadTimeout
    set(value) {
      if (geoStateHook("body_read_timeout", value)) return
      _bodyReadTimeout = value
      bumpRevision()
    }

  private var _syncBodyReadMaxConcurrent: Int = 64

  /** python_name: sync_body_read_max_concurrent (models.py:266). */
  public var syncBodyReadMaxConcurrent: Int
    get() = _syncBodyReadMaxConcurrent
    set(value) {
      if (geoStateHook("sync_body_read_max_concurrent", value)) return
      _syncBodyReadMaxConcurrent = value
      bumpRevision()
    }

  private var _customLogFile: String? = null

  /** python_name: custom_log_file (models.py:282). */
  public var customLogFile: String?
    get() = _customLogFile
    set(value) {
      if (geoStateHook("custom_log_file", value)) return
      _customLogFile = value
      bumpRevision()
    }

  private var _logSuspiciousLevel: LogLevel? = LogLevel.WARNING

  /** python_name: log_suspicious_level (models.py:287). */
  public var logSuspiciousLevel: LogLevel?
    get() = _logSuspiciousLevel
    set(value) {
      if (geoStateHook("log_suspicious_level", value)) return
      _logSuspiciousLevel = value
      bumpRevision()
    }

  private var _logRequestLevel: LogLevel? = null

  /** python_name: log_request_level (models.py:291). */
  public var logRequestLevel: LogLevel?
    get() = _logRequestLevel
    set(value) {
      if (geoStateHook("log_request_level", value)) return
      _logRequestLevel = value
      bumpRevision()
    }

  private var _logCountryCheckLevel: LogLevel? = LogLevel.INFO

  /** python_name: log_country_check_level (models.py:295). */
  public var logCountryCheckLevel: LogLevel?
    get() = _logCountryCheckLevel
    set(value) {
      if (geoStateHook("log_country_check_level", value)) return
      _logCountryCheckLevel = value
      bumpRevision()
    }

  private var _logFormat: LogFormat = LogFormat.TEXT

  /** python_name: log_format (models.py:307). */
  public var logFormat: LogFormat
    get() = _logFormat
    set(value) {
      if (geoStateHook("log_format", value)) return
      _logFormat = value
      bumpRevision()
    }

  private var _customErrorResponses: Map<Int, String> = emptyMap()

  /** python_name: custom_error_responses (models.py:312). */
  public var customErrorResponses: Map<Int, String>
    get() = _customErrorResponses
    set(value) {
      val validated = ConfigValidators.validateIntKeyedStrDict(value, "custom_error_responses")
      if (geoStateHook("custom_error_responses", validated)) return
      _customErrorResponses = validated
      bumpRevision()
    }

  private var _rateLimit: Int = 10

  /** python_name: rate_limit (models.py:316). */
  public var rateLimit: Int
    get() = _rateLimit
    set(value) {
      val validated = ConfigValidators.validateIntFieldValue(value, "rate_limit")
      if (geoStateHook("rate_limit", validated)) return
      _rateLimit = validated
      bumpRevision()
    }

  private var _rateLimitWindow: Int = 60

  /** python_name: rate_limit_window (models.py:320). */
  public var rateLimitWindow: Int
    get() = _rateLimitWindow
    set(value) {
      val validated = ConfigValidators.validateIntFieldValue(value, "rate_limit_window")
      if (geoStateHook("rate_limit_window", validated)) return
      _rateLimitWindow = validated
      bumpRevision()
    }

  private var _enforceHttps: Boolean = false

  /** python_name: enforce_https (models.py:324). */
  public var enforceHttps: Boolean
    get() = _enforceHttps
    set(value) {
      if (geoStateHook("enforce_https", value)) return
      _enforceHttps = value
      bumpRevision()
    }

  private var _securityHeaders: Map<String, Any?>? = defaultSecurityHeaders()

  /** python_name: security_headers (models.py:328). */
  public var securityHeaders: Map<String, Any?>?
    get() = _securityHeaders
    set(value) {
      val validated = ConfigValidators.validateOptionalStrAnyDict(value, "security_headers")
      if (geoStateHook("security_headers", validated)) return
      _securityHeaders = validated
      bumpRevision()
    }

  private var _customRequestCheck: CustomRequestCheck? = null

  /** python_name: custom_request_check (models.py:347). */
  public var customRequestCheck: CustomRequestCheck?
    get() = _customRequestCheck
    set(value) {
      if (geoStateHook("custom_request_check", value)) return
      _customRequestCheck = value
      bumpRevision()
    }

  private var _authVerifier: AuthVerifier? = null

  /** python_name: auth_verifier (models.py:351). */
  public var authVerifier: AuthVerifier?
    get() = _authVerifier
    set(value) {
      if (geoStateHook("auth_verifier", value)) return
      _authVerifier = value
      bumpRevision()
    }

  private var _customResponseModifier: CustomResponseModifier? = null

  /** python_name: custom_response_modifier (models.py:361). */
  public var customResponseModifier: CustomResponseModifier?
    get() = _customResponseModifier
    set(value) {
      if (geoStateHook("custom_response_modifier", value)) return
      _customResponseModifier = value
      bumpRevision()
    }

  private var _enableCors: Boolean = false

  /** python_name: enable_cors (models.py:368). */
  public var enableCors: Boolean
    get() = _enableCors
    set(value) {
      if (geoStateHook("enable_cors", value)) return
      _enableCors = value
      bumpRevision()
    }

  private var _corsAllowOrigins: List<String> = listOf("*")

  /** python_name: cors_allow_origins (models.py:370). */
  public var corsAllowOrigins: List<String>
    get() = _corsAllowOrigins
    set(value) {
      val validated = ConfigValidators.validateStrList(value, "cors_allow_origins")
      if (geoStateHook("cors_allow_origins", validated)) return
      _corsAllowOrigins = validated
      bumpRevision()
    }

  private var _corsAllowMethods: List<String> =
      listOf("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")

  /** python_name: cors_allow_methods (models.py:374). */
  public var corsAllowMethods: List<String>
    get() = _corsAllowMethods
    set(value) {
      val validated = ConfigValidators.validateStrList(value, "cors_allow_methods")
      if (geoStateHook("cors_allow_methods", validated)) return
      _corsAllowMethods = validated
      bumpRevision()
    }

  private var _corsAllowHeaders: List<String> = listOf("*")

  /** python_name: cors_allow_headers (models.py:379). */
  public var corsAllowHeaders: List<String>
    get() = _corsAllowHeaders
    set(value) {
      val validated = ConfigValidators.validateStrList(value, "cors_allow_headers")
      if (geoStateHook("cors_allow_headers", validated)) return
      _corsAllowHeaders = validated
      bumpRevision()
    }

  private var _corsAllowCredentials: Boolean = false

  /** python_name: cors_allow_credentials (models.py:383). */
  public var corsAllowCredentials: Boolean
    get() = _corsAllowCredentials
    set(value) {
      if (geoStateHook("cors_allow_credentials", value)) return
      _corsAllowCredentials = value
      bumpRevision()
    }

  private var _corsExposeHeaders: List<String> = emptyList()

  /** python_name: cors_expose_headers (models.py:387). */
  public var corsExposeHeaders: List<String>
    get() = _corsExposeHeaders
    set(value) {
      val validated = ConfigValidators.validateStrList(value, "cors_expose_headers")
      if (geoStateHook("cors_expose_headers", validated)) return
      _corsExposeHeaders = validated
      bumpRevision()
    }

  private var _corsMaxAge: Int = 600

  /** python_name: cors_max_age (models.py:391). */
  public var corsMaxAge: Int
    get() = _corsMaxAge
    set(value) {
      if (geoStateHook("cors_max_age", value)) return
      _corsMaxAge = value
      bumpRevision()
    }

  private var _blockCloudProviders: Set<String>? = null

  /** python_name: block_cloud_providers (models.py:395). */
  public var blockCloudProviders: Set<String>?
    get() = _blockCloudProviders
    set(value) {
      val validated = ConfigValidators.validateBlockCloudProvidersValue(value)
      if (geoStateHook("block_cloud_providers", validated)) return
      _blockCloudProviders = validated
      bumpRevision()
    }

  private var _cloudIpRefreshInterval: Int = 3600

  /** python_name: cloud_ip_refresh_interval (models.py:408). */
  public var cloudIpRefreshInterval: Int
    get() = _cloudIpRefreshInterval
    set(value) {
      if (geoStateHook("cloud_ip_refresh_interval", value)) return
      _cloudIpRefreshInterval = value
      bumpRevision()
    }

  private var _lazyInit: Boolean = true

  /** python_name: lazy_init (models.py:415). */
  public var lazyInit: Boolean
    get() = _lazyInit
    set(value) {
      if (geoStateHook("lazy_init", value)) return
      _lazyInit = value
      bumpRevision()
    }

  private var _geoIpDbMaxAge: Int = 86400

  /** python_name: geo_ip_db_max_age (models.py:434). */
  public var geoIpDbMaxAge: Int
    get() = _geoIpDbMaxAge
    set(value) {
      if (geoStateHook("geo_ip_db_max_age", value)) return
      _geoIpDbMaxAge = value
      bumpRevision()
    }

  private var _cloudIpStore: Any? = null

  /**
   * python_name: cloud_ip_store (models.py:441). Accepts a CloudIpStoreProtocol instance or a
   * CloudIpStoreFactory function.
   */
  public var cloudIpStore: Any?
    get() = _cloudIpStore
    set(value) {
      if (geoStateHook("cloud_ip_store", value)) return
      _cloudIpStore = value
      bumpRevision()
    }

  private var _excludePaths: List<String> =
      listOf("/docs", "/redoc", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/static")

  /** python_name: exclude_paths (models.py:452). */
  public var excludePaths: List<String>
    get() = _excludePaths
    set(value) {
      val validated = ConfigValidators.validateExcludePathsValue(value)
      if (geoStateHook("exclude_paths", validated)) return
      _excludePaths = validated
      bumpRevision()
    }

  private var _enableIpBanning: Boolean = true

  /** python_name: enable_ip_banning (models.py:464). */
  public var enableIpBanning: Boolean
    get() = _enableIpBanning
    set(value) {
      val validated = ConfigValidators.validateBoolFieldValue(value, "enable_ip_banning")
      if (geoStateHook("enable_ip_banning", validated)) return
      _enableIpBanning = validated
      bumpRevision()
    }

  private var _enableRateLimiting: Boolean = true

  /** python_name: enable_rate_limiting (models.py:468). */
  public var enableRateLimiting: Boolean
    get() = _enableRateLimiting
    set(value) {
      val validated = ConfigValidators.validateBoolFieldValue(value, "enable_rate_limiting")
      if (geoStateHook("enable_rate_limiting", validated)) return
      _enableRateLimiting = validated
      bumpRevision()
    }

  private var _enablePenetrationDetection: Boolean = true

  /** python_name: enable_penetration_detection (models.py:472). */
  public var enablePenetrationDetection: Boolean
    get() = _enablePenetrationDetection
    set(value) {
      val validated = ConfigValidators.validateBoolFieldValue(value, "enable_penetration_detection")
      if (geoStateHook("enable_penetration_detection", validated)) return
      _enablePenetrationDetection = validated
      bumpRevision()
    }

  private var _failSecure: Boolean = true

  /** python_name: fail_secure (models.py:476). */
  public var failSecure: Boolean
    get() = _failSecure
    set(value) {
      if (geoStateHook("fail_secure", value)) return
      _failSecure = value
      bumpRevision()
    }

  private var _redisFailOpen: Boolean = false

  /** python_name: redis_fail_open (models.py:486). */
  public var redisFailOpen: Boolean
    get() = _redisFailOpen
    set(value) {
      if (geoStateHook("redis_fail_open", value)) return
      _redisFailOpen = value
      bumpRevision()
    }

  private var _routeResolutionStrict: Boolean = false

  /** python_name: route_resolution_strict (models.py:498). */
  public var routeResolutionStrict: Boolean
    get() = _routeResolutionStrict
    set(value) {
      if (geoStateHook("route_resolution_strict", value)) return
      _routeResolutionStrict = value
      bumpRevision()
    }

  private var _ipinfoToken: String? = null

  /** python_name: ipinfo_token (models.py:513). */
  public var ipinfoToken: String?
    get() = _ipinfoToken
    set(value) {
      if (geoStateHook("ipinfo_token", value)) return
      _ipinfoToken = value
      bumpRevision()
    }

  private var _ipinfoDbPath: Path? = Paths.get("data/ipinfo/country_asn.mmdb")

  /** python_name: ipinfo_db_path (models.py:519). */
  public var ipinfoDbPath: Path?
    get() = _ipinfoDbPath
    set(value) {
      if (geoStateHook("ipinfo_db_path", value)) return
      _ipinfoDbPath = value
      bumpRevision()
    }

  private var _enableAgent: Boolean = false

  /** python_name: enable_agent (models.py:525). */
  public var enableAgent: Boolean
    get() = _enableAgent
    set(value) {
      if (geoStateHook("enable_agent", value)) return
      _enableAgent = value
      bumpRevision()
    }

  private var _agentApiKey: String? = null

  /** python_name: agent_api_key (models.py:529). */
  public var agentApiKey: String?
    get() = _agentApiKey
    set(value) {
      if (geoStateHook("agent_api_key", value)) return
      _agentApiKey = value
      bumpRevision()
    }

  private var _agentStrict: Boolean = false

  /** python_name: agent_strict (models.py:533). */
  public var agentStrict: Boolean
    get() = _agentStrict
    set(value) {
      if (geoStateHook("agent_strict", value)) return
      _agentStrict = value
      bumpRevision()
    }

  private var _onError: OnErrorHook? = null

  /** python_name: on_error (models.py:542). */
  public var onError: OnErrorHook?
    get() = _onError
    set(value) {
      if (geoStateHook("on_error", value)) return
      _onError = value
      bumpRevision()
    }

  private var _onBlock: BlockHook? = null

  /** python_name: on_block (models.py:552). */
  public var onBlock: BlockHook?
    get() = _onBlock
    set(value) {
      if (geoStateHook("on_block", value)) return
      _onBlock = value
      bumpRevision()
    }

  private var _agentEndpoint: String = "https://api.guard-core.com"

  /** python_name: agent_endpoint (models.py:569). */
  public var agentEndpoint: String
    get() = _agentEndpoint
    set(value) {
      if (geoStateHook("agent_endpoint", value)) return
      _agentEndpoint = value
      bumpRevision()
    }

  private var _agentProjectId: String? = null

  /** python_name: agent_project_id (models.py:574). */
  public var agentProjectId: String?
    get() = _agentProjectId
    set(value) {
      if (geoStateHook("agent_project_id", value)) return
      _agentProjectId = value
      bumpRevision()
    }

  private var _agentBufferSize: Int = 100

  /** python_name: agent_buffer_size (models.py:578). */
  public var agentBufferSize: Int
    get() = _agentBufferSize
    set(value) {
      if (geoStateHook("agent_buffer_size", value)) return
      _agentBufferSize = value
      bumpRevision()
    }

  private var _agentFlushInterval: Int = 30

  /** python_name: agent_flush_interval (models.py:582). */
  public var agentFlushInterval: Int
    get() = _agentFlushInterval
    set(value) {
      if (geoStateHook("agent_flush_interval", value)) return
      _agentFlushInterval = value
      bumpRevision()
    }

  private var _agentEnableEvents: Boolean = true

  /** python_name: agent_enable_events (models.py:586). */
  public var agentEnableEvents: Boolean
    get() = _agentEnableEvents
    set(value) {
      if (geoStateHook("agent_enable_events", value)) return
      _agentEnableEvents = value
      bumpRevision()
    }

  private var _agentEnableMetrics: Boolean = true

  /** python_name: agent_enable_metrics (models.py:590). */
  public var agentEnableMetrics: Boolean
    get() = _agentEnableMetrics
    set(value) {
      if (geoStateHook("agent_enable_metrics", value)) return
      _agentEnableMetrics = value
      bumpRevision()
    }

  private var _agentTimeout: Int = 30

  /** python_name: agent_timeout (models.py:594). */
  public var agentTimeout: Int
    get() = _agentTimeout
    set(value) {
      if (geoStateHook("agent_timeout", value)) return
      _agentTimeout = value
      bumpRevision()
    }

  private var _agentRetryAttempts: Int = 3

  /** python_name: agent_retry_attempts (models.py:598). */
  public var agentRetryAttempts: Int
    get() = _agentRetryAttempts
    set(value) {
      if (geoStateHook("agent_retry_attempts", value)) return
      _agentRetryAttempts = value
      bumpRevision()
    }

  private var _agentProjectEncryptionKey: String? = null

  /** python_name: agent_project_encryption_key (models.py:602). */
  public var agentProjectEncryptionKey: String?
    get() = _agentProjectEncryptionKey
    set(value) {
      if (geoStateHook("agent_project_encryption_key", value)) return
      _agentProjectEncryptionKey = value
      bumpRevision()
    }

  private var _agentGuardVersion: String? = null

  /** python_name: agent_guard_version (models.py:612). */
  public var agentGuardVersion: String?
    get() = _agentGuardVersion
    set(value) {
      if (geoStateHook("agent_guard_version", value)) return
      _agentGuardVersion = value
      bumpRevision()
    }

  private var _agentHighWatermarkRatio: Double? = null

  /** python_name: agent_high_watermark_ratio (models.py:622). */
  public var agentHighWatermarkRatio: Double?
    get() = _agentHighWatermarkRatio
    set(value) {
      if (geoStateHook("agent_high_watermark_ratio", value)) return
      _agentHighWatermarkRatio = value
      bumpRevision()
    }

  private var _agentMaxConcurrentFlushes: Int? = null

  /** python_name: agent_max_concurrent_flushes (models.py:630). */
  public var agentMaxConcurrentFlushes: Int?
    get() = _agentMaxConcurrentFlushes
    set(value) {
      if (geoStateHook("agent_max_concurrent_flushes", value)) return
      _agentMaxConcurrentFlushes = value
      bumpRevision()
    }

  private var _agentBufferOverflowPolicy: BufferOverflowPolicy? = null

  /** python_name: agent_buffer_overflow_policy (models.py:638). */
  public var agentBufferOverflowPolicy: BufferOverflowPolicy?
    get() = _agentBufferOverflowPolicy
    set(value) {
      if (geoStateHook("agent_buffer_overflow_policy", value)) return
      _agentBufferOverflowPolicy = value
      bumpRevision()
    }

  private var _agentBackoffFactor: Double? = null

  /** python_name: agent_backoff_factor (models.py:649). */
  public var agentBackoffFactor: Double?
    get() = _agentBackoffFactor
    set(value) {
      if (geoStateHook("agent_backoff_factor", value)) return
      _agentBackoffFactor = value
      bumpRevision()
    }

  private var _agentSensitiveHeaders: List<String>? = null

  /** python_name: agent_sensitive_headers (models.py:657). */
  public var agentSensitiveHeaders: List<String>?
    get() = _agentSensitiveHeaders
    set(value) {
      val validated = ConfigValidators.validateOptionalStrList(value, "agent_sensitive_headers")
      if (geoStateHook("agent_sensitive_headers", validated)) return
      _agentSensitiveHeaders = validated
      bumpRevision()
    }

  private var _agentMaxPayloadSize: Int? = null

  /** python_name: agent_max_payload_size (models.py:665). */
  public var agentMaxPayloadSize: Int?
    get() = _agentMaxPayloadSize
    set(value) {
      if (geoStateHook("agent_max_payload_size", value)) return
      _agentMaxPayloadSize = value
      bumpRevision()
    }

  private var _agentCompressionEnabled: Boolean? = null

  /** python_name: agent_compression_enabled (models.py:673). */
  public var agentCompressionEnabled: Boolean?
    get() = _agentCompressionEnabled
    set(value) {
      if (geoStateHook("agent_compression_enabled", value)) return
      _agentCompressionEnabled = value
      bumpRevision()
    }

  private var _agentCompressionThreshold: Int? = null

  /** python_name: agent_compression_threshold (models.py:682). */
  public var agentCompressionThreshold: Int?
    get() = _agentCompressionThreshold
    set(value) {
      if (geoStateHook("agent_compression_threshold", value)) return
      _agentCompressionThreshold = value
      bumpRevision()
    }

  private var _agentInstallId: String? = null

  /** python_name: agent_install_id (models.py:690). */
  public var agentInstallId: String?
    get() = _agentInstallId
    set(value) {
      if (geoStateHook("agent_install_id", value)) return
      _agentInstallId = value
      bumpRevision()
    }

  private var _agentPayloadSigningSecret: String? = null

  /** python_name: agent_payload_signing_secret (models.py:698). */
  public var agentPayloadSigningSecret: String?
    get() = _agentPayloadSigningSecret
    set(value) {
      if (geoStateHook("agent_payload_signing_secret", value)) return
      _agentPayloadSigningSecret = value
      bumpRevision()
    }

  private var _enableDynamicRules: Boolean = false

  /** python_name: enable_dynamic_rules (models.py:703). */
  public var enableDynamicRules: Boolean
    get() = _enableDynamicRules
    set(value) {
      if (geoStateHook("enable_dynamic_rules", value)) return
      _enableDynamicRules = value
      bumpRevision()
    }

  private var _dynamicRuleInterval: Int = 300

  /** python_name: dynamic_rule_interval (models.py:707). */
  public var dynamicRuleInterval: Int
    get() = _dynamicRuleInterval
    set(value) {
      if (geoStateHook("dynamic_rule_interval", value)) return
      _dynamicRuleInterval = value
      bumpRevision()
    }

  private var _dynamicRulesCachePath: Path? = null

  /** python_name: dynamic_rules_cache_path (models.py:713). */
  public var dynamicRulesCachePath: Path?
    get() = _dynamicRulesCachePath
    set(value) {
      val validated = ConfigValidators.validateDynamicRulesCachePathValue(value)
      if (geoStateHook("dynamic_rules_cache_path", validated)) return
      _dynamicRulesCachePath = validated
      bumpRevision()
    }

  private var _agentStatusInterval: Int = 300

  /** python_name: agent_status_interval (models.py:722). */
  public var agentStatusInterval: Int
    get() = _agentStatusInterval
    set(value) {
      if (geoStateHook("agent_status_interval", value)) return
      _agentStatusInterval = value
      bumpRevision()
    }

  private var _emergencyMode: Boolean = false

  /** python_name: emergency_mode (models.py:729). */
  public var emergencyMode: Boolean
    get() = _emergencyMode
    set(value) {
      val validated = ConfigValidators.validateBoolFieldValue(value, "emergency_mode")
      if (geoStateHook("emergency_mode", validated)) return
      _emergencyMode = validated
      bumpRevision()
    }

  private var _emergencyWhitelist: List<String> = emptyList()

  /** python_name: emergency_whitelist (models.py:733). */
  public var emergencyWhitelist: List<String>
    get() = _emergencyWhitelist
    set(value) {
      val validated = ConfigValidators.validateStrListFieldValue(value, "emergency_whitelist")
      if (geoStateHook("emergency_whitelist", validated)) return
      _emergencyWhitelist = validated
      bumpRevision()
    }

  private var _endpointRateLimits: Map<String, Pair<Int, Int>> = emptyMap()

  /** python_name: endpoint_rate_limits (models.py:738). */
  public var endpointRateLimits: Map<String, Pair<Int, Int>>
    get() = _endpointRateLimits
    set(value) {
      val validated = ConfigValidators.validateEndpointRateLimitsValue(value)
      if (geoStateHook("endpoint_rate_limits", validated)) return
      _endpointRateLimits = validated
      bumpRevision()
    }

  private var _detectionCompilerTimeout: Double = 2.0

  /** python_name: detection_compiler_timeout (models.py:743). */
  public var detectionCompilerTimeout: Double
    get() = _detectionCompilerTimeout
    set(value) {
      if (geoStateHook("detection_compiler_timeout", value)) return
      _detectionCompilerTimeout = value
      bumpRevision()
    }

  private var _detectionPatternValidationCachePath: String? = null

  /** python_name: detection_pattern_validation_cache_path (models.py:750). */
  public var detectionPatternValidationCachePath: String?
    get() = _detectionPatternValidationCachePath
    set(value) {
      if (geoStateHook("detection_pattern_validation_cache_path", value)) return
      _detectionPatternValidationCachePath = value
      bumpRevision()
    }

  private var _detectionMaxContentLength: Int = 10000

  /** python_name: detection_max_content_length (models.py:768). */
  public var detectionMaxContentLength: Int
    get() = _detectionMaxContentLength
    set(value) {
      if (geoStateHook("detection_max_content_length", value)) return
      _detectionMaxContentLength = value
      bumpRevision()
    }

  private var _detectionMaxBodyInspectBytes: Int = 262144

  /** python_name: detection_max_body_inspect_bytes (models.py:783). */
  public var detectionMaxBodyInspectBytes: Int
    get() = _detectionMaxBodyInspectBytes
    set(value) {
      if (geoStateHook("detection_max_body_inspect_bytes", value)) return
      _detectionMaxBodyInspectBytes = value
      bumpRevision()
    }

  private var _detectionMaxScanValues: Int = 512

  /** python_name: detection_max_scan_values (models.py:814). */
  public var detectionMaxScanValues: Int
    get() = _detectionMaxScanValues
    set(value) {
      if (geoStateHook("detection_max_scan_values", value)) return
      _detectionMaxScanValues = value
      bumpRevision()
    }

  private var _detectionMaxScanChars: Int = 65536

  /** python_name: detection_max_scan_chars (models.py:833). */
  public var detectionMaxScanChars: Int
    get() = _detectionMaxScanChars
    set(value) {
      if (geoStateHook("detection_max_scan_chars", value)) return
      _detectionMaxScanChars = value
      bumpRevision()
    }

  private var _detectionMaxJsonDepth: Int = 32

  /** python_name: detection_max_json_depth (models.py:853). */
  public var detectionMaxJsonDepth: Int
    get() = _detectionMaxJsonDepth
    set(value) {
      if (geoStateHook("detection_max_json_depth", value)) return
      _detectionMaxJsonDepth = value
      bumpRevision()
    }

  private var _detectionBinaryMinRunLength: Int = 16

  /** python_name: detection_binary_min_run_length (models.py:871). */
  public var detectionBinaryMinRunLength: Int
    get() = _detectionBinaryMinRunLength
    set(value) {
      if (geoStateHook("detection_binary_min_run_length", value)) return
      _detectionBinaryMinRunLength = value
      bumpRevision()
    }

  private var _detectionPreserveAttackPatterns: Boolean = true

  /** python_name: detection_preserve_attack_patterns (models.py:899). */
  public var detectionPreserveAttackPatterns: Boolean
    get() = _detectionPreserveAttackPatterns
    set(value) {
      if (geoStateHook("detection_preserve_attack_patterns", value)) return
      _detectionPreserveAttackPatterns = value
      bumpRevision()
    }

  private var _detectionSemanticThreshold: Double = 0.7

  /** python_name: detection_semantic_threshold (models.py:904). */
  public var detectionSemanticThreshold: Double
    get() = _detectionSemanticThreshold
    set(value) {
      if (geoStateHook("detection_semantic_threshold", value)) return
      _detectionSemanticThreshold = value
      bumpRevision()
    }

  private var _detectionAnomalyThreshold: Double = 3.0

  /** python_name: detection_anomaly_threshold (models.py:911). */
  public var detectionAnomalyThreshold: Double
    get() = _detectionAnomalyThreshold
    set(value) {
      if (geoStateHook("detection_anomaly_threshold", value)) return
      _detectionAnomalyThreshold = value
      bumpRevision()
    }

  private var _detectionSlowPatternThreshold: Double = 0.1

  /** python_name: detection_slow_pattern_threshold (models.py:918). */
  public var detectionSlowPatternThreshold: Double
    get() = _detectionSlowPatternThreshold
    set(value) {
      if (geoStateHook("detection_slow_pattern_threshold", value)) return
      _detectionSlowPatternThreshold = value
      bumpRevision()
    }

  private var _detectionMonitorHistorySize: Int = 1000

  /** python_name: detection_monitor_history_size (models.py:925). */
  public var detectionMonitorHistorySize: Int
    get() = _detectionMonitorHistorySize
    set(value) {
      if (geoStateHook("detection_monitor_history_size", value)) return
      _detectionMonitorHistorySize = value
      bumpRevision()
    }

  private var _detectionMaxTrackedPatterns: Int = 1000

  /** python_name: detection_max_tracked_patterns (models.py:932). */
  public var detectionMaxTrackedPatterns: Int
    get() = _detectionMaxTrackedPatterns
    set(value) {
      if (geoStateHook("detection_max_tracked_patterns", value)) return
      _detectionMaxTrackedPatterns = value
      bumpRevision()
    }

  private var _detectionAnomalyEmissionCooldown: Double = 60.0

  /** python_name: detection_anomaly_emission_cooldown (models.py:939). */
  public var detectionAnomalyEmissionCooldown: Double
    get() = _detectionAnomalyEmissionCooldown
    set(value) {
      if (geoStateHook("detection_anomaly_emission_cooldown", value)) return
      _detectionAnomalyEmissionCooldown = value
      bumpRevision()
    }

  private var _detectionMinSamplesForAnomaly: Int = 30

  /** python_name: detection_min_samples_for_anomaly (models.py:949). */
  public var detectionMinSamplesForAnomaly: Int
    get() = _detectionMinSamplesForAnomaly
    set(value) {
      if (geoStateHook("detection_min_samples_for_anomaly", value)) return
      _detectionMinSamplesForAnomaly = value
      bumpRevision()
    }

  private var _detectionThreatScoreThreshold: Double = 1.0

  /** python_name: detection_threat_score_threshold (models.py:959). */
  public var detectionThreatScoreThreshold: Double
    get() = _detectionThreatScoreThreshold
    set(value) {
      if (geoStateHook("detection_threat_score_threshold", value)) return
      _detectionThreatScoreThreshold = value
      bumpRevision()
    }

  private var _mutedEventTypes: Set<String> = emptySet()

  /** python_name: muted_event_types (models.py:966). */
  public var mutedEventTypes: Set<String>
    get() = _mutedEventTypes
    set(value) {
      val validated = ConfigValidators.validateMutedEventTypesValue(value)
      if (geoStateHook("muted_event_types", validated)) return
      _mutedEventTypes = validated
      bumpRevision()
    }

  private var _mutedMetricTypes: Set<String> = emptySet()

  /** python_name: muted_metric_types (models.py:971). */
  public var mutedMetricTypes: Set<String>
    get() = _mutedMetricTypes
    set(value) {
      val validated = ConfigValidators.validateMutedMetricTypesValue(value)
      if (geoStateHook("muted_metric_types", validated)) return
      _mutedMetricTypes = validated
      bumpRevision()
    }

  private var _mutedCheckLogs: Set<String> = emptySet()

  /** python_name: muted_check_logs (models.py:976). */
  public var mutedCheckLogs: Set<String>
    get() = _mutedCheckLogs
    set(value) {
      val validated = ConfigValidators.validateMutedCheckLogsValue(value)
      if (geoStateHook("muted_check_logs", validated)) return
      _mutedCheckLogs = validated
      bumpRevision()
    }

  private var _logSensitiveHeaders: Set<String> = emptySet()

  /** python_name: log_sensitive_headers (models.py:981). */
  public var logSensitiveHeaders: Set<String>
    get() = _logSensitiveHeaders
    set(value) {
      val validated = ConfigValidators.validateSensitiveNameSetValue(value, "log_sensitive_headers")
      if (geoStateHook("log_sensitive_headers", validated)) return
      _logSensitiveHeaders = validated
      bumpRevision()
    }

  private var _logSensitiveParams: Set<String> = emptySet()

  /** python_name: log_sensitive_params (models.py:989). */
  public var logSensitiveParams: Set<String>
    get() = _logSensitiveParams
    set(value) {
      val validated = ConfigValidators.validateSensitiveNameSetValue(value, "log_sensitive_params")
      if (geoStateHook("log_sensitive_params", validated)) return
      _logSensitiveParams = validated
      bumpRevision()
    }

  private var _logSensitiveBodyFields: Set<String> = emptySet()

  /** python_name: log_sensitive_body_fields (models.py:998). */
  public var logSensitiveBodyFields: Set<String>
    get() = _logSensitiveBodyFields
    set(value) {
      val validated =
          ConfigValidators.validateSensitiveNameSetValue(value, "log_sensitive_body_fields")
      if (geoStateHook("log_sensitive_body_fields", validated)) return
      _logSensitiveBodyFields = validated
      bumpRevision()
    }

  private var _enableOtel: Boolean = false

  /** python_name: enable_otel (models.py:1008). */
  public var enableOtel: Boolean
    get() = _enableOtel
    set(value) {
      if (geoStateHook("enable_otel", value)) return
      _enableOtel = value
      bumpRevision()
    }

  private var _otelServiceName: String = "guard-core"

  /** python_name: otel_service_name (models.py:1013). */
  public var otelServiceName: String
    get() = _otelServiceName
    set(value) {
      if (geoStateHook("otel_service_name", value)) return
      _otelServiceName = value
      bumpRevision()
    }

  private var _otelExporterEndpoint: String? = null

  /** python_name: otel_exporter_endpoint (models.py:1018). */
  public var otelExporterEndpoint: String?
    get() = _otelExporterEndpoint
    set(value) {
      if (geoStateHook("otel_exporter_endpoint", value)) return
      _otelExporterEndpoint = value
      bumpRevision()
    }

  private var _otelResourceAttributes: Map<String, String> = emptyMap()

  /** python_name: otel_resource_attributes (models.py:1023). */
  public var otelResourceAttributes: Map<String, String>
    get() = _otelResourceAttributes
    set(value) {
      val validated = ConfigValidators.validateStrKeyedStrDict(value, "otel_resource_attributes")
      if (geoStateHook("otel_resource_attributes", validated)) return
      _otelResourceAttributes = validated
      bumpRevision()
    }

  private var _enableLogfire: Boolean = false

  /** python_name: enable_logfire (models.py:1031). */
  public var enableLogfire: Boolean
    get() = _enableLogfire
    set(value) {
      if (geoStateHook("enable_logfire", value)) return
      _enableLogfire = value
      bumpRevision()
    }

  private var _logfireServiceName: String = "guard-core"

  /** python_name: logfire_service_name (models.py:1036). */
  public var logfireServiceName: String
    get() = _logfireServiceName
    set(value) {
      if (geoStateHook("logfire_service_name", value)) return
      _logfireServiceName = value
      bumpRevision()
    }

  private var _enableEnrichment: Boolean = false

  /** python_name: enable_enrichment (models.py:1041). */
  public var enableEnrichment: Boolean
    get() = _enableEnrichment
    set(value) {
      if (geoStateHook("enable_enrichment", value)) return
      _enableEnrichment = value
      bumpRevision()
    }

  private var _excludedDetectionHeaders: Set<String> = emptySet()

  /** python_name: excluded_detection_headers (models.py:1052). */
  public var excludedDetectionHeaders: Set<String>
    get() = _excludedDetectionHeaders
    set(value) {
      val validated = ConfigValidators.validateStrSet(value, "excluded_detection_headers")
      if (geoStateHook("excluded_detection_headers", validated)) return
      _excludedDetectionHeaders = validated
      bumpRevision()
    }

  private var _excludedDetectionParams: Set<String> = emptySet()

  /** python_name: excluded_detection_params (models.py:1061). */
  public var excludedDetectionParams: Set<String>
    get() = _excludedDetectionParams
    set(value) {
      val validated = ConfigValidators.validateStrSet(value, "excluded_detection_params")
      if (geoStateHook("excluded_detection_params", validated)) return
      _excludedDetectionParams = validated
      bumpRevision()
    }

  private var _excludedDetectionBodyFields: Set<String> = emptySet()

  /** python_name: excluded_detection_body_fields (models.py:1067). */
  public var excludedDetectionBodyFields: Set<String>
    get() = _excludedDetectionBodyFields
    set(value) {
      val validated = ConfigValidators.validateStrSet(value, "excluded_detection_body_fields")
      if (geoStateHook("excluded_detection_body_fields", validated)) return
      _excludedDetectionBodyFields = validated
      bumpRevision()
    }

  private var _detectionScanBody: Boolean = true

  /** python_name: detection_scan_body (models.py:1075). */
  public var detectionScanBody: Boolean
    get() = _detectionScanBody
    set(value) {
      if (geoStateHook("detection_scan_body", value)) return
      _detectionScanBody = value
      bumpRevision()
    }

  private var _enabledDetectionCategories: Set<String> =
      DetectionCategories.ALL_DETECTION_CATEGORIES

  /** python_name: enabled_detection_categories (models.py:1083). */
  public var enabledDetectionCategories: Set<String>
    get() = _enabledDetectionCategories
    set(value) {
      val validated = ConfigValidators.validateEnabledDetectionCategoriesValue(value)
      if (geoStateHook("enabled_detection_categories", validated)) return
      _enabledDetectionCategories = validated
      bumpRevision()
    }

  init {
    builder.applyTo(this)
    runModelValidators(builder)
    constructing = false
    revisionCounter = 0
  }

  // ---------------------------------------------- construction helpers

  internal fun setRawTrustedProxies(value: List<String>) {
    _trustedProxies = value
  }

  internal fun setRawTrustedProxyDepth(value: Int) {
    _trustedProxyDepth = value
  }

  internal fun setRawTrustXForwardedProto(value: Boolean) {
    _trustXForwardedProto = value
  }

  internal fun setRawPassiveMode(value: Boolean) {
    _passiveMode = value
  }

  internal fun setRawGeoIpHandler(value: GeoIPHandler?) {
    _geoIpHandler = value
  }

  internal fun setRawEnableRedis(value: Boolean) {
    _enableRedis = value
  }

  internal fun setRawRedisUrl(value: String?) {
    _redisUrl = value
  }

  internal fun setRawRedisPrefix(value: String) {
    _redisPrefix = value
  }

  internal fun setRawRedisSocketConnectTimeout(value: Double?) {
    _redisSocketConnectTimeout = value
  }

  internal fun setRawRedisSocketTimeout(value: Double?) {
    _redisSocketTimeout = value
  }

  internal fun setRawRedisHealthCheckInterval(value: Int) {
    _redisHealthCheckInterval = value
  }

  internal fun setRawRedisMaxConnections(value: Int?) {
    _redisMaxConnections = value
  }

  internal fun setRawRedisRetries(value: Int) {
    _redisRetries = value
  }

  internal fun setRawWhitelist(value: List<String>?) {
    _whitelist = value
  }

  internal fun setRawBlacklist(value: List<String>) {
    _blacklist = value
  }

  internal fun setRawExemptIps(value: List<String>) {
    _exemptIps = value
  }

  internal fun setRawWhitelistCountries(value: Set<String>) {
    _whitelistCountries = value
  }

  internal fun setRawBlockedCountries(value: Set<String>) {
    _blockedCountries = value
  }

  internal fun setRawBlockedUserAgents(value: List<String>) {
    _blockedUserAgents = value
  }

  internal fun setRawAutoBanThreshold(value: Int) {
    _autoBanThreshold = value
  }

  internal fun setRawAutoBanDuration(value: Int) {
    _autoBanDuration = value
  }

  internal fun setRawThreatBanConfig(value: Map<String, ThreatBanConfig>) {
    _threatBanConfig = value
  }

  internal fun setRawEnableRateLimitAutoBan(value: Boolean) {
    _enableRateLimitAutoBan = value
  }

  internal fun setRawGlobalBehaviorRules(value: List<BehaviorRuleConfig>) {
    _globalBehaviorRules = value
  }

  internal fun setRawBehaviorScanResponseBody(value: Boolean) {
    _behaviorScanResponseBody = value
  }

  internal fun setRawBehaviorMaxResponseBodyInspectBytes(value: Int) {
    _behaviorMaxResponseBodyInspectBytes = value
  }

  internal fun setRawBodyReadTimeout(value: Double) {
    _bodyReadTimeout = value
  }

  internal fun setRawSyncBodyReadMaxConcurrent(value: Int) {
    _syncBodyReadMaxConcurrent = value
  }

  internal fun setRawCustomLogFile(value: String?) {
    _customLogFile = value
  }

  internal fun setRawLogSuspiciousLevel(value: LogLevel?) {
    _logSuspiciousLevel = value
  }

  internal fun setRawLogRequestLevel(value: LogLevel?) {
    _logRequestLevel = value
  }

  internal fun setRawLogCountryCheckLevel(value: LogLevel?) {
    _logCountryCheckLevel = value
  }

  internal fun setRawLogFormat(value: LogFormat) {
    _logFormat = value
  }

  internal fun setRawCustomErrorResponses(value: Map<Int, String>) {
    _customErrorResponses = value
  }

  internal fun setRawRateLimit(value: Int) {
    _rateLimit = value
  }

  internal fun setRawRateLimitWindow(value: Int) {
    _rateLimitWindow = value
  }

  internal fun setRawEnforceHttps(value: Boolean) {
    _enforceHttps = value
  }

  internal fun setRawSecurityHeaders(value: Map<String, Any?>?) {
    _securityHeaders = value
  }

  internal fun setRawCustomRequestCheck(value: CustomRequestCheck?) {
    _customRequestCheck = value
  }

  internal fun setRawAuthVerifier(value: AuthVerifier?) {
    _authVerifier = value
  }

  internal fun setRawCustomResponseModifier(value: CustomResponseModifier?) {
    _customResponseModifier = value
  }

  internal fun setRawEnableCors(value: Boolean) {
    _enableCors = value
  }

  internal fun setRawCorsAllowOrigins(value: List<String>) {
    _corsAllowOrigins = value
  }

  internal fun setRawCorsAllowMethods(value: List<String>) {
    _corsAllowMethods = value
  }

  internal fun setRawCorsAllowHeaders(value: List<String>) {
    _corsAllowHeaders = value
  }

  internal fun setRawCorsAllowCredentials(value: Boolean) {
    _corsAllowCredentials = value
  }

  internal fun setRawCorsExposeHeaders(value: List<String>) {
    _corsExposeHeaders = value
  }

  internal fun setRawCorsMaxAge(value: Int) {
    _corsMaxAge = value
  }

  internal fun setRawBlockCloudProviders(value: Set<String>?) {
    _blockCloudProviders = value
  }

  internal fun setRawCloudIpRefreshInterval(value: Int) {
    _cloudIpRefreshInterval = value
  }

  internal fun setRawLazyInit(value: Boolean) {
    _lazyInit = value
  }

  internal fun setRawGeoIpDbMaxAge(value: Int) {
    _geoIpDbMaxAge = value
  }

  internal fun setRawCloudIpStore(value: Any?) {
    _cloudIpStore = value
  }

  internal fun setRawExcludePaths(value: List<String>) {
    _excludePaths = value
  }

  internal fun setRawEnableIpBanning(value: Boolean) {
    _enableIpBanning = value
  }

  internal fun setRawEnableRateLimiting(value: Boolean) {
    _enableRateLimiting = value
  }

  internal fun setRawEnablePenetrationDetection(value: Boolean) {
    _enablePenetrationDetection = value
  }

  internal fun setRawFailSecure(value: Boolean) {
    _failSecure = value
  }

  internal fun setRawRedisFailOpen(value: Boolean) {
    _redisFailOpen = value
  }

  internal fun setRawRouteResolutionStrict(value: Boolean) {
    _routeResolutionStrict = value
  }

  internal fun setRawIpinfoToken(value: String?) {
    _ipinfoToken = value
  }

  internal fun setRawIpinfoDbPath(value: Path?) {
    _ipinfoDbPath = value
  }

  internal fun setRawEnableAgent(value: Boolean) {
    _enableAgent = value
  }

  internal fun setRawAgentApiKey(value: String?) {
    _agentApiKey = value
  }

  internal fun setRawAgentStrict(value: Boolean) {
    _agentStrict = value
  }

  internal fun setRawOnError(value: OnErrorHook?) {
    _onError = value
  }

  internal fun setRawOnBlock(value: BlockHook?) {
    _onBlock = value
  }

  internal fun setRawAgentEndpoint(value: String) {
    _agentEndpoint = value
  }

  internal fun setRawAgentProjectId(value: String?) {
    _agentProjectId = value
  }

  internal fun setRawAgentBufferSize(value: Int) {
    _agentBufferSize = value
  }

  internal fun setRawAgentFlushInterval(value: Int) {
    _agentFlushInterval = value
  }

  internal fun setRawAgentEnableEvents(value: Boolean) {
    _agentEnableEvents = value
  }

  internal fun setRawAgentEnableMetrics(value: Boolean) {
    _agentEnableMetrics = value
  }

  internal fun setRawAgentTimeout(value: Int) {
    _agentTimeout = value
  }

  internal fun setRawAgentRetryAttempts(value: Int) {
    _agentRetryAttempts = value
  }

  internal fun setRawAgentProjectEncryptionKey(value: String?) {
    _agentProjectEncryptionKey = value
  }

  internal fun setRawAgentGuardVersion(value: String?) {
    _agentGuardVersion = value
  }

  internal fun setRawAgentHighWatermarkRatio(value: Double?) {
    _agentHighWatermarkRatio = value
  }

  internal fun setRawAgentMaxConcurrentFlushes(value: Int?) {
    _agentMaxConcurrentFlushes = value
  }

  internal fun setRawAgentBufferOverflowPolicy(value: BufferOverflowPolicy?) {
    _agentBufferOverflowPolicy = value
  }

  internal fun setRawAgentBackoffFactor(value: Double?) {
    _agentBackoffFactor = value
  }

  internal fun setRawAgentSensitiveHeaders(value: List<String>?) {
    _agentSensitiveHeaders = value
  }

  internal fun setRawAgentMaxPayloadSize(value: Int?) {
    _agentMaxPayloadSize = value
  }

  internal fun setRawAgentCompressionEnabled(value: Boolean?) {
    _agentCompressionEnabled = value
  }

  internal fun setRawAgentCompressionThreshold(value: Int?) {
    _agentCompressionThreshold = value
  }

  internal fun setRawAgentInstallId(value: String?) {
    _agentInstallId = value
  }

  internal fun setRawAgentPayloadSigningSecret(value: String?) {
    _agentPayloadSigningSecret = value
  }

  internal fun setRawEnableDynamicRules(value: Boolean) {
    _enableDynamicRules = value
  }

  internal fun setRawDynamicRuleInterval(value: Int) {
    _dynamicRuleInterval = value
  }

  internal fun setRawDynamicRulesCachePath(value: Path?) {
    _dynamicRulesCachePath = value
  }

  internal fun setRawAgentStatusInterval(value: Int) {
    _agentStatusInterval = value
  }

  internal fun setRawEmergencyMode(value: Boolean) {
    _emergencyMode = value
  }

  internal fun setRawEmergencyWhitelist(value: List<String>) {
    _emergencyWhitelist = value
  }

  internal fun setRawEndpointRateLimits(value: Map<String, Pair<Int, Int>>) {
    _endpointRateLimits = value
  }

  internal fun setRawDetectionCompilerTimeout(value: Double) {
    _detectionCompilerTimeout = value
  }

  internal fun setRawDetectionPatternValidationCachePath(value: String?) {
    _detectionPatternValidationCachePath = value
  }

  internal fun setRawDetectionMaxContentLength(value: Int) {
    _detectionMaxContentLength = value
  }

  internal fun setRawDetectionMaxBodyInspectBytes(value: Int) {
    _detectionMaxBodyInspectBytes = value
  }

  internal fun setRawDetectionMaxScanValues(value: Int) {
    _detectionMaxScanValues = value
  }

  internal fun setRawDetectionMaxScanChars(value: Int) {
    _detectionMaxScanChars = value
  }

  internal fun setRawDetectionMaxJsonDepth(value: Int) {
    _detectionMaxJsonDepth = value
  }

  internal fun setRawDetectionBinaryMinRunLength(value: Int) {
    _detectionBinaryMinRunLength = value
  }

  internal fun setRawDetectionPreserveAttackPatterns(value: Boolean) {
    _detectionPreserveAttackPatterns = value
  }

  internal fun setRawDetectionSemanticThreshold(value: Double) {
    _detectionSemanticThreshold = value
  }

  internal fun setRawDetectionAnomalyThreshold(value: Double) {
    _detectionAnomalyThreshold = value
  }

  internal fun setRawDetectionSlowPatternThreshold(value: Double) {
    _detectionSlowPatternThreshold = value
  }

  internal fun setRawDetectionMonitorHistorySize(value: Int) {
    _detectionMonitorHistorySize = value
  }

  internal fun setRawDetectionMaxTrackedPatterns(value: Int) {
    _detectionMaxTrackedPatterns = value
  }

  internal fun setRawDetectionAnomalyEmissionCooldown(value: Double) {
    _detectionAnomalyEmissionCooldown = value
  }

  internal fun setRawDetectionMinSamplesForAnomaly(value: Int) {
    _detectionMinSamplesForAnomaly = value
  }

  internal fun setRawDetectionThreatScoreThreshold(value: Double) {
    _detectionThreatScoreThreshold = value
  }

  internal fun setRawMutedEventTypes(value: Set<String>) {
    _mutedEventTypes = value
  }

  internal fun setRawMutedMetricTypes(value: Set<String>) {
    _mutedMetricTypes = value
  }

  internal fun setRawMutedCheckLogs(value: Set<String>) {
    _mutedCheckLogs = value
  }

  internal fun setRawLogSensitiveHeaders(value: Set<String>) {
    _logSensitiveHeaders = value
  }

  internal fun setRawLogSensitiveParams(value: Set<String>) {
    _logSensitiveParams = value
  }

  internal fun setRawLogSensitiveBodyFields(value: Set<String>) {
    _logSensitiveBodyFields = value
  }

  internal fun setRawEnableOtel(value: Boolean) {
    _enableOtel = value
  }

  internal fun setRawOtelServiceName(value: String) {
    _otelServiceName = value
  }

  internal fun setRawOtelExporterEndpoint(value: String?) {
    _otelExporterEndpoint = value
  }

  internal fun setRawOtelResourceAttributes(value: Map<String, String>) {
    _otelResourceAttributes = value
  }

  internal fun setRawEnableLogfire(value: Boolean) {
    _enableLogfire = value
  }

  internal fun setRawLogfireServiceName(value: String) {
    _logfireServiceName = value
  }

  internal fun setRawEnableEnrichment(value: Boolean) {
    _enableEnrichment = value
  }

  internal fun setRawExcludedDetectionHeaders(value: Set<String>) {
    _excludedDetectionHeaders = value
  }

  internal fun setRawExcludedDetectionParams(value: Set<String>) {
    _excludedDetectionParams = value
  }

  internal fun setRawExcludedDetectionBodyFields(value: Set<String>) {
    _excludedDetectionBodyFields = value
  }

  internal fun setRawDetectionScanBody(value: Boolean) {
    _detectionScanBody = value
  }

  internal fun setRawEnabledDetectionCategories(value: Set<String>) {
    _enabledDetectionCategories = value
  }

  // ------------------------------------------------- setattr pipeline

  /**
   * Geo-state hook of `__setattr__` (models.py:99-100): for `_GEO_STATE_FIELDS` the assignment
   * resolves the geo handler first. When `skipGeoHook` is set the caller already ran it
   * (geo_ip_handler case).
   */
  private fun geoStateHook(name: String, value: Any?, skipGeoHook: Boolean = false): Boolean {
    if (skipGeoHook) return false
    if (name !in ConfigFieldRegistry.geoStateFieldNames) return false
    applyGeoIpHandlerAssignment(name, value)
    return false
  }

  /** Port of `_apply_geo_ip_handler_assignment` (_security_config_geo_validators.py:97-113). */
  private fun applyGeoIpHandlerAssignment(name: String, value: Any?): Any? {
    val blocked = if (name == "blocked_countries") value as? Set<String> else _blockedCountries
    val whitelist =
        if (name == "whitelist_countries") value as? Set<String> else _whitelistCountries
    val handler = if (name == "geo_ip_handler") value as? GeoIPHandler else _geoIpHandler
    val token = if (name == "ipinfo_token") value as? String else _ipinfoToken
    val resolved =
        resolveGeoIpHandler(
            blockedCountries = blocked,
            whitelistCountries = whitelist,
            geoIpHandler = handler,
            ipinfoToken = token,
            ipinfoDbPath = _ipinfoDbPath,
            geoIpDbMaxAge = _geoIpDbMaxAge,
        )
    if (name == "geo_ip_handler") return resolved
    if (resolved !== handler) _geoIpHandler = resolved
    return value
  }

  /**
   * Port of `_resolve_geo_ip_handler` (_security_config_geo_validators.py:69-94). The IPInfoManager
   * construction goes through `ConfigSeams.geoIpHandlerFactory`, registered by the W3 handlers
   * wave.
   */
  private fun resolveGeoIpHandler(
      blockedCountries: Set<String>?,
      whitelistCountries: Set<String>?,
      geoIpHandler: GeoIPHandler?,
      ipinfoToken: String?,
      ipinfoDbPath: Path?,
      geoIpDbMaxAge: Int,
  ): GeoIPHandler? {
    val hasCountryRules = !blockedCountries.isNullOrEmpty() || !whitelistCountries.isNullOrEmpty()
    if (geoIpHandler == null && hasCountryRules) {
      if (ipinfoToken.isNullOrEmpty()) {
        throw ConfigValidationError(
            "geo_ip_handler is required " + "if blocked_countries or whitelist_countries is set",
        )
      }
      val factory =
          ConfigSeams.geoIpHandlerFactory
              ?: throw ConfigValidationError(
                  "geo_ip_handler is required " +
                      "if blocked_countries or whitelist_countries is set",
              )
      return factory(ipinfoToken, ipinfoDbPath, geoIpDbMaxAge)
    }
    return geoIpHandler
  }

  /** Global behavior rule hook of `__setattr__` (models.py:103-104). */
  private fun globalBehaviorRuleHook(name: String, value: Any?): Boolean {
    if (name !in ConfigFieldRegistry.globalBehaviorRuleFieldNames) return false
    ConfigValidators.validateGlobalBehaviorRuleAssignment(this, name, value)
    return false
  }

  /** Port of `_country_shadow_should_warn` (_security_config_geo_validators.py:36). */
  private fun countryShadowShouldWarn(name: String, value: Any?): Boolean {
    if (name != "whitelist_countries" && name != "blocked_countries") return false
    val newWhitelist =
        (if (name == "whitelist_countries") value else _whitelistCountries) as? Set<String>
    val newBlocked = (if (name == "blocked_countries") value else _blockedCountries) as? Set<String>
    if (newWhitelist.isNullOrEmpty() || newBlocked.isNullOrEmpty()) return false
    return ConfigValidators.normalizedCountryValue(value) !=
        ConfigValidators.normalizedCountryValue(currentCountryValue(name))
  }

  private fun currentCountryValue(name: String): Any? =
      if (name == "whitelist_countries") _whitelistCountries else _blockedCountries

  private fun warnCountryShadow() {
    ConfigWarnings.warn(
        "blocked_countries is ignored when whitelist_countries is " +
            "non-empty: a non-empty whitelist_countries is restrictive " +
            "(only listed countries pass), so blocked_countries has no " +
            "effect. Use one or the other.",
    )
  }

  // --------------------------------------------------- model validators

  private fun runModelValidators(builder: SecurityConfigBuilder) {
    // model_validator 1: validate_optional_extras_installed (models.py:182).
    // The redis/aiohttp/maxminddb extras are pip packaging gates; the JVM
    // artifact has no optional extras, so the check is inert here
    // (documented in docs/w1-config-parity.md).

    // model_validator 2: validate_geo_ip_handler_exists (models.py:206).
    val resolved =
        resolveGeoIpHandler(
            blockedCountries = _blockedCountries,
            whitelistCountries = _whitelistCountries,
            geoIpHandler = _geoIpHandler,
            ipinfoToken = _ipinfoToken,
            ipinfoDbPath = _ipinfoDbPath,
            geoIpDbMaxAge = _geoIpDbMaxAge,
        )
    if (resolved !== _geoIpHandler) _geoIpHandler = resolved

    // model_validator 3: warn_country_allowlist_shadows_blocklist (models.py:221).
    if (_whitelistCountries.isNotEmpty() && _blockedCountries.isNotEmpty()) {
      warnCountryShadow()
    }

    // model_validator 4: validate_agent_config (models.py:227).
    if (_enableAgent && _agentApiKey.isNullOrEmpty()) {
      throw ConfigValidationError("agent_api_key is required when enable_agent is True")
    }
    if (_enableDynamicRules && !_enableAgent) {
      throw ConfigValidationError(
          "enable_agent must be True when enable_dynamic_rules is True",
      )
    }
    if (_enableEnrichment && !_enableAgent) {
      throw ConfigValidationError(
          "enable_enrichment requires enable_agent=True; enrichment is " +
              "the guard-agent-gated tier. Either enable guard-agent or set " +
              "enable_enrichment=False.",
      )
    }

    // model_validator 5: validate_global_return_pattern_body_scan (models.py:246).
    for (rule in _globalBehaviorRules) {
      if (rule.ruleType != RuleType.RETURN_PATTERN || rule.pattern == null) continue
      ConfigValidators.validateReturnPatternBodyScan(rule.pattern, this)
    }

    // model_validator 6: warn_trusted_proxies_prefix_zero (models.py:254).
    if (_trustedProxies.any { ConfigValidators.isPrefixZeroNetworkEntry(it) }) {
      ConfigValidators.warnTrustedProxiesPrefixZero()
    }

    // model_validator 7: warn_whitelist_prefix_zero (models.py:260).
    if (_whitelist.orEmpty().any { ConfigValidators.isPrefixZeroNetworkEntry(it) }) {
      ConfigValidators.warnWhitelistPrefixZero()
    }

    // model_validator 8: warn_exempt_ips_prefix_zero (models.py:266).
    ConfigValidators.warnExemptIpsPrefixZero(_exemptIps)

    // model_validator 9: warn_empty_enabled_detection_categories (models.py:271).
    if (_enablePenetrationDetection && _enabledDetectionCategories.isEmpty()) {
      ConfigValidators.warnEmptyEnabledDetectionCategories()
    }
  }

  // ---------------------------------------------------------- revision

  /** Port of `SecurityConfig.revision` (models.py:121-123). */
  public val revision: Int
    get() = revisionCounter

  /**
   * Port of `_set_prevalidated` (models.py:114): assign without running the field revalidator
   * (geo-state and global-rule hooks still run, matching `__setattr__`'s skip semantics).
   */
  public fun setPrevalidated(name: String, value: Any?) {
    val token = skipRevalidation
    skipRevalidation = true
    try {
      assignByName(name, value)
    } finally {
      skipRevalidation = token
    }
  }

  private var skipRevalidation: Boolean = false

  private var revisionBumpSuppressed: Boolean = false

  private fun bumpRevision() {
    if (!constructing && !revisionBumpSuppressed) revisionCounter += 1
  }

  /**
   * Raw assignment mirroring pydantic's `__dict__` update inside `model_copy`: no revalidator, no
   * revision bump; the geo-state and global-rule hooks run as in `__setattr__`.
   */
  internal fun rawAssign(name: String, value: Any?) {
    val suppress = revisionBumpSuppressed
    revisionBumpSuppressed = true
    try {
      setPrevalidated(name, value)
    } finally {
      revisionBumpSuppressed = suppress
    }
  }

  /** Dispatch a named assignment through the matching property setter. */
  internal fun assignByName(name: String, value: Any?) {
    when (name) {
      "trusted_proxies" -> trustedProxies = value as List<String>
      "trusted_proxy_depth" -> trustedProxyDepth = value as Int
      "trust_x_forwarded_proto" -> trustXForwardedProto = value as Boolean
      "passive_mode" -> passiveMode = value as Boolean
      "geo_ip_handler" -> geoIpHandler = value as GeoIPHandler?
      "enable_redis" -> enableRedis = value as Boolean
      "redis_url" -> redisUrl = value as String?
      "redis_prefix" -> redisPrefix = value as String
      "redis_socket_connect_timeout" -> redisSocketConnectTimeout = value as Double?
      "redis_socket_timeout" -> redisSocketTimeout = value as Double?
      "redis_health_check_interval" -> redisHealthCheckInterval = value as Int
      "redis_max_connections" -> redisMaxConnections = value as Int?
      "redis_retries" -> redisRetries = value as Int
      "whitelist" -> whitelist = value as List<String>?
      "blacklist" -> blacklist = value as List<String>
      "exempt_ips" -> exemptIps = value as List<String>
      "whitelist_countries" -> whitelistCountries = value as Set<String>
      "blocked_countries" -> blockedCountries = value as Set<String>
      "blocked_user_agents" -> blockedUserAgents = value as List<String>
      "auto_ban_threshold" -> autoBanThreshold = value as Int
      "auto_ban_duration" -> autoBanDuration = value as Int
      "threat_ban_config" -> threatBanConfig = value as Map<String, ThreatBanConfig>
      "enable_rate_limit_auto_ban" -> enableRateLimitAutoBan = value as Boolean
      "global_behavior_rules" -> globalBehaviorRules = value as List<BehaviorRuleConfig>
      "behavior_scan_response_body" -> behaviorScanResponseBody = value as Boolean
      "behavior_max_response_body_inspect_bytes" ->
          behaviorMaxResponseBodyInspectBytes = value as Int
      "body_read_timeout" -> bodyReadTimeout = value as Double
      "sync_body_read_max_concurrent" -> syncBodyReadMaxConcurrent = value as Int
      "custom_log_file" -> customLogFile = value as String?
      "log_suspicious_level" -> logSuspiciousLevel = value as LogLevel?
      "log_request_level" -> logRequestLevel = value as LogLevel?
      "log_country_check_level" -> logCountryCheckLevel = value as LogLevel?
      "log_format" -> logFormat = value as LogFormat
      "custom_error_responses" -> customErrorResponses = value as Map<Int, String>
      "rate_limit" -> rateLimit = value as Int
      "rate_limit_window" -> rateLimitWindow = value as Int
      "enforce_https" -> enforceHttps = value as Boolean
      "security_headers" -> securityHeaders = value as Map<String, Any?>?
      "custom_request_check" -> customRequestCheck = value as CustomRequestCheck?
      "auth_verifier" -> authVerifier = value as AuthVerifier?
      "custom_response_modifier" -> customResponseModifier = value as CustomResponseModifier?
      "enable_cors" -> enableCors = value as Boolean
      "cors_allow_origins" -> corsAllowOrigins = value as List<String>
      "cors_allow_methods" -> corsAllowMethods = value as List<String>
      "cors_allow_headers" -> corsAllowHeaders = value as List<String>
      "cors_allow_credentials" -> corsAllowCredentials = value as Boolean
      "cors_expose_headers" -> corsExposeHeaders = value as List<String>
      "cors_max_age" -> corsMaxAge = value as Int
      "block_cloud_providers" -> blockCloudProviders = value as Set<String>?
      "cloud_ip_refresh_interval" -> cloudIpRefreshInterval = value as Int
      "lazy_init" -> lazyInit = value as Boolean
      "geo_ip_db_max_age" -> geoIpDbMaxAge = value as Int
      "cloud_ip_store" -> cloudIpStore = value
      "exclude_paths" -> excludePaths = value as List<String>
      "enable_ip_banning" -> enableIpBanning = value as Boolean
      "enable_rate_limiting" -> enableRateLimiting = value as Boolean
      "enable_penetration_detection" -> enablePenetrationDetection = value as Boolean
      "fail_secure" -> failSecure = value as Boolean
      "redis_fail_open" -> redisFailOpen = value as Boolean
      "route_resolution_strict" -> routeResolutionStrict = value as Boolean
      "ipinfo_token" -> ipinfoToken = value as String?
      "ipinfo_db_path" -> ipinfoDbPath = value as Path?
      "enable_agent" -> enableAgent = value as Boolean
      "agent_api_key" -> agentApiKey = value as String?
      "agent_strict" -> agentStrict = value as Boolean
      "on_error" -> onError = value as OnErrorHook?
      "on_block" -> onBlock = value as BlockHook?
      "agent_endpoint" -> agentEndpoint = value as String
      "agent_project_id" -> agentProjectId = value as String?
      "agent_buffer_size" -> agentBufferSize = value as Int
      "agent_flush_interval" -> agentFlushInterval = value as Int
      "agent_enable_events" -> agentEnableEvents = value as Boolean
      "agent_enable_metrics" -> agentEnableMetrics = value as Boolean
      "agent_timeout" -> agentTimeout = value as Int
      "agent_retry_attempts" -> agentRetryAttempts = value as Int
      "agent_project_encryption_key" -> agentProjectEncryptionKey = value as String?
      "agent_guard_version" -> agentGuardVersion = value as String?
      "agent_high_watermark_ratio" -> agentHighWatermarkRatio = value as Double?
      "agent_max_concurrent_flushes" -> agentMaxConcurrentFlushes = value as Int?
      "agent_buffer_overflow_policy" -> agentBufferOverflowPolicy = value as BufferOverflowPolicy?
      "agent_backoff_factor" -> agentBackoffFactor = value as Double?
      "agent_sensitive_headers" -> agentSensitiveHeaders = value as List<String>?
      "agent_max_payload_size" -> agentMaxPayloadSize = value as Int?
      "agent_compression_enabled" -> agentCompressionEnabled = value as Boolean?
      "agent_compression_threshold" -> agentCompressionThreshold = value as Int?
      "agent_install_id" -> agentInstallId = value as String?
      "agent_payload_signing_secret" -> agentPayloadSigningSecret = value as String?
      "enable_dynamic_rules" -> enableDynamicRules = value as Boolean
      "dynamic_rule_interval" -> dynamicRuleInterval = value as Int
      "dynamic_rules_cache_path" -> dynamicRulesCachePath = value as Path?
      "agent_status_interval" -> agentStatusInterval = value as Int
      "emergency_mode" -> emergencyMode = value as Boolean
      "emergency_whitelist" -> emergencyWhitelist = value as List<String>
      "endpoint_rate_limits" -> endpointRateLimits = value as Map<String, Pair<Int, Int>>
      "detection_compiler_timeout" -> detectionCompilerTimeout = value as Double
      "detection_pattern_validation_cache_path" ->
          detectionPatternValidationCachePath = value as String?
      "detection_max_content_length" -> detectionMaxContentLength = value as Int
      "detection_max_body_inspect_bytes" -> detectionMaxBodyInspectBytes = value as Int
      "detection_max_scan_values" -> detectionMaxScanValues = value as Int
      "detection_max_scan_chars" -> detectionMaxScanChars = value as Int
      "detection_max_json_depth" -> detectionMaxJsonDepth = value as Int
      "detection_binary_min_run_length" -> detectionBinaryMinRunLength = value as Int
      "detection_preserve_attack_patterns" -> detectionPreserveAttackPatterns = value as Boolean
      "detection_semantic_threshold" -> detectionSemanticThreshold = value as Double
      "detection_anomaly_threshold" -> detectionAnomalyThreshold = value as Double
      "detection_slow_pattern_threshold" -> detectionSlowPatternThreshold = value as Double
      "detection_monitor_history_size" -> detectionMonitorHistorySize = value as Int
      "detection_max_tracked_patterns" -> detectionMaxTrackedPatterns = value as Int
      "detection_anomaly_emission_cooldown" -> detectionAnomalyEmissionCooldown = value as Double
      "detection_min_samples_for_anomaly" -> detectionMinSamplesForAnomaly = value as Int
      "detection_threat_score_threshold" -> detectionThreatScoreThreshold = value as Double
      "muted_event_types" -> mutedEventTypes = value as Set<String>
      "muted_metric_types" -> mutedMetricTypes = value as Set<String>
      "muted_check_logs" -> mutedCheckLogs = value as Set<String>
      "log_sensitive_headers" -> logSensitiveHeaders = value as Set<String>
      "log_sensitive_params" -> logSensitiveParams = value as Set<String>
      "log_sensitive_body_fields" -> logSensitiveBodyFields = value as Set<String>
      "enable_otel" -> enableOtel = value as Boolean
      "otel_service_name" -> otelServiceName = value as String
      "otel_exporter_endpoint" -> otelExporterEndpoint = value as String?
      "otel_resource_attributes" -> otelResourceAttributes = value as Map<String, String>
      "enable_logfire" -> enableLogfire = value as Boolean
      "logfire_service_name" -> logfireServiceName = value as String
      "enable_enrichment" -> enableEnrichment = value as Boolean
      "excluded_detection_headers" -> excludedDetectionHeaders = value as Set<String>
      "excluded_detection_params" -> excludedDetectionParams = value as Set<String>
      "excluded_detection_body_fields" -> excludedDetectionBodyFields = value as Set<String>
      "detection_scan_body" -> detectionScanBody = value as Boolean
      "enabled_detection_categories" -> enabledDetectionCategories = value as Set<String>
      else -> throw ConfigValidationError("Unknown SecurityConfig field '$name'")
    }
  }

  // --------------------------------------------------------------- copy

  /**
   * Port of `SecurityConfig.model_copy` (models.py:125-131): copy the config, apply the raw update
   * mapping, then revalidate the changed revalidated fields via `_revalidate_copied_config`
   * (_security_config_validators.py:153-160). `deep` deep-copies the mutable containers, mirroring
   * pydantic's deep copy.
   */
  public fun copyWith(
      update: Map<String, Any?> = emptyMap(),
      deep: Boolean = false,
  ): SecurityConfig {
    val builder = SecurityConfigBuilder.fromConfig(this, deep)
    val copied = builder.buildInternal(skipBounds = true)
    // pydantic model_copy carries the private revision state over.
    copied.revisionCounter = this.revisionCounter
    // The update mapping is applied raw (no __setattr__ pipeline), then
    // the changed revalidated fields are revalidated below.
    for ((name, value) in update) copied.rawAssign(name, value)
    revalidateCopiedConfig(copied, update)
    return copied
  }

  /** Port of `_revalidate_copied_config` (_security_config_validators.py:153-160). */
  private fun revalidateCopiedConfig(copied: SecurityConfig, update: Map<String, Any?>) {
    // _revalidate_exclude_paths_field
    if ("exclude_paths" in update) {
      ConfigValidators.validateExcludePathsValue(copied.excludePaths)
    }
    // _revalidate_country_shadow_fields
    val countryTouched = update.keys.any { it in setOf("blocked_countries", "whitelist_countries") }
    if (
        countryTouched &&
            copied.whitelistCountries.isNotEmpty() &&
            copied.blockedCountries.isNotEmpty()
    ) {
      ConfigWarnings.warn(
          "blocked_countries is ignored when whitelist_countries is " +
              "non-empty: a non-empty whitelist_countries is restrictive " +
              "(only listed countries pass), so blocked_countries has no " +
              "effect. Use one or the other.",
      )
    }
    // _revalidate_geo_state_fields
    if (update.keys.any { it in ConfigFieldRegistry.geoStateFieldNames }) {
      copied.applyGeoIpHandlerCopySelf()
    }
    // _revalidate_changed_fields
    val fields =
        ConfigFieldRegistry.revalidatedFieldNames.intersect(update.keys) - setOf("exclude_paths")
    for (fieldName in fields) {
      copied.rawAssign(fieldName, copied.valueByName(fieldName))
    }
    // _revalidate_global_behavior_rule_fields
    if (update.keys.any { it in ConfigFieldRegistry.globalBehaviorRuleFieldNames }) {
      ConfigValidators.revalidateGlobalBehaviorRules(copied)
    }
  }

  /** Port of `_apply_geo_ip_handler_copy` (_security_config_geo_validators.py:116). */
  private fun applyGeoIpHandlerCopy(config: SecurityConfig) {
    val resolved =
        resolveGeoIpHandler(
            blockedCountries = config.blockedCountries,
            whitelistCountries = config.whitelistCountries,
            geoIpHandler = config.geoIpHandler,
            ipinfoToken = config.ipinfoToken,
            ipinfoDbPath = config.ipinfoDbPath,
            geoIpDbMaxAge = config.geoIpDbMaxAge,
        )
    if (resolved !== config.geoIpHandler) config._geoIpHandler = resolved
  }

  private fun applyGeoIpHandlerCopySelf() {
    applyGeoIpHandlerCopy(this)
  }

  /** Field value read by python field name (used by copy revalidation). */
  internal fun valueByName(name: String): Any? =
      when (name) {
        "trusted_proxies" -> trustedProxies
        "whitelist" -> whitelist
        "blacklist" -> blacklist
        "exempt_ips" -> exemptIps
        "threat_ban_config" -> threatBanConfig
        "enabled_detection_categories" -> enabledDetectionCategories
        "muted_event_types" -> mutedEventTypes
        "muted_metric_types" -> mutedMetricTypes
        "muted_check_logs" -> mutedCheckLogs
        "log_sensitive_headers" -> logSensitiveHeaders
        "log_sensitive_params" -> logSensitiveParams
        "log_sensitive_body_fields" -> logSensitiveBodyFields
        "block_cloud_providers" -> blockCloudProviders
        "blocked_countries" -> blockedCountries
        "whitelist_countries" -> whitelistCountries
        "rate_limit" -> rateLimit
        "rate_limit_window" -> rateLimitWindow
        "endpoint_rate_limits" -> endpointRateLimits
        "blocked_user_agents" -> blockedUserAgents
        "enable_penetration_detection" -> enablePenetrationDetection
        "enable_ip_banning" -> enableIpBanning
        "enable_rate_limiting" -> enableRateLimiting
        "emergency_mode" -> emergencyMode
        "emergency_whitelist" -> emergencyWhitelist
        "auto_ban_threshold" -> autoBanThreshold
        "auto_ban_duration" -> autoBanDuration
        "enable_rate_limit_auto_ban" -> enableRateLimitAutoBan
        "dynamic_rules_cache_path" -> dynamicRulesCachePath
        "exclude_paths" -> excludePaths
        "global_behavior_rules" -> globalBehaviorRules
        "custom_error_responses" -> customErrorResponses
        "security_headers" -> securityHeaders
        "cors_allow_origins" -> corsAllowOrigins
        "cors_allow_methods" -> corsAllowMethods
        "cors_allow_headers" -> corsAllowHeaders
        "cors_expose_headers" -> corsExposeHeaders
        "agent_sensitive_headers" -> agentSensitiveHeaders
        "otel_resource_attributes" -> otelResourceAttributes
        "excluded_detection_headers" -> excludedDetectionHeaders
        "excluded_detection_params" -> excludedDetectionParams
        "excluded_detection_body_fields" -> excludedDetectionBodyFields
        else -> throw ConfigValidationError("Unknown SecurityConfig field '$name'")
      }

  // ----------------------------------------------------- agent config

  /**
   * Port of `SecurityConfig.to_agent_config` (models.py:317-365). The guard-agent-jvm AgentConfig
   * construction goes through `ConfigSeams.agentConfigFactory` (registered by the W7 agent wave);
   * the None short-circuit paths are fully live.
   */
  public fun toAgentConfig(guardCoreVersion: String): Any? {
    if (!enableAgent || agentApiKey.isNullOrEmpty()) return null
    val factory =
        ConfigSeams.agentConfigFactory
            ?: throw AgentPackageNotInstalledError(
                "guard-agent is not installed but enable_agent=True. " +
                    "Install it with: pip install guard-agent",
            )
    val kwargs =
        linkedMapOf<String, Any?>(
            "api_key" to agentApiKey,
            "endpoint" to agentEndpoint,
            "project_id" to agentProjectId,
            "buffer_size" to agentBufferSize,
            "flush_interval" to agentFlushInterval,
            "dynamic_rule_interval" to dynamicRuleInterval,
            "status_interval" to agentStatusInterval,
            "high_watermark_ratio" to agentHighWatermarkRatio,
            "max_concurrent_flushes" to agentMaxConcurrentFlushes,
            "buffer_overflow_policy" to agentBufferOverflowPolicy?.pythonName,
            "enable_events" to agentEnableEvents,
            "enable_metrics" to agentEnableMetrics,
            "timeout" to agentTimeout,
            "retry_attempts" to agentRetryAttempts,
            "backoff_factor" to agentBackoffFactor,
            "sensitive_headers" to agentSensitiveHeaders,
            "max_payload_size" to agentMaxPayloadSize,
            "project_encryption_key" to agentProjectEncryptionKey,
            "guard_version" to agentGuardVersion,
            "guard_core_version" to guardCoreVersion,
            "compression_enabled" to agentCompressionEnabled,
            "compression_threshold" to agentCompressionThreshold,
            "install_id" to agentInstallId,
            "payload_signing_secret" to agentPayloadSigningSecret,
            "on_error" to onError,
        )
    val filtered = kwargs.filterValues { it != null }
    return factory(filtered)
  }

  internal companion object {
    /** The security_headers default factory (models.py:329-343), byte-exact. */
    internal fun defaultSecurityHeaders(): Map<String, Any?> =
        linkedMapOf(
            "enabled" to true,
            "hsts" to
                linkedMapOf<String, Any?>(
                    "max_age" to 31536000,
                    "include_subdomains" to true,
                    "preload" to false,
                ),
            "csp" to null,
            "frame_options" to "SAMEORIGIN",
            "content_type_options" to "nosniff",
            "xss_protection" to "1; mode=block",
            "referrer_policy" to "strict-origin-when-cross-origin",
            "permissions_policy" to "geolocation=(), microphone=(), camera=()",
            "custom" to null,
        )
  }
}
