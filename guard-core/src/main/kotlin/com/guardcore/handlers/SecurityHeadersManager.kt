package com.guardcore.handlers

import com.guardcore.config.EventTypes
import com.guardcore.config.SecurityConfig
import com.guardcore.util.LoggingUtils
import com.guardcore.util.RequestLogging
import java.util.logging.Logger
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.jsonPrimitive

/**
 * Port of `guard_core/handlers/security_headers_handler.py` (SecurityHeadersManager) with its three
 * mixin files:
 * - `_security_headers_config.py` -> [com.guardcore.handlers] config-method group below
 * - `_security_headers_cache.py` -> [com.guardcore.handlers] cache-method group
 * - `_security_headers_cors.py` -> [com.guardcore.handlers] CORS-method group
 * - `_security_headers_events.py` -> [com.guardcore.handlers] events-method group
 *
 * The Python class spreads four mixins over shared instance state; the JVM port keeps one class
 * with the method groups in declaration order.
 */
public class SecurityHeadersManager private constructor() {
  public companion object {
    @Volatile private var instance: SecurityHeadersManager? = null

    private val lock = Mutex()

    /** Python `SecurityHeadersManager()` singleton dispatch (security_headers_handler.py:45). */
    public suspend fun getInstance(): SecurityHeadersManager {
      instance?.let {
        return it
      }
      lock.withLock {
        instance?.let {
          return it
        }
        val created = SecurityHeadersManager()
        instance = created
        return created
      }
    }

    /** Test seam mirroring `SecurityHeadersManager._instance = None`. */
    public fun resetInstance() {
      synchronized(this) { instance = null }
    }

    /** Port of `default_headers` (security_headers_handler.py:32), byte-exact. */
    public val DEFAULT_HEADERS: Map<String, String> =
        linkedMapOf(
            "X-Content-Type-Options" to "nosniff",
            "X-Frame-Options" to "SAMEORIGIN",
            "X-XSS-Protection" to "1; mode=block",
            "Referrer-Policy" to "strict-origin-when-cross-origin",
            "Permissions-Policy" to "geolocation=(), microphone=(), camera=()",
            "X-Permitted-Cross-Domain-Policies" to "none",
            "X-Download-Options" to "noopen",
            "Cross-Origin-Embedder-Policy" to "require-corp",
            "Cross-Origin-Opener-Policy" to "same-origin",
            "Cross-Origin-Resource-Policy" to "same-origin",
        )
  }

  public val logger: Logger = Logger.getLogger("guard_core.handlers.security_headers")

  /** Port of `headers_cache` (security_headers_handler.py:50): TTLCache(maxsize=1000, ttl=300). */
  public var headersCache: TtlCache<String, Map<String, String>> =
      TtlCache(maxsize = 1000, ttlSeconds = 300.0)

  @Volatile public var redisHandler: RedisManager? = null

  @Volatile public var agentHandler: HandlerAgentSink? = null

  @Volatile public var enabled: Boolean = true

  @Volatile public var customHeaders: Map<String, String> = linkedMapOf()

  public var cspConfig: Map<String, List<String>>? = null

  public var hstsConfig: Map<String, Any?>? = null

  public var corsConfig: Map<String, Any?>? = null

  @Volatile public var defaultHeaders: Map<String, String> = DEFAULT_HEADERS

  // ---------------------------------------------------------- _security_headers_config.py

  /** Port of `_HEADER_NAME_TOKEN_RE` (_security_headers_config.py:20). */
  private val headerNameTokenRegex = Regex("[!#\$%&'*+.^_`|~0-9A-Za-z-]+")

  /** Port of `_validate_header_name` (_security_headers_config.py:22). */
  public fun validateHeaderName(name: String): String {
    if (!headerNameTokenRegex.matches(name)) {
      throw IllegalArgumentException("Invalid header name: $name")
    }
    return name
  }

  /** Port of `_validate_header_value` (_security_headers_config.py:27). */
  public fun validateHeaderValue(value: String): String {
    if (value.contains('\r') || value.contains('\n')) {
      throw IllegalArgumentException("Invalid header value contains newline: $value")
    }
    if (value.length > 8192) {
      throw IllegalArgumentException("Header value too long: ${value.length} bytes")
    }
    return value.filter { it.code >= 32 || it == '\t' }
  }

  /** Port of `_compute_csp_config` (_security_headers_config.py:35). */
  public fun computeCspConfig(csp: Map<String, List<String>>?): Map<String, List<String>>? {
    if (csp == null || csp.isEmpty()) {
      return null
    }
    for ((directive, sources) in csp) {
      if ("'unsafe-inline'" in sources || "'unsafe-eval'" in sources) {
        logger.warning("CSP directive '$directive' contains unsafe sources")
      }
    }
    return csp
  }

  /** Port of `_configure_csp` (_security_headers_config.py:48). */
  public fun configureCsp(csp: Map<String, List<String>>?) {
    cspConfig = computeCspConfig(csp)
  }

  /** Port of `_compute_hsts_config` (_security_headers_config.py:51). */
  public fun computeHstsConfig(
      hstsMaxAge: Int?,
      hstsIncludeSubdomains: Boolean,
      hstsPreload: Boolean,
  ): Map<String, Any?>? {
    if (hstsMaxAge == null) {
      return null
    }
    var preload = hstsPreload
    var includeSubdomains = hstsIncludeSubdomains
    if (preload) {
      if (hstsMaxAge < 31536000) {
        logger.warning("HSTS preload requires max_age >= 31536000")
        preload = false
      }
      if (!includeSubdomains) {
        logger.warning("HSTS preload requires includeSubDomains")
        includeSubdomains = true
      }
    }
    return linkedMapOf(
        "max_age" to hstsMaxAge,
        "include_subdomains" to includeSubdomains,
        "preload" to preload,
    )
  }

  /** Port of `_configure_hsts` (_security_headers_config.py:74). */
  public fun configureHsts(
      hstsMaxAge: Int?,
      hstsIncludeSubdomains: Boolean,
      hstsPreload: Boolean,
  ) {
    hstsConfig = computeHstsConfig(hstsMaxAge, hstsIncludeSubdomains, hstsPreload)
  }

  /** Port of `_compute_cors_config` (_security_headers_config.py:84). */
  public fun computeCorsConfig(
      corsOrigins: List<String>?,
      corsAllowCredentials: Boolean,
      corsAllowMethods: List<String>?,
      corsAllowHeaders: List<String>?,
  ): Map<String, Any?>? {
    if (corsOrigins == null || corsOrigins.isEmpty()) {
      return null
    }
    var allowCredentials = corsAllowCredentials
    if ("*" in corsOrigins && corsAllowCredentials) {
      logger.severe("CORS config error: Wildcard origin disallowed with credentials")
      allowCredentials = false
    }
    return linkedMapOf(
        "origins" to corsOrigins,
        "allow_credentials" to allowCredentials,
        "allow_methods" to (corsAllowMethods ?: listOf("GET", "POST")),
        "allow_headers" to (corsAllowHeaders ?: listOf("*")),
    )
  }

  /** Port of `_configure_cors` (_security_headers_config.py:107). */
  public fun configureCors(
      corsOrigins: List<String>?,
      corsAllowCredentials: Boolean,
      corsAllowMethods: List<String>?,
      corsAllowHeaders: List<String>?,
  ) {
    corsConfig =
        computeCorsConfig(corsOrigins, corsAllowCredentials, corsAllowMethods, corsAllowHeaders)
  }

  private fun resetOrApplyHeader(
      headers: MutableMap<String, String>,
      headerName: String,
      override: String?,
      classDefault: String,
  ) {
    headers[headerName] = if (override != null) validateHeaderValue(override) else classDefault
  }

  /** Port of `_compute_default_headers` (_security_headers_config.py:131). */
  public fun computeDefaultHeaders(
      frameOptions: String?,
      contentTypeOptions: String?,
      xssProtection: String?,
      referrerPolicy: String?,
      permissionsPolicy: String?,
  ): Map<String, String> {
    val classDefaults = DEFAULT_HEADERS
    val headers = classDefaults.toMutableMap()
    resetOrApplyHeader(headers, "X-Frame-Options", frameOptions, classDefaults["X-Frame-Options"]!!)
    resetOrApplyHeader(
        headers,
        "X-Content-Type-Options",
        contentTypeOptions,
        classDefaults["X-Content-Type-Options"]!!,
    )
    resetOrApplyHeader(
        headers,
        "X-XSS-Protection",
        xssProtection,
        classDefaults["X-XSS-Protection"]!!,
    )
    resetOrApplyHeader(
        headers,
        "Referrer-Policy",
        referrerPolicy,
        classDefaults["Referrer-Policy"]!!,
    )

    when {
      permissionsPolicy == "UNSET" ->
          headers["Permissions-Policy"] = classDefaults["Permissions-Policy"]!!
      !permissionsPolicy.isNullOrEmpty() ->
          headers["Permissions-Policy"] = validateHeaderValue(permissionsPolicy)
      else -> headers.remove("Permissions-Policy")
    }

    return headers
  }

  /** Port of `_update_default_headers` (_security_headers_config.py:174). */
  public fun updateDefaultHeaders(
      frameOptions: String?,
      contentTypeOptions: String?,
      xssProtection: String?,
      referrerPolicy: String?,
      permissionsPolicy: String?,
  ) {
    defaultHeaders =
        computeDefaultHeaders(
            frameOptions,
            contentTypeOptions,
            xssProtection,
            referrerPolicy,
            permissionsPolicy,
        )
  }

  /** Port of `_compute_custom_headers` (_security_headers_config.py:190). */
  public fun computeCustomHeaders(customHeaders: Map<String, String>?): Map<String, String> {
    if (customHeaders == null || customHeaders.isEmpty()) {
      return linkedMapOf()
    }
    val result = linkedMapOf<String, String>()
    for ((name, value) in customHeaders) {
      result[validateHeaderName(name)] = validateHeaderValue(value)
    }
    return result
  }

  /** Port of `_add_custom_headers` (_security_headers_config.py:201). */
  public fun addCustomHeaders(customHeaders: Map<String, String>?) {
    this.customHeaders = computeCustomHeaders(customHeaders)
  }

  /** Port of `_resolve_headers_state` (_security_headers_config.py:204). */
  public fun resolveHeadersState(
      config: SecurityConfig?,
  ): ResolvedHeadersState {
    if (config == null) {
      return ResolvedHeadersState(cspConfig, hstsConfig, defaultHeaders, customHeaders)
    }

    val headersConfig = config.securityHeaders ?: emptyMap()
    @Suppress("UNCHECKED_CAST")
    val hstsCfg = headersConfig["hsts"] as? Map<String, Any?> ?: emptyMap()
    @Suppress("UNCHECKED_CAST") val cspCfg = headersConfig["csp"] as? Map<String, List<String>>

    val computedCsp = computeCspConfig(cspCfg)
    val computedHsts =
        computeHstsConfig(
            (hstsCfg["max_age"] as? Number)?.toInt(),
            hstsCfg["include_subdomains"] as? Boolean ?: true,
            hstsCfg["preload"] as? Boolean ?: false,
        )
    val computedDefaults =
        computeDefaultHeaders(
            headersConfig["frame_options"] as? String,
            headersConfig["content_type_options"] as? String,
            headersConfig["xss_protection"] as? String,
            headersConfig["referrer_policy"] as? String,
            headersConfig["permissions_policy"] as? String ?: "UNSET",
        )
    @Suppress("UNCHECKED_CAST")
    val computedCustom = computeCustomHeaders(headersConfig["custom"] as? Map<String, String>)

    return ResolvedHeadersState(computedCsp, computedHsts, computedDefaults, computedCustom)
  }

  /** The (csp, hsts, default_headers, custom_headers) tuple of `_resolve_headers_state`. */
  public class ResolvedHeadersState(
      public val cspConfig: Map<String, List<String>>?,
      public val hstsConfig: Map<String, Any?>?,
      public val defaultHeaders: Map<String, String>,
      public val customHeaders: Map<String, String>,
  )

  /** Port of `_resolve_cors_state` (_security_headers_config.py:240). */
  public fun resolveCorsState(config: SecurityConfig?): Map<String, Any?>? {
    if (config == null) {
      return corsConfig
    }
    return computeCorsConfig(
        if (config.enableCors) config.corsAllowOrigins else null,
        config.corsAllowCredentials,
        config.corsAllowMethods,
        config.corsAllowHeaders,
    )
  }

  /** Port of `configure` (_security_headers_config.py:253). */
  public fun configure(
      enabled: Boolean = true,
      csp: Map<String, List<String>>? = null,
      hstsMaxAge: Int? = null,
      hstsIncludeSubdomains: Boolean = true,
      hstsPreload: Boolean = false,
      frameOptions: String? = null,
      contentTypeOptions: String? = null,
      xssProtection: String? = null,
      referrerPolicy: String? = null,
      permissionsPolicy: String? = "UNSET",
      customHeaders: Map<String, String>? = null,
      corsOrigins: List<String>? = null,
      corsAllowCredentials: Boolean = false,
      corsAllowMethods: List<String>? = null,
      corsAllowHeaders: List<String>? = null,
  ) {
    this.enabled = enabled
    this.headersCache.clear()

    configureCsp(csp)
    configureHsts(hstsMaxAge, hstsIncludeSubdomains, hstsPreload)
    configureCors(corsOrigins, corsAllowCredentials, corsAllowMethods, corsAllowHeaders)
    updateDefaultHeaders(
        frameOptions,
        contentTypeOptions,
        xssProtection,
        referrerPolicy,
        permissionsPolicy,
    )
    addCustomHeaders(customHeaders)
  }

  // ---------------------------------------------------------- security_headers_handler.py

  /** Port of `_build_csp` (security_headers_handler.py:64). */
  public fun buildCsp(cspConfig: Map<String, List<String>>): String {
    val directives = mutableListOf<String>()
    for ((directive, sources) in cspConfig) {
      if (sources.isNotEmpty()) {
        directives.add("$directive ${sources.joinToString(" ")}")
      } else {
        directives.add(directive)
      }
    }
    return directives.joinToString("; ")
  }

  /** Port of `_build_hsts` (security_headers_handler.py:74). */
  public fun buildHsts(hstsConfig: Map<String, Any?>): String {
    val parts = mutableListOf("max-age=${hstsConfig["max_age"]}")
    if (hstsConfig["include_subdomains"] == true) {
      parts.add("includeSubDomains")
    }
    if (hstsConfig["preload"] == true) {
      parts.add("preload")
    }
    return parts.joinToString("; ")
  }

  /** Port of `get_headers` (security_headers_handler.py:82). */
  public suspend fun getHeaders(
      requestPath: String? = null,
      config: SecurityConfig? = null,
  ): Map<String, String> {
    if (config != null) {
      val cfg = config.securityHeaders
      val enabledFlag = if (cfg == null) false else (cfg["enabled"] as? Boolean ?: true)
      if (!enabledFlag) {
        return linkedMapOf()
      }
    } else if (!enabled) {
      return linkedMapOf()
    }

    val cacheKey = generateCacheKey(requestPath, config)
    headersCache.get(cacheKey)?.let {
      return it
    }

    val state = resolveHeadersState(config)

    val headers = state.defaultHeaders.toMutableMap()

    state.cspConfig?.let { headers["Content-Security-Policy"] = buildCsp(it) }
    state.hstsConfig?.let { headers["Strict-Transport-Security"] = buildHsts(it) }

    headers.putAll(state.customHeaders)

    headersCache[cacheKey] = headers

    if (agentHandler != null && requestPath != null) {
      sendHeadersAppliedEvent(requestPath, headers)
    }

    return headers
  }

  // ---------------------------------------------------------- _security_headers_cache.py

  /** Port of `_generate_cache_key` (_security_headers_cache.py:31). */
  public fun generateCacheKey(requestPath: String?, config: SecurityConfig? = null): String {
    val base =
        if (requestPath.isNullOrEmpty()) {
          "default"
        } else {
          val normalized = requestPath.lowercase().trim('/')
          val digest =
              java.security.MessageDigest.getInstance("SHA-256")
                  .digest(normalized.toByteArray(Charsets.UTF_8))
                  .joinToString("") { "%02x".format(it) }
          "path_${digest.take(16)}"
        }
    return if (config == null) base else "cfg_${System.identityHashCode(config)}_$base"
  }

  /** Port of `initialize_redis` (_security_headers_cache.py:42). */
  public suspend fun initializeHeadersRedis(redisHandler: RedisManager?) {
    this.redisHandler = redisHandler
    loadCachedConfig()
    cacheConfiguration()
  }

  /** Port of `_load_cached_config` (_security_headers_cache.py:47). */
  public suspend fun loadCachedConfig() {
    val redis = redisHandler ?: return

    try {
      val csp = redis.getKey("security_headers", "csp_config")?.toString()
      if (!csp.isNullOrEmpty()) {
        cspConfig = PyJsonSerde.parseCspConfig(csp)
      }

      val hsts = redis.getKey("security_headers", "hsts_config")?.toString()
      if (!hsts.isNullOrEmpty()) {
        hstsConfig = PyJsonSerde.parseHstsConfig(hsts)
      }

      val custom = redis.getKey("security_headers", "custom_headers")?.toString()
      if (!custom.isNullOrEmpty()) {
        val loaded = PyJsonSerde.parseCustomHeaders(custom)
        val validated = linkedMapOf<String, String>()
        for ((name, value) in loaded) {
          validated[validateHeaderName(name)] = validateHeaderValue(value)
        }
        customHeaders = validated
      }
    } catch (e: Exception) {
      logger.warning(
          "Failed to load cached header config: ${LoggingUtils.sanitizeForLog(e.toString())}",
      )
    }
  }

  /** Port of `_cache_configuration` (_security_headers_cache.py:80). */
  public suspend fun cacheConfiguration() {
    val redis = redisHandler ?: return

    try {
      cspConfig?.let {
        redis.setKey("security_headers", "csp_config", PyJsonSerde.dumpsCspConfig(it), ttl = 86400)
      }
      hstsConfig?.let {
        redis.setKey(
            "security_headers",
            "hsts_config",
            PyJsonSerde.dumpsHstsConfig(it),
            ttl = 86400,
        )
      }
      if (customHeaders.isNotEmpty()) {
        redis.setKey(
            "security_headers",
            "custom_headers",
            PyJsonSerde.dumpsCustomHeaders(customHeaders),
            ttl = 86400,
        )
      }
    } catch (e: Exception) {
      logger.warning("Failed to cache header configuration: $e")
    }
  }

  /** Port of `reset` (_security_headers_cache.py:109). */
  public suspend fun reset() {
    headersCache.clear()
    (customHeaders as? MutableMap<String, String>)?.clear()
    customHeaders = linkedMapOf()
    cspConfig = null
    hstsConfig = null
    corsConfig = null
    enabled = true
    defaultHeaders = DEFAULT_HEADERS

    val redis = redisHandler
    if (redis != null) {
      try {
        // python uses the raw connection here (conn.keys with the embedded prefix).
        val ops = redis.getConnection().client as? RedisOperations
        val keys = ops?.keys("${redisPrefixOf(redis)}security_headers:*")
        if (!keys.isNullOrEmpty()) {
          ops?.del(*keys.toTypedArray())
        }
      } catch (e: Exception) {
        logger.warning("Failed to clear Redis cache: $e")
      }
    }

    redisHandler = null
    agentHandler = null
  }

  // ---------------------------------------------------------- _security_headers_cors.py

  /** Port of `_is_wildcard_with_credentials` (_security_headers_cors.py:17). */
  public fun isWildcardWithCredentials(
      allowedOrigins: List<String>,
      corsConfigArg: Map<String, Any?>? = null,
  ): Boolean {
    if ("*" !in allowedOrigins) {
      return false
    }
    val effective = corsConfigArg ?: corsConfig
    if (effective != null && effective["allow_credentials"] == true) {
      logger.warning("Credentials cannot be used with wildcard origin - blocking CORS")
      return true
    }
    return false
  }

  /** Port of `_is_origin_allowed` (_security_headers_cors.py:34). */
  public fun isOriginAllowed(origin: String, allowedOrigins: List<String>): Boolean =
      "*" in allowedOrigins || origin in allowedOrigins

  /** Port of `_get_validated_cors_config` (_security_headers_cors.py:37). */
  public fun getValidatedCorsConfig(
      corsConfigArg: Map<String, Any?>? = null,
  ): Pair<List<String>, List<String>> {
    val effective = corsConfigArg ?: corsConfig
    if (effective == null) {
      return listOf("GET", "POST") to listOf("*")
    }

    @Suppress("UNCHECKED_CAST")
    val allowMethods = effective["allow_methods"] as? List<String> ?: listOf("GET", "POST")
    @Suppress("UNCHECKED_CAST")
    val allowHeaders = effective["allow_headers"] as? List<String> ?: listOf("*")

    return allowMethods to allowHeaders
  }

  /** Port of `_build_cors_headers` (_security_headers_cors.py:56). */
  public fun buildCorsHeaders(
      origin: String,
      allowedOrigins: List<String>,
      allowMethods: List<String>,
      allowHeaders: List<String>,
      corsConfigArg: Map<String, Any?>? = null,
  ): Map<String, String> {
    val effective = corsConfigArg ?: corsConfig
    val corsHeaders = linkedMapOf<String, String>()
    corsHeaders["Access-Control-Allow-Origin"] = if (origin in allowedOrigins) origin else "*"
    corsHeaders["Access-Control-Allow-Methods"] = allowMethods.joinToString(", ")
    corsHeaders["Access-Control-Allow-Headers"] = allowHeaders.joinToString(", ")
    corsHeaders["Access-Control-Max-Age"] = "3600"

    if (effective != null && effective["allow_credentials"] == true) {
      corsHeaders["Access-Control-Allow-Credentials"] = "true"
    }

    return corsHeaders
  }

  /** Port of `get_cors_headers` (_security_headers_cors.py:79). */
  public suspend fun getCorsHeaders(
      origin: String,
      config: SecurityConfig? = null,
  ): Map<String, String> {
    val corsCfg = resolveCorsState(config) ?: return linkedMapOf()

    @Suppress("UNCHECKED_CAST")
    val allowedOrigins = corsCfg["origins"] as? List<String> ?: return linkedMapOf()

    if (isWildcardWithCredentials(allowedOrigins, corsCfg)) {
      return linkedMapOf()
    }

    if (!isOriginAllowed(origin, allowedOrigins)) {
      return linkedMapOf()
    }

    val (allowMethods, allowHeaders) = getValidatedCorsConfig(corsCfg)
    return buildCorsHeaders(origin, allowedOrigins, allowMethods, allowHeaders, corsCfg)
  }

  // ---------------------------------------------------------- _security_headers_events.py

  /** Port of `initialize_agent` (_security_headers_events.py:32). */
  public suspend fun initializeHeadersAgent(agentHandler: HandlerAgentSink?) {
    this.agentHandler = agentHandler
  }

  /** Port of `_send_headers_applied_event` (_security_headers_events.py:35). */
  public suspend fun sendHeadersAppliedEvent(path: String, headers: Map<String, String>) {
    try {
      agentHandler?.sendEvent(
          linkedMapOf<String, Any?>(
              "event_type" to EventTypes.EVENT_SECURITY_HEADERS_APPLIED,
              "ip_address" to null,
              "action_taken" to "headers_added",
              "handler_name" to SECURITY_HEADERS_HANDLER_NAME,
              "metadata" to
                  mapOf(
                      "path" to RequestLogging.redactEndpointForDisplay(path, null, null),
                      "headers_count" to headers.size,
                      "has_csp" to headers.containsKey("Content-Security-Policy"),
                      "has_hsts" to headers.containsKey("Strict-Transport-Security"),
                  ),
          ),
      )
    } catch (e: Exception) {
      logger.fine("Failed to send headers event to agent: $e")
    }
  }

  /** Port of `validate_csp_report` (_security_headers_events.py:61). */
  public suspend fun validateCspReport(report: Map<String, Any?>): Boolean {
    val requiredFields = listOf("document-uri", "violated-directive", "blocked-uri")

    @Suppress("UNCHECKED_CAST")
    val cspReport = report["csp-report"] as? Map<String, Any?> ?: emptyMap()
    if (!requiredFields.all { it in cspReport }) {
      return false
    }

    val safeDirective = safeCspDirective(cspReport["violated-directive"])
    val safeBlockedUri = safeCspUri(cspReport["blocked-uri"])
    val safeDocumentUri = safeCspUri(cspReport["document-uri"])
    logger.warning(
        "CSP Violation: $safeDirective blocked $safeBlockedUri on $safeDocumentUri",
    )

    if (agentHandler != null) {
      sendCspViolationEvent(cspReport)
    }

    return true
  }

  /** Port of `_send_csp_violation_event` (_security_headers_events.py:82). */
  public suspend fun sendCspViolationEvent(report: Map<String, Any?>) {
    try {
      agentHandler?.sendEvent(
          linkedMapOf<String, Any?>(
              "event_type" to EventTypes.EVENT_CSP_VIOLATION,
              "ip_address" to null,
              "action_taken" to "logged",
              "handler_name" to SECURITY_HEADERS_HANDLER_NAME,
              "metadata" to
                  mapOf(
                      "document_uri" to safeCspUri(report["document-uri"]),
                      "violated_directive" to safeCspDirective(report["violated-directive"]),
                      "blocked_uri" to safeCspUri(report["blocked-uri"]),
                      "source_file" to safeCspUri(report["source-file"]),
                      "line_number" to safeCspLineNumber(report["line-number"]),
                  ),
          ),
      )
    } catch (e: Exception) {
      val safeError = RequestLogging.redactHeaderValueForDisplay(e.toString(), null, null)
      logger.fine("Failed to send CSP violation event to agent: $safeError")
    }
  }
}

/** Python `_SECURITY_HEADERS_HANDLER_NAME` (_security_headers_events.py:10). */
public const val SECURITY_HEADERS_HANDLER_NAME: String = "security_headers"

/** Port of `_safe_csp_uri` (_security_headers_events.py:13). */
public fun safeCspUri(value: Any?): String =
    RequestLogging.redactEndpointForDisplay(value?.toString() ?: "None", null, null)

/** Port of `_safe_csp_directive` (_security_headers_events.py:17). */
public fun safeCspDirective(value: Any?): String =
    RequestLogging.redactHeaderValueForDisplay(value?.toString() ?: "None", null, null)

/** Port of `_safe_csp_line_number` (_security_headers_events.py:21). */
public fun safeCspLineNumber(value: Any?): Int? =
    when (value) {
      null -> null
      is Number -> value.toInt()
      else -> value.toString().toIntOrNull()
    }

/**
 * Port of `security_headers_manager = SecurityHeadersManager()` (security_headers_handler.py:122).
 */
public suspend fun securityHeadersManager(): SecurityHeadersManager =
    SecurityHeadersManager.getInstance()

/**
 * Port of `reset_global_state` (security_headers_handler.py:125): reset the singleton and swap in a
 * fresh manager.
 */
public suspend fun resetSecurityHeadersGlobalState() {
  val manager = SecurityHeadersManager.getInstance()
  manager.reset()
}

/**
 * Python-ordered JSON helpers for the security-headers Redis blobs (json.dumps of the config dicts,
 * insertion-ordered like the Python dicts).
 */
public object PyJsonSerde {
  private val json = kotlinx.serialization.json.Json

  public fun dumpsCspConfig(config: Map<String, List<String>>): String =
      PyJsonDumps.dumps(
          kotlinx.serialization.json.JsonObject(
              config.mapValues { (_, v) ->
                kotlinx.serialization.json.JsonArray(
                    v.map { kotlinx.serialization.json.JsonPrimitive(it) },
                )
              },
          ),
      )

  public fun parseCspConfig(payload: String): Map<String, List<String>> {
    val obj = json.parseToJsonElement(payload).let { it as kotlinx.serialization.json.JsonObject }
    val result = linkedMapOf<String, List<String>>()
    for ((k, v) in obj) {
      result[k] = (v as kotlinx.serialization.json.JsonArray).map { it.jsonPrimitive.content }
    }
    return result
  }

  public fun dumpsHstsConfig(config: Map<String, Any?>): String =
      PyJsonDumps.dumps(
          kotlinx.serialization.json.JsonObject(
              config.mapValues { (_, v) ->
                when (v) {
                  is Boolean -> kotlinx.serialization.json.JsonPrimitive(v)
                  is Number -> kotlinx.serialization.json.JsonPrimitive(v.toLong())
                  else -> kotlinx.serialization.json.JsonPrimitive(v.toString())
                }
              },
          ),
      )

  public fun parseHstsConfig(payload: String): Map<String, Any?> {
    val obj = json.parseToJsonElement(payload) as kotlinx.serialization.json.JsonObject
    val result = linkedMapOf<String, Any?>()
    result["max_age"] =
        (obj["max_age"] as kotlinx.serialization.json.JsonPrimitive).longOrNullSafe()
    result["include_subdomains"] =
        (obj["include_subdomains"] as kotlinx.serialization.json.JsonPrimitive).content == "true"
    result["preload"] =
        (obj["preload"] as kotlinx.serialization.json.JsonPrimitive).content == "true"
    return result
  }

  public fun dumpsCustomHeaders(headers: Map<String, String>): String =
      PyJsonDumps.dumps(
          kotlinx.serialization.json.JsonObject(
              headers.mapValues { (_, v) -> kotlinx.serialization.json.JsonPrimitive(v) },
          ),
      )

  public fun parseCustomHeaders(payload: String): Map<String, String> {
    val obj = json.parseToJsonElement(payload) as kotlinx.serialization.json.JsonObject
    val result = linkedMapOf<String, String>()
    for ((k, v) in obj) {
      result[k] = (v as kotlinx.serialization.json.JsonPrimitive).content
    }
    return result
  }

  private fun kotlinx.serialization.json.JsonPrimitive.longOrNullSafe(): Long? =
      when (val v = content) {
        "null" -> null
        else -> v.toLongOrNull() ?: throw IllegalArgumentException("not a long: $v")
      }
}
