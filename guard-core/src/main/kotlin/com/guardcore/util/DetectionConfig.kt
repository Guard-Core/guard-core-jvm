package com.guardcore.util

import com.guardcore.config.SecurityConfig
import com.guardcore.decorators.RouteConfig
import com.guardcore.util.py.parseAddress

/**
 * Port of `guard_core/_utils/detection_config.py` (G-7a): the per-scan config resolution against
 * (config, route_config) pairs (detection_config.py:14-234).
 */
public object DetectionConfig {
  /** Python `_DEFAULT_EXCLUDED_HEADERS` (detection_config.py:60). */
  public val DEFAULT_EXCLUDED_HEADERS: Set<String> =
      setOf(
          "host",
          "user-agent",
          "accept",
          "accept-encoding",
          "connection",
          "origin",
          "referer",
          "sec-fetch-site",
          "sec-fetch-mode",
          "sec-fetch-dest",
          "sec-ch-ua",
          "sec-ch-ua-mobile",
          "sec-ch-ua-platform",
          "forwarded",
          "x-forwarded-for",
          "x-forwarded-host",
          "x-forwarded-proto",
          "x-real-ip",
          "x-client-ip",
          "x-cluster-client-ip",
          "cf-connecting-ip",
          "true-client-ip",
          "fly-client-ip",
          "x-envoy-external-address",
      )

  /** Python `_ADDRESS_HEADER_SKIP_CATEGORIES` (detection_config.py:101). */
  public val ADDRESS_HEADER_SKIP_CATEGORIES: Set<String> = setOf("ssrf")

  /** Python `_GENERIC_EXCLUDED_HEADER_SKIP_CATEGORIES` (detection_config.py:103). */
  public val GENERIC_EXCLUDED_HEADER_SKIP_CATEGORIES: Set<String> = emptySet()

  /** Python `_HEADER_CATEGORY_EXCLUSIONS` (detection_config.py:105). */
  public val HEADER_CATEGORY_EXCLUSIONS: Map<String, Set<String>> =
      listOf(
              "host",
              "origin",
              "x-forwarded-for",
              "x-forwarded-host",
              "x-real-ip",
              "x-client-ip",
              "x-cluster-client-ip",
              "cf-connecting-ip",
              "true-client-ip",
              "fly-client-ip",
              "x-envoy-external-address",
          )
          .associateWith { ADDRESS_HEADER_SKIP_CATEGORIES } +
          mapOf("via" to ADDRESS_HEADER_SKIP_CATEGORIES)

  /** Python `_resolve_excluded_params` (detection_config.py:14). */
  public fun resolveExcludedParams(
      config: SecurityConfig?,
      routeConfig: RouteConfig?,
  ): Set<String> {
    routeConfig?.excludedDetectionParams?.let {
      return it.map { k -> k.lowercase() }.toSet()
    }
    config?.let {
      return it.excludedDetectionParams.map { k -> k.lowercase() }.toSet()
    }
    return emptySet()
  }

  /** Python `_resolve_excluded_body_fields` (detection_config.py:24). */
  public fun resolveExcludedBodyFields(
      config: SecurityConfig?,
      routeConfig: RouteConfig?,
  ): Set<String> {
    routeConfig?.excludedDetectionBodyFields?.let {
      return it.map { k -> k.lowercase() }.toSet()
    }
    config?.let {
      return it.excludedDetectionBodyFields.map { k -> k.lowercase() }.toSet()
    }
    return emptySet()
  }

  /** Python `_resolve_enabled_categories` (detection_config.py:37). */
  public fun resolveEnabledCategories(
      config: SecurityConfig?,
      routeConfig: RouteConfig?,
  ): Set<String>? {
    routeConfig?.enabledDetectionCategories?.let {
      return it.toSet()
    }
    config?.let {
      return it.enabledDetectionCategories.toSet()
    }
    return null
  }

  /** Python `_resolve_scan_body` (detection_config.py:50). */
  public fun resolveScanBody(config: SecurityConfig?, routeConfig: RouteConfig?): Boolean {
    routeConfig?.detectionScanBody?.let {
      return it
    }
    config?.let {
      return it.detectionScanBody
    }
    return true
  }

  /** Python `_resolve_excluded_headers` (detection_config.py:90). */
  public fun resolveExcludedHeaders(
      config: SecurityConfig?,
      routeConfig: RouteConfig?,
  ): Set<String> {
    val excluded = DEFAULT_EXCLUDED_HEADERS.toMutableSet()
    config?.let {
      excluded.addAll(it.excludedDetectionHeaders.map { h -> h.lowercase() })
    }
    routeConfig?.excludedDetectionHeaders?.let {
      excluded.addAll(it.map { h -> h.lowercase() })
    }
    return excluded
  }

  /** Python `_address_chain_token_is_address` (detection_config.py:121). */
  private fun addressChainTokenIsAddress(token: String): Boolean =
      try {
        parseAddress(IpExtraction.stripForwardedEntryPort(token))
        true
      } catch (e: Exception) {
        false
      }

  /** Python `_value_looks_like_address_chain` (detection_config.py:133). */
  private fun valueLooksLikeAddressChain(value: String): Boolean {
    val tokens = value.split(",").map { it.trim() }.filter { it.isNotEmpty() }
    if (tokens.isEmpty()) {
      return false
    }
    return tokens.all { addressChainTokenIsAddress(it) }
  }

  /** Python `_excluded_header_skip_categories` (detection_config.py:140). */
  public fun excludedHeaderSkipCategories(key: String, value: String): Set<String> {
    val normalized = key.trim().lowercase()
    val mapped = HEADER_CATEGORY_EXCLUSIONS[normalized]
    if (mapped != null) {
      return mapped
    }
    if (valueLooksLikeAddressChain(value)) {
      return ADDRESS_HEADER_SKIP_CATEGORIES
    }
    return GENERIC_EXCLUDED_HEADER_SKIP_CATEGORIES
  }

  /** Python `_excluded_header_effective_categories` (detection_config.py:150). */
  public fun excludedHeaderEffectiveCategories(
      key: String,
      value: String,
      enabledCategories: Set<String>?,
  ): Set<String>? {
    val skip = excludedHeaderSkipCategories(key, value)
    if (skip.isEmpty()) {
      return enabledCategories
    }
    val base =
        if (enabledCategories != null) {
          enabledCategories.toSet()
        } else {
          com.guardcore.engine.suspatterns.ALL_DETECTION_CATEGORIES.toSet()
        }
    return base - skip
  }

  /** Python `_resolve_semantic_excluded_headers`: global and route-level names, lowercased. */
  public fun resolveSemanticExcludedHeaders(
      config: SecurityConfig?,
      routeConfig: RouteConfig?,
  ): Set<String> = buildSet {
    config?.excludedSemanticDetectionHeaders?.forEach { add(it.trim().lowercase()) }
    routeConfig?.excludedSemanticDetectionHeaders?.forEach { add(it.trim().lowercase()) }
  }

  /** Python `_resolve_log_level` (detection_config.py:167). */
  public fun resolveLogLevel(config: SecurityConfig?): String? =
      config?.logSuspiciousLevel?.pythonName ?: "WARNING"

  /** Python `_resolve_sensitive_log_headers` (detection_config.py:171). */
  public fun resolveSensitiveLogHeaders(config: SecurityConfig?): Set<String> =
      RequestLogging.mergeSensitiveLogHeaders(config?.logSensitiveHeaders)

  /** Python `_resolve_sensitive_log_params` (detection_config.py:177). */
  public fun resolveSensitiveLogParams(config: SecurityConfig?): Set<String> =
      // _merge_sensitive_names(_DEFAULT_SENSITIVE_LOG_FIELDS, extra) ==
      // _merge_sensitive_log_body_fields
      RequestLogging.mergeSensitiveLogBodyFields(config?.logSensitiveParams)

  /** Python `_resolve_sensitive_log_body_fields` (detection_config.py:184). */
  public fun resolveSensitiveLogBodyFields(config: SecurityConfig?): Set<String> =
      RequestLogging.mergeSensitiveLogBodyFields(config?.logSensitiveBodyFields)

  /** Python `_resolve_max_scan_values` (detection_config.py:196). */
  public fun resolveMaxScanValues(config: SecurityConfig?): Int =
      config?.detectionMaxScanValues ?: DetectionScanContext.DEFAULT_MAX_SCAN_VALUES

  /** Python `_resolve_max_scan_chars` (detection_config.py:207). */
  public fun resolveMaxScanChars(config: SecurityConfig?): Int =
      config?.detectionMaxScanChars ?: DetectionScanContext.DEFAULT_MAX_SCAN_CHARS

  /** Python `_resolve_max_scan_seconds`. */
  public fun resolveMaxScanSeconds(config: SecurityConfig?): Double =
      config?.detectionMaxScanSeconds ?: DetectionScanContext.DEFAULT_MAX_SCAN_SECONDS

  /** Python `_resolve_max_json_depth` (detection_config.py:218). */
  public fun resolveMaxJsonDepth(config: SecurityConfig?): Int =
      config?.detectionMaxJsonDepth ?: DetectionScanContext.DEFAULT_MAX_JSON_DEPTH

  /** Python `_resolve_binary_min_run_length` (detection_config.py:229). */
  public fun resolveBinaryMinRunLength(config: SecurityConfig?): Int =
      config?.detectionBinaryMinRunLength ?: DetectionScanContext.DEFAULT_BINARY_MIN_RUN_LENGTH
}
