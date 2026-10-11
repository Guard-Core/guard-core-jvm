package com.guardcore.core.events

/**
 * Port of `guard_core/core/events/event_types.py`: the event-type constants (event_types.py:5-43),
 * metric constants (event_types.py:90-92), check-name registry (event_types.py:102-122) and
 * EventFilter (event_types.py:135-144). The enrichment keys (event_types.py:125-131) and the
 * EVENT_TYPE_VALUES / METRIC_TYPE_VALUES frozensets close with the W4b events wave.
 */
public object EventTypes {
  public const val EVENT_PENETRATION_ATTEMPT: String = "penetration_attempt"
  public const val EVENT_IP_BLOCKED: String = "ip_blocked"
  public const val EVENT_IP_BANNED: String = "ip_banned"
  public const val EVENT_IP_BAN_FAILED: String = "ip_ban_failed"
  public const val EVENT_IP_UNBANNED: String = "ip_unbanned"
  public const val EVENT_CLOUD_BLOCKED: String = "cloud_blocked"
  public const val EVENT_HTTPS_ENFORCED: String = "https_enforced"
  public const val EVENT_DECORATOR_VIOLATION: String = "decorator_violation"
  public const val EVENT_BEHAVIOR_VIOLATION: String = "behavioral_violation"
  public const val EVENT_PATTERN_DETECTED: String = "pattern_detected"
  public const val EVENT_DYNAMIC_RULE_UPDATED: String = "dynamic_rule_updated"
  public const val EVENT_DYNAMIC_RULE_APPLIED: String = "dynamic_rule_applied"
  public const val EVENT_DYNAMIC_RULE_VIOLATION: String = "dynamic_rule_violation"
  public const val EVENT_EMERGENCY_MODE: String = "emergency_mode_activated"

  public const val EVENT_ACCESS_DENIED: String = "access_denied"
  public const val EVENT_AUTHENTICATION_FAILED: String = "authentication_failed"
  public const val EVENT_CONTENT_FILTERED: String = "content_filtered"
  public const val EVENT_COUNTRY_BLOCKED: String = "country_blocked"
  public const val EVENT_CSP_VIOLATION: String = "csp_violation"
  public const val EVENT_CUSTOM_REQUEST_CHECK: String = "custom_request_check"
  public const val EVENT_DECODING_ERROR: String = "decoding_error"
  public const val EVENT_EMERGENCY_MODE_BLOCK: String = "emergency_mode_block"
  public const val EVENT_GEO_LOOKUP_FAILED: String = "geo_lookup_failed"
  public const val EVENT_PATH_EXCLUDED: String = "path_excluded"
  public const val EVENT_PATTERN_ADDED: String = "pattern_added"
  public const val EVENT_PATTERN_REMOVED: String = "pattern_removed"
  public const val EVENT_RATE_LIMITED: String = "rate_limited"
  public const val EVENT_RATE_LIMIT_SCRIPT_RELOADED: String = "rate_limit_script_reloaded"
  public const val EVENT_REDIS_CONNECTION: String = "redis_connection"
  public const val EVENT_REDIS_ERROR: String = "redis_error"
  public const val EVENT_ROUTE_UNRESOLVED: String = "route_unresolved"
  public const val EVENT_SECURITY_BYPASS: String = "security_bypass"
  public const val EVENT_SECURITY_HEADERS_APPLIED: String = "security_headers_applied"
  public const val EVENT_USER_AGENT_BLOCKED: String = "user_agent_blocked"
  public const val EVENT_SUSPICIOUS_REQUEST: String = "suspicious_request"
  public const val EVENT_DETECTION_ENGINE_CALLBACK_ERROR: String = "detection_engine_callback_error"
  public const val EVENT_PATTERN_ANOMALY_TIMEOUT: String = "pattern_anomaly_timeout"
  public const val EVENT_PATTERN_ANOMALY_SLOW_EXECUTION: String = "pattern_anomaly_slow_execution"
  public const val EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY: String =
      "pattern_anomaly_statistical_anomaly"

  public const val METRIC_RESPONSE_TIME: String = "response_time"
  public const val METRIC_REQUEST_COUNT: String = "request_count"
  public const val METRIC_ERROR_RATE: String = "error_rate"

  /** Port of `CHECK_NAME_VALUES` (event_types.py:102). */
  public val CHECK_NAME_VALUES: Set<String> =
      setOf(
          "authentication",
          "cloud_ip_refresh",
          "cloud_provider",
          "custom_request",
          "custom_validators",
          "emergency_mode",
          "https_enforcement",
          "ip_security",
          "rate_limit",
          "referrer",
          "request_logging",
          "request_size_content",
          "required_headers",
          "route_config",
          "suspicious_activity",
          "time_window",
          "user_agent",
      )
}

/** Port of `EventFilter` (event_types.py:135): muted event/metric sets with allow checks. */
public class EventFilter(
    public val mutedEventTypes: Set<String> = emptySet(),
    public val mutedMetricTypes: Set<String> = emptySet(),
) {
  public fun isEventAllowed(eventType: String): Boolean = eventType !in mutedEventTypes

  public fun isMetricAllowed(metricType: String): Boolean = metricType !in mutedMetricTypes
}
