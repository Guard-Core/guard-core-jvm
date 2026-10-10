package com.guardcore.config

/**
 * Port of `guard_core/core/events/event_types.py` (event_types.py:1-122): the
 * event/metric/check-name value sets the muted_* config fields validate against, plus the
 * enrichment keys and the EventFilter helper.
 */
public object EventTypes {
  // Event name constants (event_types.py:5-44), verbatim values.
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

  /** Port of `EVENT_TYPE_VALUES` (event_types.py:46). */
  public val EVENT_TYPE_VALUES: Set<String> =
      setOf(
          EVENT_PENETRATION_ATTEMPT,
          EVENT_IP_BLOCKED,
          EVENT_IP_BANNED,
          EVENT_IP_BAN_FAILED,
          EVENT_IP_UNBANNED,
          EVENT_CLOUD_BLOCKED,
          EVENT_HTTPS_ENFORCED,
          EVENT_DECORATOR_VIOLATION,
          EVENT_BEHAVIOR_VIOLATION,
          EVENT_PATTERN_DETECTED,
          EVENT_DYNAMIC_RULE_UPDATED,
          EVENT_DYNAMIC_RULE_APPLIED,
          EVENT_DYNAMIC_RULE_VIOLATION,
          EVENT_EMERGENCY_MODE,
          EVENT_ACCESS_DENIED,
          EVENT_AUTHENTICATION_FAILED,
          EVENT_CONTENT_FILTERED,
          EVENT_COUNTRY_BLOCKED,
          EVENT_CSP_VIOLATION,
          EVENT_CUSTOM_REQUEST_CHECK,
          EVENT_DECODING_ERROR,
          EVENT_EMERGENCY_MODE_BLOCK,
          EVENT_GEO_LOOKUP_FAILED,
          EVENT_PATH_EXCLUDED,
          EVENT_PATTERN_ADDED,
          EVENT_PATTERN_REMOVED,
          EVENT_RATE_LIMITED,
          EVENT_RATE_LIMIT_SCRIPT_RELOADED,
          EVENT_REDIS_CONNECTION,
          EVENT_REDIS_ERROR,
          EVENT_ROUTE_UNRESOLVED,
          EVENT_SECURITY_BYPASS,
          EVENT_SECURITY_HEADERS_APPLIED,
          EVENT_USER_AGENT_BLOCKED,
          EVENT_SUSPICIOUS_REQUEST,
          EVENT_DETECTION_ENGINE_CALLBACK_ERROR,
          EVENT_PATTERN_ANOMALY_TIMEOUT,
          EVENT_PATTERN_ANOMALY_SLOW_EXECUTION,
          EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY,
      )

  // Metric constants (event_types.py:90-92).
  public const val METRIC_RESPONSE_TIME: String = "response_time"
  public const val METRIC_REQUEST_COUNT: String = "request_count"
  public const val METRIC_ERROR_RATE: String = "error_rate"

  /** Port of `METRIC_TYPE_VALUES` (event_types.py:94). */
  public val METRIC_TYPE_VALUES: Set<String> =
      setOf(METRIC_RESPONSE_TIME, METRIC_REQUEST_COUNT, METRIC_ERROR_RATE)

  /** Port of `CHECK_NAME_VALUES` (event_types.py:102-122), verbatim. */
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

  // Enrichment keys (event_types.py:125-132).
  public const val ENRICHMENT_KEY_PROJECT_ID: String = "guard.project_id"
  public const val ENRICHMENT_KEY_SERVICE_NAME: String = "guard.service.name"
  public const val ENRICHMENT_KEY_DEPLOYMENT_ENV: String = "guard.deployment.environment"
  public const val ENRICHMENT_KEY_THREAT_SCORE: String = "guard.threat_score"
  public const val ENRICHMENT_KEY_RULE_ID: String = "guard.rule.id"
  public const val ENRICHMENT_KEY_RULE_VERSION: String = "guard.rule.version"
  public const val ENRICHMENT_KEY_BEHAVIOR_KEY: String = "guard.behavior.correlation_key"
  public const val ENRICHMENT_KEY_RECENT_EVENT_COUNT: String = "guard.behavior.recent_event_count"
}

/** Port of the `EventFilter` dataclass (event_types.py:135-144). */
public class EventFilter(
    public val mutedEventTypes: Set<String> = emptySet(),
    public val mutedMetricTypes: Set<String> = emptySet(),
) {
  /** Port of `is_event_allowed` (event_types.py:140). */
  public fun isEventAllowed(eventType: String): Boolean = eventType !in mutedEventTypes

  /** Port of `is_metric_allowed` (event_types.py:142). */
  public fun isMetricAllowed(metricType: String): Boolean = metricType !in mutedMetricTypes
}
