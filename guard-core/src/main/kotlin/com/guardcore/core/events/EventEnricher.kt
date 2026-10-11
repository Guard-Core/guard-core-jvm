package com.guardcore.core.events

import com.guardcore.config.SecurityConfig
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.DynamicRuleEvent
import com.guardcore.handlers.DynamicRuleManager
import java.security.MessageDigest
import java.util.logging.Logger

/**
 * Port of `guard_core/core/events/enricher.py`: the threat-score table (enricher.py:65-105),
 * [ThreatScorer] (enricher.py:111), [EnrichmentContext] (enricher.py:117) and [EventEnricher]
 * (enricher.py:125) writing the `guard.*` enrichment keys into the event metadata / metric tags.
 */
public object ThreatScorer {
  /** Port of `_THREAT_SCORE_MAP` (enricher.py:65). */
  private val THREAT_SCORE_MAP: Map<String, Int> =
      mapOf(
          EventTypes.EVENT_PENETRATION_ATTEMPT to 90,
          EventTypes.EVENT_IP_BANNED to 70,
          EventTypes.EVENT_EMERGENCY_MODE to 60,
          EventTypes.EVENT_IP_BLOCKED to 50,
          EventTypes.EVENT_BEHAVIOR_VIOLATION to 50,
          EventTypes.EVENT_CLOUD_BLOCKED to 50,
          EventTypes.EVENT_COUNTRY_BLOCKED to 50,
          EventTypes.EVENT_DECORATOR_VIOLATION to 50,
          EventTypes.EVENT_AUTHENTICATION_FAILED to 50,
          EventTypes.EVENT_EMERGENCY_MODE_BLOCK to 50,
          EventTypes.EVENT_DYNAMIC_RULE_VIOLATION to 50,
          EventTypes.EVENT_PATTERN_DETECTED to 50,
          EventTypes.EVENT_SUSPICIOUS_REQUEST to 50,
          EventTypes.EVENT_DYNAMIC_RULE_APPLIED to 40,
          EventTypes.EVENT_CSP_VIOLATION to 40,
          EventTypes.EVENT_CONTENT_FILTERED to 40,
          EventTypes.EVENT_CUSTOM_REQUEST_CHECK to 40,
          EventTypes.EVENT_DECODING_ERROR to 40,
          EventTypes.EVENT_REDIS_ERROR to 40,
          EventTypes.EVENT_IP_BAN_FAILED to 40,
          EventTypes.EVENT_DETECTION_ENGINE_CALLBACK_ERROR to 40,
          EventTypes.EVENT_PATTERN_ANOMALY_TIMEOUT to 40,
          EventTypes.EVENT_PATTERN_ANOMALY_SLOW_EXECUTION to 40,
          EventTypes.EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY to 40,
          EventTypes.EVENT_ACCESS_DENIED to 30,
          EventTypes.EVENT_USER_AGENT_BLOCKED to 30,
          EventTypes.EVENT_SECURITY_BYPASS to 30,
          EventTypes.EVENT_RATE_LIMITED to 20,
          EventTypes.EVENT_GEO_LOOKUP_FAILED to 20,
          EventTypes.EVENT_REDIS_CONNECTION to 20,
          EventTypes.EVENT_ROUTE_UNRESOLVED to 20,
          EventTypes.EVENT_IP_UNBANNED to 10,
          EventTypes.EVENT_HTTPS_ENFORCED to 10,
          EventTypes.EVENT_DYNAMIC_RULE_UPDATED to 10,
          EventTypes.EVENT_PATH_EXCLUDED to 10,
          EventTypes.EVENT_PATTERN_ADDED to 10,
          EventTypes.EVENT_PATTERN_REMOVED to 10,
          EventTypes.EVENT_RATE_LIMIT_SCRIPT_RELOADED to 10,
          EventTypes.EVENT_SECURITY_HEADERS_APPLIED to 10,
      )

  /** Port of `_DEFAULT_THREAT_SCORE` (enricher.py:106). */
  private const val DEFAULT_THREAT_SCORE: Int = 20

  /** Port of `ThreatScorer.score_for` (enricher.py:112). */
  public fun scoreFor(eventType: String?): Int =
      if (eventType == null) DEFAULT_THREAT_SCORE
      else THREAT_SCORE_MAP.getOrDefault(eventType, DEFAULT_THREAT_SCORE)
}

/** Port of `_BEHAVIOR_CORRELATION_WINDOW_SECONDS` (enricher.py:108). */
public const val BEHAVIOR_CORRELATION_WINDOW_SECONDS: Int = 300

/** Port of `EnrichmentContext` (enricher.py:117). */
public class EnrichmentContext(
    public val config: SecurityConfig,
    public val agentHandler: Any? = null,
    public val dynamicRuleHandler: DynamicRuleManager? = null,
    public val behaviorTracker: BehaviorTracker? = null,
)

/**
 * Port of `EventEnricher` (enricher.py:125): mutates the event's metadata bag / metric's tags bag
 * in place with identity, threat-score, rule-correlation and behavior-correlation enrichments.
 * Enrichment failures log and leave the event unenriched (enricher.py:139).
 */
public class EventEnricher(
    private val context: EnrichmentContext,
) {
  public val logger: Logger = Logger.getLogger("guard_core.enricher")

  /** Port of `enrich_event` (enricher.py:129). */
  public suspend fun enrichEvent(event: Map<String, Any?>) {
    try {
      @Suppress("UNCHECKED_CAST")
      val metadata = event["metadata"] as? MutableMap<String, Any?> ?: return
      applyIdentity(metadata)
      applyThreatScore(event, metadata)
      applyRuleCorrelation(event, metadata)
      applyBehaviorCorrelation(event, metadata)
    } catch (e: Exception) {
      logger.severe("event enrichment failed; event will be sent unenriched: $e")
    }
  }

  /** Port of `enrich_metric` (enricher.py:141). */
  public suspend fun enrichMetric(metric: Map<String, Any?>) {
    try {
      @Suppress("UNCHECKED_CAST") val tags = metric["tags"] as? MutableMap<String, Any?> ?: return
      applyIdentity(tags)
    } catch (e: Exception) {
      logger.severe("metric enrichment failed; metric will be sent unenriched: $e")
    }
  }

  /** Port of `_apply_identity` (enricher.py:150). */
  private fun applyIdentity(bag: MutableMap<String, Any?>) {
    val cfg = context.config
    if (cfg.agentProjectId != null) {
      bag[EventTypes.ENRICHMENT_KEY_PROJECT_ID] = cfg.agentProjectId
    }
    bag[EventTypes.ENRICHMENT_KEY_SERVICE_NAME] = cfg.otelServiceName
    val env = cfg.otelResourceAttributes["deployment.environment"]
    if (!env.isNullOrEmpty()) {
      bag[EventTypes.ENRICHMENT_KEY_DEPLOYMENT_ENV] = env
    }
  }

  /** Port of `_apply_threat_score` (enricher.py:159). */
  private fun applyThreatScore(event: Map<String, Any?>, bag: MutableMap<String, Any?>) {
    val eventType = event["event_type"] as? String ?: return
    bag[EventTypes.ENRICHMENT_KEY_THREAT_SCORE] = ThreatScorer.scoreFor(eventType)
  }

  /** Port of `_apply_rule_correlation` (enricher.py:165). */
  private fun applyRuleCorrelation(
      event: Map<String, Any?>,
      bag: MutableMap<String, Any?>,
  ) {
    val ruleHandler = context.dynamicRuleHandler ?: return
    val match =
        ruleHandler.matchEvent(
            object : DynamicRuleEvent {
              override val ipAddress: String?
                get() = event["ip_address"] as? String

              override val country: String?
                get() = event["country"] as? String

              override val eventType: String?
                get() = event["event_type"] as? String
            },
        ) ?: return
    bag[EventTypes.ENRICHMENT_KEY_RULE_ID] = match.first
    bag[EventTypes.ENRICHMENT_KEY_RULE_VERSION] = match.second
  }

  /** Port of `_apply_behavior_correlation` (enricher.py:176). */
  private suspend fun applyBehaviorCorrelation(
      event: Map<String, Any?>,
      bag: MutableMap<String, Any?>,
  ) {
    val tracker = context.behaviorTracker ?: return
    val ip = event["ip_address"] as? String
    if (ip.isNullOrEmpty()) {
      return
    }
    val windowSeconds = BEHAVIOR_CORRELATION_WINDOW_SECONDS
    val count = tracker.getRecentEventCount(ip, windowSeconds)
    bag[EventTypes.ENRICHMENT_KEY_RECENT_EVENT_COUNT] = count
    val bucket = System.currentTimeMillis() / 1000 / windowSeconds
    val service = context.config.otelServiceName
    val raw = "$ip|$service|$bucket".encodeToByteArray()
    val digest = MessageDigest.getInstance("SHA-256").digest(raw)
    val hex = StringBuilder(digest.size * 2)
    for (byte in digest) {
      val v = byte.toInt() and 0xff
      hex.append("0123456789abcdef"[(v ushr 4) and 0xf])
      hex.append("0123456789abcdef"[v and 0xf])
    }
    bag[EventTypes.ENRICHMENT_KEY_BEHAVIOR_KEY] = hex.substring(0, 16)
  }
}
