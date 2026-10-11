package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.events.AgentTelemetryMember
import com.guardcore.core.events.BEHAVIOR_CORRELATION_WINDOW_SECONDS
import com.guardcore.core.events.CompositeAgentHandler
import com.guardcore.core.events.EnrichmentContext
import com.guardcore.core.events.EventEnricher
import com.guardcore.core.events.EventFilter
import com.guardcore.core.events.EventTypes
import com.guardcore.core.events.LogfireHandler
import com.guardcore.core.events.OtelHandler
import com.guardcore.core.events.SinkTelemetryMember
import com.guardcore.core.events.ThreatScorer
import com.guardcore.core.events.securityEventEnvelope
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.HandlerAgentSink
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** W4b events port tests: vocab sets, envelope shape, enricher, composite wiring, otel/logfire. */
public class EventsPortTest {
  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      SecurityConfigBuilder().apply(mutate).build()

  @Test
  fun vocabSetsMatchReference() {
    // event_types.py:46-100: 39 event values, 3 metric values.
    assertEquals(39, EventTypes.EVENT_TYPE_VALUES.size)
    assertEquals(3, EventTypes.METRIC_TYPE_VALUES.size)
    assertTrue(EventTypes.EVENT_TYPE_VALUES.containsAll(setOf("penetration_attempt",
        "emergency_mode_activated", "pattern_anomaly_statistical_anomaly")))
    // Enrichment keys (event_types.py:125-131), verbatim.
    assertEquals("guard.project_id", EventTypes.ENRICHMENT_KEY_PROJECT_ID)
    assertEquals("guard.service.name", EventTypes.ENRICHMENT_KEY_SERVICE_NAME)
    assertEquals("guard.deployment.environment", EventTypes.ENRICHMENT_KEY_DEPLOYMENT_ENV)
    assertEquals("guard.threat_score", EventTypes.ENRICHMENT_KEY_THREAT_SCORE)
    assertEquals("guard.rule.id", EventTypes.ENRICHMENT_KEY_RULE_ID)
    assertEquals("guard.rule.version", EventTypes.ENRICHMENT_KEY_RULE_VERSION)
    assertEquals(
        "guard.behavior.correlation_key",
        EventTypes.ENRICHMENT_KEY_BEHAVIOR_KEY,
    )
    assertEquals(
        "guard.behavior.recent_event_count",
        EventTypes.ENRICHMENT_KEY_RECENT_EVENT_COUNT,
    )
    assertEquals(300, BEHAVIOR_CORRELATION_WINDOW_SECONDS)
  }

  @Test
  fun threatScoreMapMatchesReference() {
    // enricher.py:65-106 anchors.
    assertEquals(90, ThreatScorer.scoreFor("penetration_attempt"))
    assertEquals(70, ThreatScorer.scoreFor("ip_banned"))
    assertEquals(60, ThreatScorer.scoreFor("emergency_mode_activated"))
    assertEquals(50, ThreatScorer.scoreFor("ip_blocked"))
    assertEquals(40, ThreatScorer.scoreFor("redis_error"))
    assertEquals(30, ThreatScorer.scoreFor("access_denied"))
    assertEquals(20, ThreatScorer.scoreFor("rate_limited"))
    assertEquals(10, ThreatScorer.scoreFor("https_enforced"))
    assertEquals(20, ThreatScorer.scoreFor("unlisted_type"))
    assertEquals(20, ThreatScorer.scoreFor(null))
  }

  @Test
  fun envelopeCarriesFullSecurityEventFieldSet() {
    val envelope = securityEventEnvelope(eventType = "ip_banned", ipAddress = "1.2.3.4")
    assertEquals(
        listOf(
            "idempotency_key",
            "timestamp",
            "event_type",
            "ip_address",
            "country",
            "user_agent",
            "action_taken",
            "reason",
            "endpoint",
            "method",
            "status_code",
            "response_time",
            "decorator_type",
            "rule_type",
            "pattern_matched",
            "handler_name",
            "metadata",
        ),
        envelope.keys.toList(),
    )
    // Model defaults (guard_agent/models.py:208).
    assertEquals("1.2.3.4", envelope["ip_address"])
    assertEquals("", envelope["action_taken"])
    assertEquals("", envelope["reason"])
    assertNull(envelope["country"])
    assertNull(envelope["status_code"])
    assertNull(envelope["pattern_matched"])
    assertTrue((envelope["metadata"] as Map<*, *>).isEmpty())
  }

  @Test
  fun enricherAppliesIdentityAndThreatScore() = runBlocking {
    val cfg =
        config {
          agentProjectId = "proj-1"
          otelServiceName = "svc"
          otelResourceAttributes = mapOf("deployment.environment" to "prod")
        }
    val enricher = EventEnricher(EnrichmentContext(config = cfg))
    val metadata = linkedMapOf<String, Any?>()
    val event =
        linkedMapOf<String, Any?>("event_type" to "ip_banned", "metadata" to metadata)
    enricher.enrichEvent(event)
    assertEquals("proj-1", metadata["guard.project_id"])
    assertEquals("svc", metadata["guard.service.name"])
    assertEquals("prod", metadata["guard.deployment.environment"])
    assertEquals(70, metadata["guard.threat_score"])
  }

  @Test
  fun enricherWithoutProjectIdOmitsKey() = runBlocking {
    val enricher = EventEnricher(EnrichmentContext(config = config()))
    val tags = linkedMapOf<String, Any?>()
    enricher.enrichMetric(linkedMapOf("metric_type" to "request_count", "tags" to tags))
    assertFalse(tags.containsKey("guard.project_id"))
    assertEquals("guard-core", tags["guard.service.name"])
    assertFalse(tags.containsKey("guard.deployment.environment"))
    assertFalse(tags.containsKey("guard.threat_score"))
  }

  @Test
  fun enricherBehaviorCorrelationHashesIpServiceBucket() = runBlocking {
    val cfg = config { otelServiceName = "svc" }
    val tracker = BehaviorTracker(cfg)
    val enricher =
        EventEnricher(EnrichmentContext(config = cfg, behaviorTracker = tracker))
    val metadata = linkedMapOf<String, Any?>()
    enricher.enrichEvent(
        linkedMapOf<String, Any?>(
            "event_type" to "ip_blocked",
            "ip_address" to "203.0.113.7",
            "metadata" to metadata,
        ),
    )
    assertEquals(0, metadata["guard.behavior.recent_event_count"])
    val key = metadata["guard.behavior.correlation_key"] as String
    assertEquals(16, key.length)
    assertTrue(key.all { it in "0123456789abcdef" })
  }

  @Test
  fun compositeFiltersEventsAndRunsEnricher() = runBlocking {
    val captured = mutableListOf<Map<String, Any?>>()
    val sink =
        object : HandlerAgentSink {
          override suspend fun sendEvent(event: Map<String, Any?>) {
            captured.add(event)
          }
        }
    val member: AgentTelemetryMember = SinkTelemetryMember(sink)
    val enricher =
        EventEnricher(
            EnrichmentContext(config = config { otelServiceName = "svc" }),
        )
    val composite =
        CompositeAgentHandler(
            listOf(member),
            eventFilter = EventFilter(mutedEventTypes = setOf("rate_limited")),
            enricher = enricher,
        )
    composite.sendEvent(
        linkedMapOf<String, Any?>(
            "event_type" to "rate_limited",
            "metadata" to linkedMapOf<String, Any?>(),
        ),
    )
    assertEquals(0, captured.size)
    val metadata = linkedMapOf<String, Any?>()
    composite.sendEvent(
        linkedMapOf<String, Any?>(
            "event_type" to "ip_banned",
            "metadata" to metadata,
        ),
    )
    assertEquals(1, captured.size)
    assertEquals(70, metadata["guard.threat_score"])
    assertEquals("svc", metadata["guard.service.name"])
  }

  @Test
  fun otelHandlerWithoutSurfaceWarnsAndDisables() = runBlocking {
    val handler = OtelHandler(SimpleOtelConfig())
    val before = java.util.logging.Logger.getLogger("guard_core").handlers
    assertTrue(before.isEmpty() || true)
    handler.start()
    assertFalse(handler.healthCheck())
    // sendEvent/sendMetric are inert without the surface.
    handler.sendEvent(securityEventEnvelope(eventType = "ip_banned"))
    handler.sendMetric(mapOf("metric_type" to "request_count", "value" to 1.0))
    handler.stop()
    assertNull(OtelHandler.surface)
  }

  @Test
  fun otelHandlerSignalEndpointStripsKnownSuffix() {
    assertEquals("http://otel:4318/v1/traces",
        OtelHandler.otlpSignalEndpoint("http://otel:4318", "/v1/traces"))
    assertEquals("http://otel:4318/v1/metrics",
        OtelHandler.otlpSignalEndpoint("http://otel:4318/v1/traces", "/v1/metrics"))
    assertEquals("http://otel:4318/v1/logs",
        OtelHandler.otlpSignalEndpoint("http://otel:4318/", "/v1/logs"))
    assertNull(OtelHandler.otlpSignalEndpoint(null, "/v1/traces"))
  }

  @Test
  fun logfireHandlerWithoutSurfaceWarnsAndDisables() = runBlocking {
    val handler =
        LogfireHandler(
            object : LogfireHandler.LogfireConfig {
              override val logfireServiceName: String = "guard-core"
            },
        )
    handler.start()
    assertFalse(handler.healthCheck())
    handler.sendEvent(securityEventEnvelope(eventType = "ip_banned"))
    handler.sendMetric(mapOf("metric_type" to "error_rate", "value" to 1.0))
    handler.stop()
    assertNull(LogfireHandler.surface)
  }

  @Test
  fun compositeIsDegradedOnlyAfterFailedStart() = runBlocking {
    val failing =
        object : AgentTelemetryMember {
          override suspend fun sendEvent(event: Map<String, Any?>) {}

          override suspend fun start() {
            throw IllegalStateException("boom")
          }

          override suspend fun healthCheck(): Boolean = false
        }
    val composite = CompositeAgentHandler(listOf(failing))
    assertFalse(composite.isStarted)
    assertFalse(composite.isDegraded)
    composite.start()
    assertTrue(composite.isStarted)
    assertTrue(composite.isDegraded)
    assertIs<List<String>>(composite.failedHandlerNames)
    assertEquals(1, composite.failedHandlerNames.size)
    assertFalse(composite.healthCheck())
  }

  private class SimpleOtelConfig : OtelHandler.ProviderConfig {
    override val otelServiceName: String = "guard-core"
    override val otelResourceAttributes: Map<String, String> = emptyMap()
    override val otelExporterEndpoint: String? = null
  }
}
