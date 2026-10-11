package com.guardcore.core.events

/**
 * The guard-agent `SecurityEvent` telemetry envelope as a field map (guard_agent/models.py:208):
 * the model constructor's defaults (ip_address="", action_taken="", reason="", metadata={}, every
 * optional field null, idempotency_key=uuid4) applied to whatever the emitter passes, exactly like
 * the python emitters constructing `SecurityEvent(...)` and the bus/harness dumping the model. The
 * model class itself is the W7 agent seam; every emitter in the engine builds its events through
 * this helper so the observable envelope key set is the model's field set everywhere.
 */
public fun securityEventEnvelope(
    eventType: String,
    ipAddress: String = "",
    actionTaken: String = "",
    reason: String = "",
    country: String? = null,
    userAgent: String? = null,
    endpoint: String? = null,
    method: String? = null,
    statusCode: Int? = null,
    responseTime: Double? = null,
    decoratorType: String? = null,
    ruleType: String? = null,
    patternMatched: String? = null,
    handlerName: String? = null,
    metadata: Map<String, Any?> = emptyMap(),
): LinkedHashMap<String, Any?> =
    linkedMapOf(
        "idempotency_key" to java.util.UUID.randomUUID().toString(),
        "timestamp" to java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).toString(),
        "event_type" to eventType,
        "ip_address" to ipAddress,
        "country" to country,
        "user_agent" to userAgent,
        "action_taken" to actionTaken,
        "reason" to reason,
        "endpoint" to endpoint,
        "method" to method,
        "status_code" to statusCode,
        "response_time" to responseTime,
        "decorator_type" to decoratorType,
        "rule_type" to ruleType,
        "pattern_matched" to patternMatched,
        "handler_name" to handlerName,
        "metadata" to metadata,
    )
