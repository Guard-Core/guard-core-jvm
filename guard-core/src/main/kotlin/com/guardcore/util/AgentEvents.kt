package com.guardcore.util

import com.guardcore.protocols.AgentHandlerProtocol
import com.guardcore.protocols.GuardRequest
import java.util.concurrent.CompletionStage
import java.util.logging.Logger

/**
 * Port of `guard_core/_utils/agent_events.py` (agent_events.py:1-94): error-hook invocation,
 * pipeline response timing, and agent event dispatch.
 */
public object AgentEvents {
  private val logger: Logger = Logger.getLogger("guard_core")

  private const val IP_EXTRACTION_HANDLER_NAME = "ip_extraction"

  /** Port of `invoke_error_hook` (agent_events.py:15). */
  public fun invokeErrorHook(
      hook: SecurityConfigOnErrorHook?,
      stage: String,
      exc: Throwable,
      context: Map<String, Any?>,
  ) {
    if (hook == null) return
    try {
      hook.invoke(stage, exc, context)
    } catch (hookError: Exception) {
      logger.severe("on_error hook raised while handling '$stage': $hookError")
    }
  }

  /** The (stage, exception, context) callback shape of SecurityConfig.on_error. */
  public fun interface SecurityConfigOnErrorHook {
    public fun invoke(stage: String, exc: Throwable, context: Map<String, Any?>)
  }

  /**
   * Port of `get_pipeline_response_time` (agent_events.py:29). The Python version stores
   * `_guard_pipeline_start` on request.state; the JVM port stores it in the request state bag under
   * the same name. Python reads `time.monotonic()`; the JVM port uses System.nanoTime (also
   * monotonic) and converts to seconds.
   */
  public fun getPipelineResponseTime(request: GuardRequest?): Double? {
    if (request == null) return null
    var pipelineStart = request.state.getAttr("_guard_pipeline_start") as? Double
    if (pipelineStart == null) {
      pipelineStart = System.nanoTime() / 1_000_000_000.0
      request.state.setAttr("_guard_pipeline_start", pipelineStart)
    }
    return System.nanoTime() / 1_000_000_000.0 - pipelineStart
  }

  /**
   * Port of `send_agent_event` (agent_events.py:39-94). The Python version constructs the
   * guard-agent SecurityEvent telemetry model via `_pydantic_plugin_mute.get_telemetry_model`
   * (guard_agent/models.py:208); the model class itself is the W7 agent seam, so the event is
   * built as the same full field map (idempotency_key, timestamp, event_type, ip_address, country,
   * user_agent, action_taken, reason, endpoint, method, status_code, response_time,
   * decorator_type, rule_type, pattern_matched, handler_name, metadata; extra kwargs fold into
   * top-level model fields exactly like the `extra="allow"` construction) and handed to
   * `AgentHandlerProtocol.sendEvent`.
   */
  public suspend fun sendAgentEvent(
      agentHandler: AgentHandlerProtocol?,
      eventType: String,
      ipAddress: String,
      actionTaken: String,
      reason: String,
      request: GuardRequest? = null,
      metadata: Map<String, Any?> = emptyMap(),
      extra: Map<String, Any?> = emptyMap(),
  ) {
    if (agentHandler == null) return
    try {
      var endpoint: String? = null
      var method: String? = null
      var userAgent: String? = null
      if (request != null) {
        endpoint = request.urlPath
        method = request.method
        userAgent = request.headers["User-Agent"]
      }
      var meta = LinkedHashMap<String, Any?>(metadata)
      val decoratorType = extra["decorator_type"]
      val ruleType = extra["rule_type"]
      if (decoratorType != null) {
        meta["decorator_type"] = decoratorType
      }
      if (ruleType != null) {
        meta["rule_type"] = ruleType
      }
      val event =
          com.guardcore.core.events.securityEventEnvelope(
              eventType = eventType,
              ipAddress = ipAddress,
              country = null,
              userAgent = userAgent,
              actionTaken = actionTaken,
              reason = reason,
              endpoint = endpoint,
              method = method,
              responseTime = getPipelineResponseTime(request),
              decoratorType = decoratorType as? String,
              ruleType = ruleType as? String,
              handlerName = IP_EXTRACTION_HANDLER_NAME,
              metadata = meta,
          ) + extra.filterKeys { it !in setOf("decorator_type", "rule_type", "metadata") }
      agentHandler.sendEvent(event)
    } catch (e: Exception) {
      Logger.getLogger("guard_core.utils").severe("Failed to send agent event: $e")
    }
  }
}

/** Shared helper: await a Python-style awaitable result (CompletionStage). */
internal suspend fun awaitIfAwaitable(result: Any?) {
  if (result is CompletionStage<*>) {
    result.toCompletableFuture().get()
  }
}
