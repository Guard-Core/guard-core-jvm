package com.guardcore.protocols

/**
 * Port of `guard_core/protocols/agent_protocol.py` (agent_protocol.py:9): the telemetry sink that
 * ships security events and metrics off-box.
 */
public interface AgentHandlerProtocol {
  /** Python async `initialize_redis` (agent_protocol.py:18). */
  public suspend fun initializeRedis(redisHandler: RedisHandlerProtocol)

  /** Python async `send_event` (agent_protocol.py:21). Must not block or raise. */
  public suspend fun sendEvent(event: Any?)

  /** Python async `send_metric` (agent_protocol.py:24). Must not block or raise. */
  public suspend fun sendMetric(metric: Any?)

  /** Python async `start` (agent_protocol.py:27). */
  public suspend fun start()

  /** Python async `stop` (agent_protocol.py:30). Must be idempotent. */
  public suspend fun stop()

  /** Python async `flush_buffer` (agent_protocol.py:33). */
  public suspend fun flushBuffer()

  /** Python async `get_dynamic_rules` (agent_protocol.py:36). */
  public suspend fun getDynamicRules(): Any?

  /** Python async `health_check` (agent_protocol.py:39). */
  public suspend fun healthCheck(): Boolean
}
