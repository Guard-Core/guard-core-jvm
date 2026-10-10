package com.guardcore.util

import com.guardcore.config.BlockHook
import com.guardcore.protocols.GuardRequest
import java.util.logging.Logger

/**
 * Port of `guard_core/_utils/block_events.py` (block_events.py:1-91): on_block hook invocation and
 * block payload construction.
 */
public object BlockEvents {
  private val logger: Logger = Logger.getLogger("guard_core")

  /** Port of `ON_BLOCK_EXCLUDED_CHECK_NAMES` (block_events.py:11). */
  public val ON_BLOCK_EXCLUDED_CHECK_NAMES: Set<String> =
      setOf("custom_request", "custom_validators", "https_enforcement")

  /** Port of `invoke_block_hook` (block_events.py:16). */
  public suspend fun invokeBlockHook(
      hook: BlockHook?,
      request: GuardRequest,
      payload: Map<String, Any?>,
  ) {
    if (hook == null) return
    try {
      val result = hook.invoke(request, payload)
      awaitIfAwaitable(result)
    } catch (hookError: Exception) {
      logger.severe("on_block hook raised: $hookError")
    }
  }

  /** Port of `build_block_payload` (block_events.py:31-63). */
  public fun buildBlockPayload(
      request: GuardRequest,
      checkName: String,
      reason: String,
      triggerInfo: String,
      passiveMode: Boolean,
      statusCode: Int?,
      sensitiveParams: Set<String>? = null,
      sensitiveBodyFields: Set<String>? = null,
      sensitiveHeaders: Set<String>? = null,
  ): Map<String, Any?> {
    val cachedIp = request.state.getAttr("client_ip") as? String
    val clientIp =
        when {
          !cachedIp.isNullOrEmpty() -> cachedIp
          request.clientHost != null -> IpExtraction.canonicalizeIp(request.clientHost!!)
          else -> IpExtraction.UNKNOWN_CLIENT_IDENTITY
        }
    return linkedMapOf(
        "check_name" to checkName,
        "reason" to reason,
        "trigger_info" to triggerInfo,
        "passive_mode" to passiveMode,
        "client_ip" to clientIp,
        "path" to
            RequestLogging.redactUrlForDisplay(
                request.urlPath,
                sensitiveParams,
                sensitiveBodyFields,
                sensitiveHeaders,
            ),
        "method" to request.method,
        "status_code" to statusCode,
    )
  }

  /** Port of `fire_block_hook` (block_events.py:66-91). */
  public suspend fun fireBlockHook(
      hook: BlockHook?,
      request: GuardRequest,
      checkName: String,
      reason: String,
      triggerInfo: String,
      passiveMode: Boolean,
      statusCode: Int?,
      sensitiveParams: Set<String>? = null,
      sensitiveBodyFields: Set<String>? = null,
      sensitiveHeaders: Set<String>? = null,
  ) {
    if (hook == null || checkName in ON_BLOCK_EXCLUDED_CHECK_NAMES) return
    val payload =
        buildBlockPayload(
            request,
            checkName,
            reason,
            triggerInfo,
            passiveMode,
            statusCode,
            sensitiveParams,
            sensitiveBodyFields,
            sensitiveHeaders,
        )
    invokeBlockHook(hook, request, payload)
  }

  /**
   * Port of the `_guard_block_stash` write (request_logging.py:413): stash the block reason on the
   * request state for the response path.
   */
  public fun setBlockStash(request: GuardRequest, stash: Map<String, Any?>) {
    request.state.setAttr("_guard_block_stash", stash)
  }
}
