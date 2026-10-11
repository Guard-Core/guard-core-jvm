package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.CloudManager
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.RequestLogging

/**
 * Port of `guard_core/core/checks/implementations/cloud_provider.py`: CloudProviderCheck
 * (cloud_provider.py:20).
 */
public class CloudProviderCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val requires: List<String> = listOf("cloud")

  override val containerFields: List<String> = listOf("block_cloud_providers")

  /** Python `__init__` (cloud_provider.py:24). */
  private val cloudHandler: CloudManager = CloudManager.getInstance()

  override val checkName: String = "cloud_provider"

  /** Python async `_emit_cloud_block_events` (cloud_provider.py:95). */
  private suspend fun emitCloudBlockEvents(
      request: GuardRequest,
      clientIp: String,
      cloudProvidersToCheck: List<String>,
      routeConfig: RouteConfig?,
  ) {
    val routeBlocksClouds = routeConfig?.blockCloudProviders?.isNotEmpty() == true

    middleware.eventBus?.sendCloudDetectionEvents(
        request,
        clientIp,
        cloudProvidersToCheck,
        if (routeBlocksClouds) null else routeConfig,
        cloudHandler,
        config.passiveMode,
    )

    if (!routeBlocksClouds) {
      return
    }

    ChecksHelpers.emitAccessDeniedEvent(
        middleware,
        request,
        eventType = EventTypes.EVENT_DECORATOR_VIOLATION,
        reason = "Cloud provider IP $clientIp blocked",
        decoratorType = "block_clouds",
        passiveMode = config.passiveMode,
        linkedMapOf(
            "violation_type" to "cloud_provider",
            "blocked_providers" to cloudProvidersToCheck.toList(),
        ),
    )
  }

  /** Python async `check` (cloud_provider.py:44). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    if (
        request.state.getAttr("is_whitelisted") == true ||
            request.state.getAttr("is_exempt") == true
    ) {
      return null
    }

    val clientIp = request.state.getAttr("client_ip") as? String
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig
    if (clientIp.isNullOrEmpty()) {
      return null
    }

    if (middleware.routeResolver?.shouldBypassCheck("clouds", routeConfig) == true) {
      return null
    }

    val cloudProvidersToCheck = middleware.routeResolver?.getCloudProvidersToCheck(routeConfig)
    if (cloudProvidersToCheck.isNullOrEmpty()) {
      return null
    }

    if (!cloudHandler.isCloudIp(clientIp, cloudProvidersToCheck.toSet())) {
      return null
    }

    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "Blocked cloud provider IP: $clientIp",
        level = config.logSuspiciousLevel?.pythonName,
        passiveMode = config.passiveMode,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    emitCloudBlockEvents(request, clientIp, cloudProvidersToCheck, routeConfig)

    if (!config.passiveMode) {
      return middleware.createErrorResponse(403, "Cloud provider IP not allowed")
    }

    return null
  }

  public companion object : CheckCompanion<CloudProviderCheck>() {
    /** Python classmethod `applies_to` (cloud_provider.py:34). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        config.blockCloudProviders?.isNotEmpty() == true ||
            config.enableDynamicRules ||
            ChecksHelpers.routeConfigApplies(routeConfigs) { rc ->
              rc.blockCloudProviders.isNotEmpty()
            }

    override val containerFields: List<String> = listOf("block_cloud_providers")

    override fun create(middleware: GuardMiddlewareProtocol): CloudProviderCheck =
        CloudProviderCheck(middleware)
  }
}
