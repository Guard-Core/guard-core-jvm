package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.CloudManager
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse

/**
 * Port of `guard_core/core/checks/implementations/cloud_ip_refresh.py`: CloudIpRefreshCheck
 * (cloud_ip_refresh.py:16).
 */
public class CloudIpRefreshCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val requires: List<String> = listOf("cloud")

  override val containerFields: List<String> = listOf("block_cloud_providers")

  /** Python `__init__` (cloud_ip_refresh.py:20): the module-singleton cloud handler. */
  private val cloudHandler: CloudManager = CloudManager.getInstance()

  override val checkName: String = "cloud_ip_refresh"

  /** Python async `check` (cloud_ip_refresh.py:40). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig
    val cloudProvidersToCheck = middleware.routeResolver?.getCloudProvidersToCheck(routeConfig)
    if (cloudProvidersToCheck.isNullOrEmpty()) {
      return null
    }

    if (
        System.currentTimeMillis() / 1000 - middleware.lastCloudIpRefresh >
            config.cloudIpRefreshInterval
    ) {
      val previousRefresh = middleware.lastCloudIpRefresh
      middleware.lastCloudIpRefresh = (System.currentTimeMillis() / 1000).toInt()
      val scheduled =
          cloudHandler.scheduleRefresh(
              cloudProvidersToCheck.toSet(),
              ttl = config.cloudIpRefreshInterval,
              refresh = { middleware.refreshCloudIpRanges() },
          )
      if (!scheduled) {
        middleware.lastCloudIpRefresh = previousRefresh
      }
    }
    return null
  }

  public companion object : CheckCompanion<CloudIpRefreshCheck>() {
    /** Python classmethod `applies_to` (cloud_ip_refresh.py:30). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        config.blockCloudProviders?.isNotEmpty() == true ||
            ChecksHelpers.routeConfigApplies(routeConfigs) { rc ->
              rc.blockCloudProviders.isNotEmpty()
            }

    override val containerFields: List<String> = listOf("block_cloud_providers")

    override fun create(middleware: GuardMiddlewareProtocol): CloudIpRefreshCheck =
        CloudIpRefreshCheck(middleware)
  }
}
