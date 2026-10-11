package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse

/**
 * Port of `guard_core/core/checks/implementations/custom_request.py`: CustomRequestCheck
 * (custom_request.py:11).
 */
public class CustomRequestCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val checkName: String = "custom_request"

  /** Python async `check` (custom_request.py:24). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val customRequestCheck = config.customRequestCheck ?: return null

    val customResponse = customRequestCheck.invoke(request)
    if (customResponse != null) {
      middleware.eventBus?.sendMiddlewareEvent(
          EventTypes.EVENT_CUSTOM_REQUEST_CHECK,
          request,
          if (!config.passiveMode) "request_blocked" else "logged_only",
          "Custom request check returned blocking response",
          linkedMapOf(
              "response_status" to customResponse.statusCode,
              "check_function" to (checkFunctionName() ?: "anonymous"),
          ),
      )

      if (!config.passiveMode) {
        val modified = middleware.responseFactory?.applyModifier(customResponse)
        return modified
      }
    }
    return null
  }

  /**
   * Python `self.config.custom_request_check.__name__` (custom_request.py:40): JVM fun interfaces
   * carry no function name, so named checks implement [com.guardcore.config.CustomRequestCheck]
   * objects exposing a name through their class simple name.
   */
  private fun checkFunctionName(): String? =
      config.customRequestCheck?.let { it::class.java.simpleName.ifEmpty { null } }

  public companion object : CheckCompanion<CustomRequestCheck>() {
    /** Python classmethod `applies_to` (custom_request.py:16). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean = config.customRequestCheck != null

    override fun create(middleware: GuardMiddlewareProtocol): CustomRequestCheck =
        CustomRequestCheck(middleware)
  }
}
