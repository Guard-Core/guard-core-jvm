package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.checks.Verifier
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.RequestLogging

/**
 * Port of `guard_core/core/checks/implementations/custom_validators.py`: CustomValidatorsCheck
 * (custom_validators.py:13).
 */
public class CustomValidatorsCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val checkName: String = "custom_validators"

  /** Python async `check` (custom_validators.py:28). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig
    val validators = routeConfig?.customValidators
    if (routeConfig == null || validators.isNullOrEmpty()) {
      return null
    }

    for (validator in validators) {
      val validationResponse = validator(request)
      if (Verifier.truthy(validationResponse)) {
        RequestLogging.logActivity(
            request,
            logger,
            logType = "suspicious",
            reason = "Custom validation failed",
            level = config.logSuspiciousLevel?.pythonName,
            passiveMode = config.passiveMode,
            checkName = checkName,
            mutedCheckLogs = config.mutedCheckLogs,
            onBlock = config.onBlock,
            sensitiveHeaders = config.logSensitiveHeaders,
            sensitiveParams = config.logSensitiveParams,
            sensitiveBodyFields = config.logSensitiveBodyFields,
        )

        ChecksHelpers.emitDecoratorEvent(
            middleware,
            request,
            eventType = EventTypes.EVENT_DECORATOR_VIOLATION,
            actionTaken = if (!config.passiveMode) "request_blocked" else "logged_only",
            reason = "Custom validation failed",
            decoratorType = "content_filtering",
            linkedMapOf(
                "violation_type" to "custom_validation",
                "validator_name" to (validatorName(validator)),
            ),
        )
        if (!config.passiveMode && validationResponse is GuardResponse) {
          return validationResponse
        }
      }
    }
    return null
  }

  /** Python `getattr(validator, "__name__", "anonymous")` (custom_validators.py:61). */
  private fun validatorName(validator: suspend (GuardRequest) -> Any?): String =
      (validator as? NamedValidator)?.name ?: "anonymous"

  public companion object : CheckCompanion<CustomValidatorsCheck>() {
    /** Python classmethod `applies_to` (custom_validators.py:18). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        ChecksHelpers.routeConfigApplies(routeConfigs) { rc -> rc.customValidators.isNotEmpty() }

    override fun create(middleware: GuardMiddlewareProtocol): CustomValidatorsCheck =
        CustomValidatorsCheck(middleware)
  }
}

/** JVM idiom for python's function `__name__`: validators may implement this to be named. */
public interface NamedValidator {
  public val name: String

  public suspend fun validate(request: GuardRequest): Any?
}
