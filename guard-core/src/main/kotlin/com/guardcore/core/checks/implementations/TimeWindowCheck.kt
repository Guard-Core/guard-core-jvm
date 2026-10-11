package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.RequestLogging
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Port of `guard_core/core/checks/implementations/time_window.py`: TimeWindowCheck
 * (time_window.py:18).
 */
public class TimeWindowCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val checkName: String = "time_window"

  private val hourMinuteFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm")

  /** Python async `_check_time_window` (time_window.py:33). */
  private suspend fun checkTimeWindow(timeRestrictions: Map<String, String>): Boolean {
    return try {
      val startTime = timeRestrictions.getValue("start")
      val endTime = timeRestrictions.getValue("end")

      val timezoneStr = timeRestrictions["timezone"] ?: "UTC"
      val tz: ZoneId =
          try {
            ZoneId.of(timezoneStr)
          } catch (e: Exception) {
            ZoneOffset.UTC
          }
      val currentTime = LocalDateTime.now(tz)
      val currentHourMinute = currentTime.format(hourMinuteFormat)

      if (startTime > endTime) {
        currentHourMinute >= startTime || currentHourMinute <= endTime
      } else {
        startTime <= currentHourMinute && currentHourMinute <= endTime
      }
    } catch (e: Exception) {
      logger.severe("Error checking time window: $e")
      true
    }
  }

  /** Python async `check` (time_window.py:57). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig
    val timeRestrictions = routeConfig?.timeRestrictions
    if (routeConfig == null || timeRestrictions.isNullOrEmpty()) {
      return null
    }

    val timeAllowed = checkTimeWindow(timeRestrictions)
    if (!timeAllowed) {
      RequestLogging.logActivity(
          request,
          logger,
          logType = "suspicious",
          reason = "Access outside allowed time window",
          level = config.logSuspiciousLevel?.pythonName,
          passiveMode = config.passiveMode,
          checkName = checkName,
          mutedCheckLogs = config.mutedCheckLogs,
          onBlock = config.onBlock,
          sensitiveHeaders = config.logSensitiveHeaders,
          sensitiveParams = config.logSensitiveParams,
          sensitiveBodyFields = config.logSensitiveBodyFields,
      )
      ChecksHelpers.emitAccessDeniedEvent(
          middleware,
          request,
          eventType = EventTypes.EVENT_DECORATOR_VIOLATION,
          reason = "Access outside allowed time window",
          decoratorType = "advanced",
          passiveMode = config.passiveMode,
          linkedMapOf("violation_type" to "time_restriction"),
      )
      if (!config.passiveMode) {
        return middleware.createErrorResponse(403, "Access not allowed at this time")
      }
    }
    return null
  }

  public companion object : CheckCompanion<TimeWindowCheck>() {
    /** Python classmethod `applies_to` (time_window.py:23). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        ChecksHelpers.routeConfigApplies(routeConfigs) { rc ->
          !rc.timeRestrictions.isNullOrEmpty()
        }

    override fun create(middleware: GuardMiddlewareProtocol): TimeWindowCheck =
        TimeWindowCheck(middleware)
  }
}
