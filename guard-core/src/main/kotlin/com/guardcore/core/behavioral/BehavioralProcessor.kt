package com.guardcore.core.behavioral

import com.guardcore.config.SecurityConfig
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.applyAction
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.MiddlewareEventBusProtocol
import com.guardcore.util.RequestLogging
import java.util.logging.Logger

/**
 * Port of `guard_core/core/behavioral/context.py` (context.py:10): BehavioralContext, the
 * context-object DI carrier for [BehavioralProcessor].
 */
public class BehavioralContext(
    public val config: SecurityConfig,
    public val logger: Logger,
    public val eventBus: MiddlewareEventBusProtocol,
    public val guardDecorator: BaseSecurityDecorator?,
    public val behaviorTracker: BehaviorTracker? = null,
    public val middleware: Any? = null,
)

/**
 * Port of `guard_core/core/behavioral/processor.py` (processor.py:12): BehavioralProcessor. Runs
 * usage/frequency rules on the request path and return-pattern rules on the response path.
 */
public class BehavioralProcessor(
    public val context: BehavioralContext,
) {
  /** Python `_behavior_tracker` (processor.py:16). */
  private fun behaviorTracker(request: GuardRequest): BehaviorTracker? {
    if (request.state.getAttr("guard_exclusion_scoped") == true) {
      return null
    }
    context.behaviorTracker?.let {
      return it
    }
    var guardDecorator = context.guardDecorator
    if (guardDecorator == null) {
      guardDecorator = request.state.getAttr("guard_decorator") as? BaseSecurityDecorator
    }
    return guardDecorator?.behaviorTracker
  }

  /** Python async `process_usage_rules` (processor.py:28). */
  public suspend fun processUsageRules(
      request: GuardRequest,
      clientIp: String,
      routeConfig: RouteConfig,
  ) {
    val behaviorTracker = behaviorTracker(request) ?: return

    val endpointId = getEndpointId(request)
    for (rule in routeConfig.behaviorRules) {
      if (rule.ruleType == "usage" || rule.ruleType == "frequency") {
        val thresholdExceeded = behaviorTracker.trackEndpointUsage(endpointId, clientIp, rule)
        if (thresholdExceeded) {
          val details = "${rule.threshold} calls in ${rule.window}s"
          val message = "Behavioral ${rule.ruleType}"
          val reason = "threshold exceeded"
          val violationReason = "$message $reason: $details"

          val guardDecorator = context.guardDecorator
          if (guardDecorator != null) {
            guardDecorator.sendDecoratorViolationEvent(
                request,
                violationType = rule.ruleType,
                reason = violationReason,
                linkedMapOf(
                    "threshold" to rule.threshold,
                    "window" to rule.window,
                    "action" to rule.action,
                    "endpoint_id" to endpointId,
                ),
            )
          } else {
            context.eventBus.sendMiddlewareEvent(
                EventTypes.EVENT_DECORATOR_VIOLATION,
                request,
                "behavioral_action_triggered",
                violationReason,
                linkedMapOf(
                    "decorator_type" to "behavioral",
                    "violation_type" to rule.ruleType,
                    "threshold" to rule.threshold,
                    "window" to rule.window,
                    "action" to rule.action,
                    "endpoint_id" to endpointId,
                ),
            )
          }

          behaviorTracker.applyAction(
              rule,
              clientIp,
              endpointId,
              "Usage threshold exceeded: $details",
          )
        }
      }
    }
  }

  /** Python async `process_return_rules` (processor.py:79). */
  public suspend fun processReturnRules(
      request: GuardRequest,
      response: GuardResponse,
      clientIp: String,
      routeConfig: RouteConfig,
  ) {
    val behaviorTracker = behaviorTracker(request) ?: return

    val endpointId = getEndpointId(request)
    for (rule in routeConfig.behaviorRules) {
      if (rule.ruleType == "return_pattern") {
        val patternDetected =
            behaviorTracker.trackReturnPattern(endpointId, clientIp, response, rule)
        if (patternDetected) {
          val details = "${rule.threshold} for '${rule.pattern}' in ${rule.window}s"
          val violationReason = "Return pattern threshold exceeded: $details"

          val guardDecorator = context.guardDecorator
          if (guardDecorator != null) {
            guardDecorator.sendDecoratorViolationEvent(
                request,
                violationType = "return_pattern",
                reason = violationReason,
                linkedMapOf(
                    "threshold" to rule.threshold,
                    "window" to rule.window,
                    "pattern" to rule.pattern,
                    "action" to rule.action,
                    "endpoint_id" to endpointId,
                ),
            )
          } else {
            context.eventBus.sendMiddlewareEvent(
                EventTypes.EVENT_DECORATOR_VIOLATION,
                request,
                "behavioral_action_triggered",
                violationReason,
                linkedMapOf(
                    "decorator_type" to "behavioral",
                    "violation_type" to "return_pattern",
                    "threshold" to rule.threshold,
                    "window" to rule.window,
                    "pattern" to rule.pattern,
                    "action" to rule.action,
                    "endpoint_id" to endpointId,
                ),
            )
          }

          behaviorTracker.applyAction(
              rule,
              clientIp,
              endpointId,
              "Return pattern threshold exceeded: $details",
          )
        }
      }
    }
  }

  /** Python async `process_global_return_rules` (processor.py:134). */
  public suspend fun processGlobalReturnRules(
      request: GuardRequest,
      response: GuardResponse,
      clientIp: String,
      rules: List<BehaviorRule>,
  ) {
    val tracker = behaviorTracker(request) ?: return

    val endpointId = getEndpointId(request)
    val correlatedCategories = collectCorrelatedCategories(clientIp)

    for (rule in rules) {
      if (rule.ruleType != "return_pattern") {
        continue
      }
      evaluateGlobalReturnRule(
          tracker,
          request,
          response,
          clientIp,
          endpointId,
          rule,
          correlatedCategories,
      )
    }
  }

  /**
   * Python `_collect_correlated_categories` (processor.py:161):
   * middleware.suspicious_request_counts.
   */
  private fun collectCorrelatedCategories(clientIp: String): List<String> {
    val middleware = context.middleware ?: return emptyList()
    val counts =
        (middleware as? com.guardcore.protocols.GuardMiddlewareProtocol)?.suspiciousRequestCounts
            ?: return emptyList()
    val ipCounts = counts[clientIp]?.toMap() ?: emptyMap()
    return ipCounts.filterValues { it > 0 }.keys.sorted()
  }

  /** Python async `_evaluate_global_return_rule` (processor.py:168). */
  private suspend fun evaluateGlobalReturnRule(
      tracker: BehaviorTracker,
      request: GuardRequest,
      response: GuardResponse,
      clientIp: String,
      endpointId: String,
      rule: BehaviorRule,
      correlatedCategories: List<String>,
  ) {
    val correlationActive = rule.correlateWithDetection && correlatedCategories.isNotEmpty()
    val effectiveThreshold = if (correlationActive) maxOf(1, rule.threshold / 2) else rule.threshold

    val patternDetected =
        tracker.trackReturnPattern(
            endpointId,
            clientIp,
            response,
            rule,
            effectiveThreshold = effectiveThreshold,
        )
    if (!patternDetected) {
      return
    }

    val details =
        "$effectiveThreshold for '${rule.pattern}' in ${rule.window}s" +
            if (correlationActive) " (correlated)" else ""

    context.eventBus.sendMiddlewareEvent(
        EventTypes.EVENT_DECORATOR_VIOLATION,
        request,
        "behavioral_action_triggered",
        "Global return pattern threshold exceeded: $details",
        linkedMapOf(
            "decorator_type" to "behavioral_global",
            "violation_type" to "return_pattern",
            "threshold" to effectiveThreshold,
            "window" to rule.window,
            "pattern" to rule.pattern,
            "action" to rule.action,
            "endpoint_id" to endpointId,
            "correlation" to correlationActive,
            "correlated_categories" to if (correlationActive) correlatedCategories else emptyList(),
        ),
    )

    tracker.applyAction(
        rule,
        clientIp,
        endpointId,
        "Global return pattern threshold exceeded: $details",
    )
  }

  /** Python `get_endpoint_id` (processor.py:223). */
  public fun getEndpointId(request: GuardRequest): String {
    val routeId = request.state.getAttr("guard_route_id") as? String
    if (!routeId.isNullOrEmpty()) {
      return routeId
    }
    val endpointId = request.state.getAttr("guard_endpoint_id") as? String
    if (!endpointId.isNullOrEmpty()) {
      return endpointId
    }
    val safePath =
        RequestLogging.redactEndpointForDisplay(
            request.urlPath,
            context.config.logSensitiveParams,
            context.config.logSensitiveBodyFields,
            context.config.logSensitiveHeaders,
        )
    return "${request.method}:$safePath"
  }
}
