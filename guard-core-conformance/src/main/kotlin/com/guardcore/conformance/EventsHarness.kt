package com.guardcore.conformance

import com.guardcore.config.CustomRequestCheck
import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.bypass.BypassContext
import com.guardcore.core.bypass.BypassHandler
import com.guardcore.core.checks.ChecksFactory
import com.guardcore.core.checks.SecurityCheckPipeline
import com.guardcore.core.events.MetricsCollector
import com.guardcore.core.events.SecurityEventBus
import com.guardcore.core.responses.ErrorResponseFactory
import com.guardcore.core.responses.ResponseContext
import com.guardcore.core.routing.RouteConfigResolver
import com.guardcore.core.routing.RoutingContext
import com.guardcore.core.validation.RequestValidator
import com.guardcore.core.validation.ValidationContext
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.decorators.RouteConfig
import com.guardcore.decorators.RouteConfigRevision
import com.guardcore.engine.detection.AnomalyEventSink
import com.guardcore.engine.detection.PerformanceMonitor
import com.guardcore.handlers.applyAction
import com.guardcore.handlers.banIp
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.CloudManager
import com.guardcore.handlers.DynamicRuleManager
import com.guardcore.handlers.DynamicRules
import com.guardcore.handlers.HandlerAgentSink
import com.guardcore.handlers.initializeBanAgent
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.IpInfoManager
import com.guardcore.handlers.RateLimitManager
import com.guardcore.handlers.RedisManager
import com.guardcore.handlers.SecurityHeadersManager
import com.guardcore.handlers.SusPatternsRegistry
import com.guardcore.handlers.resetIpBanGlobalState
import com.guardcore.handlers.unbanIp
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.MiddlewareResponseFactoryProtocol
import com.guardcore.protocols.RequestState
import com.guardcore.protocols.RouteConfigResolverProtocol
import java.nio.file.Files
import java.nio.file.Path
import java.util.logging.Logger
import kotlinx.coroutines.runBlocking

/**
 * The W4b events runner: the Kotlin port of `specs/fixtures/tools/events_harness.py`. Drives the
 * REAL guard-core event surface in-process and captures the FULL telemetry envelope of every
 * emitted SecurityEvent, the same way the W4a [PipelineHarness] drives the check pipeline.
 *
 * Comparison follows index.json comparison.events_envelopes: the observed stream is the ordered
 * flat list of captured envelopes (volatile fields dropped recursively at capture time), and only
 * the keys present in each expected envelope are compared.
 */
public object EventsHarness {
  init {
    com.guardcore.handlers.HandlerSeams.register()
    com.guardcore.util.DetectionEngineWiring.register()
  }

  /** Python `EVENTS_REDIS_PREFIX` / `EVENTS_REDIS_URL` / `EVENTS_REDIS_ERROR_URL`. */
  public const val EVENTS_REDIS_PREFIX: String = "guard_core:corpus_evts:"
  public const val EVENTS_REDIS_URL: String = "redis://localhost:6379/0"
  public const val EVENTS_REDIS_ERROR_URL: String = "redis://localhost:59999/0"

  /**
   * Volatile envelope fields (events_harness.py:89): identity (uuid4), wall-clock timestamps and
   * timing-derived measurements, dropped recursively at capture time.
   */
  private val EVENT_DROP_KEYS: Set<String> =
      setOf(
          "idempotency_key",
          "timestamp",
          "response_time",
          "execution_time",
          "execution_time_ms",
      )

  /** Python `EVENTS_CONFIG_KEYS` (events_harness.py:99): pipeline keys plus the events knobs. */
  private val EVENTS_CONFIG_KEYS: Set<String> =
      PipelineHarness.configKeys() +
          setOf(
              "agent_api_key",
              "auto_ban_duration",
              "enable_agent",
              "block_cloud_providers",
              "custom_request_check",
              "detection_anomaly_threshold",
              "detection_min_samples_for_anomaly",
              "detection_slow_pattern_threshold",
              "emergency_mode",
              "emergency_whitelist",
              "enable_dynamic_rules",
              "enable_redis",
              "redis_prefix",
              "redis_url",
              "enforce_https",
              "exclude_paths",
              "route_resolution_strict",
              "trusted_proxies",
          )

  /** Python `EVENTS_ROUTE_KEYS` (events_harness.py:120). */
  private val EVENTS_ROUTE_KEYS: Set<String> =
      PipelineHarness.routeKeys() +
          setOf(
              "auth_required",
              "block_cloud_providers",
              "max_request_size",
              "require_https",
          )

  /** Python `_normalize` (events_harness.py:128): volatile drop + 6-decimal floats. */
  public fun normalize(value: Any?): Any? =
      when (value) {
        is Map<*, *> ->
            value.entries
                .filter { it.key.toString() !in EVENT_DROP_KEYS }
                .associate { it.key.toString() to normalize(it.value) }
        is List<*> -> value.map { normalize(it) }
        is Double -> EventsComparison.round6(value)
        is Float -> EventsComparison.round6(value.toDouble())
        else -> value
      }

  /** Python `event_envelope` (events_harness.py:142) over the map-shaped envelope. */
  public fun eventEnvelope(event: Map<String, Any?>): Map<String, Any?> =
      normalize(event) as Map<String, Any?>

  /** Python `CapturingAgentHandler` (events_harness.py:170). */
  public class CapturingAgentHandler(
      private val sink: MutableList<Map<String, Any?>>,
  ) : HandlerAgentSink {
    override suspend fun sendEvent(event: Map<String, Any?>) {
      sink.add(eventEnvelope(event))
    }
  }

  /** Python `_CorpusRulesAgent` (events_harness.py:180). */
  public class CorpusRulesAgent(
      private val sink: MutableList<Map<String, Any?>>,
      private val rules: DynamicRules,
  ) : DynamicRuleManager.AgentDynamicRulesSource {
    override suspend fun getDynamicRules(): DynamicRules = rules

    override suspend fun sendEvent(event: Map<String, Any?>) {
      sink.add(eventEnvelope(event))
    }
  }

  /** Python `_EventsResponseFactory` (events_harness.py:191): modifier passthrough. */
  public class EventsResponseFactory : MiddlewareResponseFactoryProtocol {
    override fun createResponse(content: Any?, statusCode: Int): GuardResponse {
      val body = content as? String ?: content?.toString() ?: ""
      return PipelineHarness.StubResponse(statusCode, body)
    }

    override fun createRedirectResponse(url: Any?, statusCode: Int): GuardResponse {
      val response = PipelineHarness.StubResponse(statusCode)
      response.headers["Location"] = url.toString()
      return response
    }

    override suspend fun createHttpsRedirect(request: GuardRequest): GuardResponse =
        createRedirectResponse(request.urlReplaceScheme("https"), 301)

    override suspend fun applyModifier(response: GuardResponse): GuardResponse = response
  }

  public val EVENTS_RESPONSE_FACTORY: EventsResponseFactory = EventsResponseFactory()

  /** Python `corpus_reject_all` (events_harness.py:202): 418 "corpus rejected". */
  public class `corpus_reject_all` : CustomRequestCheck {
    override suspend fun invoke(request: GuardRequest): GuardResponse =
        EVENTS_RESPONSE_FACTORY.createResponse("corpus rejected", 418)
  }

  /** Python `_StubRouteResolver` over the events routes. */
  public class StubEventsRouteResolver(
      private val routes: Map<String, RouteConfig>,
  ) : RouteConfigResolverProtocol {
    override fun getRouteConfig(request: GuardRequest): RouteConfig? = routes[request.urlPath]

    override fun shouldBypassCheck(checkName: String, routeConfig: Any?): Boolean {
      val rc = routeConfig as? RouteConfig ?: return false
      return checkName in rc.bypassedChecks || "all" in rc.bypassedChecks
    }

    override fun getCloudProvidersToCheck(routeConfig: Any?): List<String>? {
      val rc = routeConfig as? RouteConfig ?: return null
      return if (rc.blockCloudProviders.isEmpty()) null else rc.blockCloudProviders.toList()
    }
  }

  /** Python `_EventsMiddleware` (events_harness.py:253): real bus wired to the capturing handler. */
  public class EventsMiddleware(
      override val config: SecurityConfig,
      public val rateLimitHandlerValue: RateLimitManager,
      public val geoIpHandlerValue: GeoIPHandler?,
      routes: Map<String, RouteConfig>,
      public val realEventBus: SecurityEventBus,
      public val capturingAgent: CapturingAgentHandler,
  ) : GuardMiddlewareProtocol {
    override val logger: Logger = Logger.getLogger("corpus.events_harness")
    override var lastCloudIpRefresh: Int = 0
    override val suspiciousRequestCounts: MutableMap<String, MutableMap<String, Int>> =
        linkedMapOf()
    override val eventBus: SecurityEventBus = realEventBus
    override val routeResolver: RouteConfigResolverProtocol = StubEventsRouteResolver(routes)
    override val guardDecorator: Any? = null
    override val responseFactory: MiddlewareResponseFactoryProtocol = EVENTS_RESPONSE_FACTORY
    override val rateLimitHandler: Any? = rateLimitHandlerValue
    override val agentHandler: com.guardcore.protocols.AgentHandlerProtocol? =
        SecurityEventBus.sinkAsAgentProtocol(capturingAgent)
    override val geoIpHandler: GeoIPHandler? = geoIpHandlerValue
    override val guardResponseFactory: com.guardcore.protocols.GuardResponseFactory? = null

    override suspend fun createErrorResponse(
        statusCode: Int,
        defaultMessage: String,
    ): GuardResponse =
        PipelineHarness.createHarnessErrorResponse(config, statusCode, defaultMessage)

    override suspend fun refreshCloudIpRanges() {}
  }

  /** Python `_PipelineRequest` over the events drives, with a removable state bag. */
  public class EventsPipelineRequest
  private constructor(
      drive: Map<String, Any?>,
      headerMap: Map<String, String>,
      private val bodyBytes: ByteArray,
  ) : GuardRequest {
    override val urlPath: String = (drive["url_path"] as? String) ?: "/api"
    override val urlScheme: String = "http"
    override val urlFull: String = "http://example.com$urlPath"
    override val method: String = (drive["method"] as? String) ?: "GET"
    override val clientHost: String = drive["client_ip"].toString()
    override val headers: Map<String, String> = PipelineHarness.CaseInsensitiveHeaders(headerMap)
    override val queryParams: Map<String, String> = emptyMap()
    override val state: RequestState = RemovableRequestState()
    override val scope: Map<String, Any?> = emptyMap()

    override fun urlReplaceScheme(scheme: String): String = "$scheme://example.com"

    override suspend fun body(): ByteArray = bodyBytes

    public companion object {
      public fun of(drive: Map<String, Any?>): EventsPipelineRequest {
        @Suppress("UNCHECKED_CAST")
        val rawHeaders = (drive["headers"] as? Map<String, String>) ?: emptyMap()
        val mutable = rawHeaders.mapKeys { it.key.lowercase() }.toMutableMap()
        val bodyBytes = (drive["body"] as? String ?: "").encodeToByteArray()
        if (bodyBytes.isNotEmpty() && "content-length" !in mutable) {
          mutable["content-length"] = bodyBytes.size.toString()
        }
        return EventsPipelineRequest(drive, mutable, bodyBytes)
      }
    }
  }

  /** The python `request.state` bag with attribute deletion (events_harness.py:362). */
  public class RemovableRequestState : RequestState {
    private val attrs: MutableMap<String, Any?> = linkedMapOf()

    override fun getAttr(name: String): Any? = attrs[name]

    override fun setAttr(name: String, value: Any?) {
      attrs[name] = value
    }

    public fun removeAttr(name: String) {
      attrs.remove(name)
    }
  }

  /** Python `_make_events_config` (events_harness.py:209) with the redis-op overrides. */
  private fun makeEventsConfig(
      caseConfig: Map<String, Any?>,
      geo: PipelineHarness.StubGeoHandler,
      overrides: Map<String, Any?> = emptyMap(),
  ): SecurityConfig {
    val builder = SecurityConfigBuilder()
    // DEFAULT_STATE (pipeline_harness.py:104) via the W4a defaults.
    builder.enableRedis = false
    builder.enableRateLimitAutoBan = false
    builder.enableIpBanning = false
    builder.autoBanThreshold = 1000
    val merged = LinkedHashMap<String, Any?>()
    for ((key, value) in caseConfig) {
      if (key in EVENTS_CONFIG_KEYS) merged[key] = value
    }
    for ((key, value) in overrides) {
      merged[key] = value
    }
    var wantsGeo =
        caseConfig.containsKey("blocked_countries") ||
            caseConfig.containsKey("whitelist_countries")
    for ((key, value) in merged) {
      if (key == "custom_request_check") continue
      if (key == "blocked_countries" || key == "whitelist_countries") wantsGeo = true
      applyConfigKey(builder, key, value, geo)
    }
    if (wantsGeo) {
      builder.geoIpHandler = geo
    }
    if (merged["custom_request_check"] == "corpus_reject_all") {
      builder.customRequestCheck = `corpus_reject_all`()
    }
    return builder.build()
  }

  /** The events-only config keys on top of the W4a pipeline key mapping. */
  private fun applyConfigKey(
      builder: SecurityConfigBuilder,
      key: String,
      value: Any?,
      geo: PipelineHarness.StubGeoHandler,
  ) {
    when (key) {
      "agent_api_key" -> builder.agentApiKey = value?.toString()
      "auto_ban_duration" -> builder.autoBanDuration = (value as Number).toInt()
      "enable_agent" -> builder.enableAgent = value as Boolean
      "block_cloud_providers" ->
          builder.blockCloudProviders = (value as List<*>).map { it.toString() }.toSet()
      "detection_anomaly_threshold" -> builder.detectionAnomalyThreshold = value as Double
      "detection_min_samples_for_anomaly" ->
          builder.detectionMinSamplesForAnomaly = (value as Number).toInt()
      "detection_slow_pattern_threshold" ->
          builder.detectionSlowPatternThreshold = value as Double
      "emergency_mode" -> builder.emergencyMode = value as Boolean
      "emergency_whitelist" ->
          builder.emergencyWhitelist = (value as List<*>).map { it.toString() }
      "enable_dynamic_rules" -> builder.enableDynamicRules = value as Boolean
      "enable_redis" -> builder.enableRedis = value as Boolean
      "redis_prefix" -> builder.redisPrefix = value.toString()
      "redis_url" -> builder.redisUrl = value.toString()
      "enforce_https" -> builder.enforceHttps = value as Boolean
      "exclude_paths" -> builder.excludePaths = (value as List<*>).map { it.toString() }
      "route_resolution_strict" -> builder.routeResolutionStrict = value as Boolean
      "trusted_proxies" -> builder.trustedProxies = (value as List<*>).map { it.toString() }
      else -> PipelineHarness.applyPipelineConfigKey(builder, key, value, geo)
    }
  }

  /** Python `_build_events_route` (events_harness.py:237). */
  private fun buildEventsRoute(path: String, overrides: Map<String, Any?>): RouteConfig {
    val routeConfig = RouteConfig(RouteConfigRevision())
    for ((key, value) in overrides) {
      if (key !in EVENTS_ROUTE_KEYS) continue
      when (key) {
        "auth_required" -> routeConfig.authRequired = value.toString()
        "block_cloud_providers" ->
            routeConfig.blockCloudProviders =
            (value as List<*>).map { it.toString() }.toMutableSet()
        "max_request_size" -> routeConfig.maxRequestSize = (value as Number).toInt()
        "require_https" -> routeConfig.requireHttps = value as Boolean
        "rate_limit" -> routeConfig.rateLimit = (value as Number).toInt()
        "rate_limit_window" -> routeConfig.rateLimitWindow = (value as Number).toInt()
        "ip_whitelist" -> routeConfig.ipWhitelist = (value as List<*>).map { it.toString() }
        "ip_blacklist" -> routeConfig.ipBlacklist = (value as List<*>).map { it.toString() }
        "blocked_countries" ->
            routeConfig.blockedCountries = (value as List<*>).map { it.toString() }
        "whitelist_countries" ->
            routeConfig.whitelistCountries = (value as List<*>).map { it.toString() }
        "blocked_user_agents" ->
            routeConfig.blockedUserAgents =
                (value as List<*>).map { it.toString() }.toMutableList()
        "bypassed_checks" ->
            routeConfig.bypassedChecks = (value as List<*>).map { it.toString() }.toMutableSet()
        "enable_suspicious_detection" -> routeConfig.enableSuspiciousDetection = value as Boolean
        "excluded_detection_headers" ->
            routeConfig.excludedDetectionHeaders =
                (value as List<*>).map { it.toString() }.toSet()
        "excluded_detection_params" ->
            routeConfig.excludedDetectionParams = (value as List<*>).map { it.toString() }.toSet()
        "excluded_detection_body_fields" ->
            routeConfig.excludedDetectionBodyFields =
                (value as List<*>).map { it.toString() }.toSet()
        "geo_rate_limits" -> {
          @Suppress("UNCHECKED_CAST") val map = value as Map<String, List<Number>>
          routeConfig.geoRateLimits = map.mapValues { (_, lw) -> lw[0].toInt() to lw[1].toInt() }
        }
      }
      routeConfig.touch()
    }
    return routeConfig
  }

  /** Python `EventsCase` (events_harness.py:320). */
  public class EventsCase(case: Map<String, Any?>) {
    public val caseConfig: Map<String, Any?> = case["config"] as? Map<String, Any?> ?: emptyMap()
    public val sink: MutableList<Map<String, Any?>> = mutableListOf()
    public val agent: CapturingAgentHandler = CapturingAgentHandler(sink)
    public val geo: PipelineHarness.StubGeoHandler =
        PipelineHarness.StubGeoHandler(
            (case["geo_countries"] as? Map<String, String>) ?: emptyMap(),
        )
    public val config: SecurityConfig = makeEventsConfig(caseConfig, geo)
    public val routes: Map<String, RouteConfig> =
        (case["routes"] as? Map<String, Map<String, Any?>>)
            ?.mapValues { (path, overrides) -> buildEventsRoute(path, overrides) }
            ?: emptyMap()
    public val eventBus: SecurityEventBus = SecurityEventBus(agent, config, geo)
    public val rateLimitHandler: RateLimitManager = RateLimitManager.getInstance(config)
    public val middleware: EventsMiddleware =
        EventsMiddleware(config, rateLimitHandler, geo, routes, eventBus, agent)
    public val pipeline: SecurityCheckPipeline = ChecksFactory.buildDefaultPipeline(middleware)

    public suspend fun prepare() {
      resetIpBanGlobalState()
      IpBanManager.getInstance().banIpOverride = null
      SecurityHeadersManager.getInstance().headersCache.clear()
      rateLimitHandler.reset()
      rateLimitHandler.initializeAgent(agent)
    }

    /** Python `_redis_op_config` (events_harness.py:539-545): the redis-scoped config copy. */
    public fun redisOpConfig(redisUrl: String, enableRateLimiting: Boolean? = null): SecurityConfig {
      val overrides =
          linkedMapOf<String, Any?>(
              "enable_redis" to true,
              "redis_url" to redisUrl,
              "redis_prefix" to EVENTS_REDIS_PREFIX,
          )
      if (enableRateLimiting != null) {
        overrides["enable_rate_limiting"] = enableRateLimiting
      }
      return makeEventsConfig(caseConfig, geo, overrides)
    }
  }

  /** Python `run_events_case` (events_harness.py:673). */
  public fun runCase(case: Map<String, Any?>): List<Map<String, Any?>> = runBlocking {
    val harness = EventsCase(case)
    val cloud = CloudManager.getInstance()
    val savedAgentHandler = cloud.agentHandler
    val savedIpOverride = cloud.isCloudIpOverride
    val savedDetailsOverride = cloud.cloudProviderDetailsOverride
    try {
      harness.prepare()
      val drives = case["drives"] as? List<Map<String, Any?>> ?: emptyList()
      for (step in drives) {
        if (step["call"] == "cloud_stub") {
          val provider = (step["provider"] as? String) ?: "AWS"
          val network = (step["network"] as? String) ?: "203.0.113.0/24"
          cloud.agentHandler = harness.agent
          cloud.isCloudIpOverride = { _, _ -> true }
          cloud.cloudProviderDetailsOverride = { _, _ -> provider to network }
          continue
        }
        val call = step["call"] as? String
        if (call != null) {
          callOp(harness, call, step)
        } else {
          drive(harness, step)
        }
      }
    } finally {
      cloud.agentHandler = savedAgentHandler
      cloud.isCloudIpOverride = savedIpOverride
      cloud.cloudProviderDetailsOverride = savedDetailsOverride
      IpBanManager.getInstance().banIpOverride = null
      // Detach every singleton agent handler this case may have wired
      // (events_harness.py:707-712).
      SusPatternsRegistry.agentHandler = null
      SecurityHeadersManager.getInstance().initializeHeadersAgent(null)
      RateLimitManager.getInstance(harness.config).initializeAgent(null)
    }
    harness.sink
  }

  /** Python `_drive` (events_harness.py:355). */
  private suspend fun drive(harness: EventsCase, step: Map<String, Any?>) {
    val request = EventsPipelineRequest.of(step)
    if (step["guard_route_unresolved"] == true) {
      request.state.setAttr("guard_route_unresolved", true)
    }
    if (step["drop_cached_client_ip"] == true) {
      (request.state as? RemovableRequestState)?.removeAttr("client_ip")
    }
    harness.pipeline.execute(request)
  }

  /** Python `_call` dispatch (events_harness.py:365) - one op per handler-owned event seam. */
  private suspend fun callOp(harness: EventsCase, op: String, step: Map<String, Any?>) {
    when (op) {
      "ban_ip" -> {
        val manager = IpBanManager.getInstance()
        manager.initializeBanAgent(harness.agent)
        manager.banIp(
            step["ip"].toString(),
            (step["duration"] as? Number)?.toInt() ?: 3600,
            (step["reason"] as? String) ?: "corpus_ban",
        )
      }
      "unban_ip" -> {
        val manager = IpBanManager.getInstance()
        manager.initializeBanAgent(harness.agent)
        manager.unbanIp(step["ip"].toString())
      }
      "ipban_fault" -> {
        // events_harness.py:383-387: make ban_ip raise, exercising the ban-escalation failure.
        IpBanManager.getInstance().banIpOverride = { _, _, _ ->
          throw IllegalStateException("corpus injected ban failure")
        }
      }
      "detect" -> {
        SusPatternsRegistry.agentHandler = harness.agent
        SusPatternsRegistry.detect(
            step["content"].toString(),
            (step["ip"] as? String) ?: "203.0.113.7",
            (step["context"] as? String) ?: "body",
        )
      }
      "add_pattern" -> {
        SusPatternsRegistry.agentHandler = harness.agent
        SusPatternsRegistry.clearCustomPatternsForCorpus()
        val added = SusPatternsRegistry.addPattern(step["pattern"].toString(), custom = true)
        check(added) { "corpus pattern rejected: ${step["pattern"]}" }
      }
      "remove_pattern" -> {
        SusPatternsRegistry.agentHandler = harness.agent
        val pattern = step["pattern"].toString()
        SusPatternsRegistry.seedCustomPatternForCorpus(pattern)
        val removed = SusPatternsRegistry.removePattern(pattern, custom = true)
        check(removed) { "corpus pattern not removed: $pattern" }
      }
      "monitor_anomaly" -> {
        val monitor =
            PerformanceMonitor(
                anomalyThreshold = (step["anomaly_threshold"] as? Number)?.toDouble() ?: 3.0,
                slowPatternThreshold =
                    (step["slow_pattern_threshold"] as? Number)?.toDouble() ?: 0.1,
                minSamplesForAnomaly =
                    (step["min_samples_for_anomaly"] as? Number)?.toInt() ?: 10,
            )
        val sink = AnomalyEventSink { event ->
          kotlinx.coroutines.runBlocking { harness.agent.sendEvent(event) }
        }
        @Suppress("UNCHECKED_CAST")
        val samples = step["samples"] as? List<Map<String, Any?>> ?: emptyList()
        for (sample in samples) {
          monitor.recordMetric(
              sample["pattern"].toString(),
              (sample["execution_time"] as? Number)?.toDouble() ?: 0.0,
              (sample["content_length"] as? Number)?.toInt() ?: 128,
              matched = sample["matched"] as? Boolean ?: false,
              timeout = sample["timeout"] as? Boolean ?: false,
              agentHandler = sink,
          )
        }
      }
      "monitor_callback_fault" -> {
        val monitor = PerformanceMonitor(minSamplesForAnomaly = 10)
        monitor.registerAnomalyCallback { _ ->
          throw IllegalStateException("corpus injected callback failure")
        }
        val sink = AnomalyEventSink { event ->
          kotlinx.coroutines.runBlocking { harness.agent.sendEvent(event) }
        }
        monitor.recordMetric(
            step["pattern"].toString(),
            (step["execution_time"] as? Number)?.toDouble() ?: 0.5,
            128,
            matched = false,
            agentHandler = sink,
        )
      }
      "dynamic_rules" -> {
        DynamicRuleManager.resetInstance()
        val manager = DynamicRuleManager.getInstance(harness.config)
        @Suppress("UNCHECKED_CAST") val payload = step["rules"] as Map<String, Any?>
        manager.agentHandler = CorpusRulesAgent(harness.sink, rulesFromPayload(payload))
        try {
          manager.updateRules()
        } finally {
          DynamicRuleManager.resetInstance()
        }
      }
      "decorator_event" -> {
        val request = EventsPipelineRequest.of(step)
        val decorator = BaseSecurityDecorator(harness.config)
        decorator.initializeAgent(harness.agent, harness.geo)
        @Suppress("UNCHECKED_CAST")
        val kwargs = (step["kwargs"] as? Map<String, Any?>) ?: emptyMap()
        when (step["send"]) {
          "send_access_denied_event" ->
              decorator.sendAccessDeniedEvent(
                  request,
                  kwargs["reason"].toString(),
                  kwargs["decorator_type"].toString(),
                  kwargs.filterKeys { it != "reason" && it != "decorator_type" },
              )
          "send_authentication_failed_event" ->
              decorator.sendAuthenticationFailedEvent(
                  request,
                  kwargs["reason"].toString(),
                  kwargs["auth_type"].toString(),
                  kwargs.filterKeys { it != "reason" && it != "auth_type" },
              )
          else -> error("unknown decorator sender ${step["send"]}")
        }
      }
      "behavior_action" -> {
        val tracker = BehaviorTracker(harness.config)
        tracker.initializeAgent(harness.agent)
        @Suppress("UNCHECKED_CAST") val rulePayload = step["rule"] as Map<String, Any?>
        val rule =
            BehaviorRule(
                ruleType = rulePayload["rule_type"].toString(),
                threshold = (rulePayload["threshold"] as Number).toInt(),
                window = (rulePayload["window"] as? Number)?.toInt() ?: 3600,
                pattern = rulePayload["pattern"]?.toString(),
                action = (rulePayload["action"] as? String) ?: "log",
            )
        tracker.applyAction(
            rule,
            step["ip"].toString(),
            (step["endpoint_id"] as? String) ?: "corpus.endpoint",
            (step["details"] as? String) ?: "Usage threshold exceeded: 1 calls in 60s",
        )
      }
      "csp_report" -> {
        val manager = SecurityHeadersManager.getInstance()
        manager.initializeHeadersAgent(harness.agent)
        @Suppress("UNCHECKED_CAST")
        val valid = manager.validateCspReport(step["report"] as Map<String, Any?>)
        check(valid) { "corpus CSP report was rejected as invalid" }
      }
      "headers_applied" -> {
        val manager = SecurityHeadersManager.getInstance()
        manager.initializeHeadersAgent(harness.agent)
        manager.headersCache.clear()
        manager.getHeaders(step["path"].toString(), config = harness.config)
      }
      "geo_country_stub" -> {
        val handler = IpInfoManager.getInstance("corpus-token")
        val country = (step["country"] as? String) ?: "CN"
        handler.agentHandler = harness.agent
        handler.countryLookupOverride = { _ -> country }
        try {
          @Suppress("UNCHECKED_CAST")
          handler.checkCountryAccess(
              step["ip"].toString(),
              (step["blocked_countries"] as? List<String>) ?: listOf("CN"),
          )
        } finally {
          handler.countryLookupOverride = null
          handler.agentHandler = null
        }
      }
      "geo_download_failure" -> {
        val handler = IpInfoManager.getInstance("corpus-token")
        val savedPath = handler.dbPath
        handler.agentHandler = harness.agent
        handler.dbPath = Files.createTempDirectory("guard_jvm_corpus_geo").resolve("corpus.mmdb")
        handler.setInitializationAttempted(false)
        handler.setReaderForTests(null)
        val savedDownload = handler.downloadOverride
        handler.downloadOverride = { throw RuntimeException("corpus injected download failure") }
        try {
          handler.initialize()
        } finally {
          handler.downloadOverride = savedDownload
          handler.agentHandler = null
          handler.dbPath = savedPath
        }
      }
      "redis_connect" -> {
        redisOpReset(harness)
        val manager = RedisManager.getInstance(harness.redisOpConfig(EVENTS_REDIS_URL))
        manager.initializeAgent(harness.agent)
        try {
          manager.initialize()
        } finally {
          // Python: manager._closed = True; await manager._discard_client() (no close event).
          manager.discardClientQuietlyForCorpus()
        }
      }
      "redis_connect_error" -> {
        redisOpReset(harness)
        val manager = RedisManager.getInstance(harness.redisOpConfig(EVENTS_REDIS_ERROR_URL))
        manager.initializeAgent(harness.agent)
        try {
          manager.initialize()
        } catch (e: com.guardcore.errors.GuardRedisError) {
          return
        }
        error("corpus expected redis connection failure")
      }
      "rate_limit_script_reload" -> {
        EventsRedisSupport.flushEventsPrefix()
        redisOpReset(harness)
        val cfg = harness.redisOpConfig(EVENTS_REDIS_URL, enableRateLimiting = true)
        val redisManager = RedisManager.getInstance(cfg)
        redisManager.initialize()
        val manager = RateLimitManager.getInstance(cfg)
        manager.reset()
        manager.initializeAgent(harness.agent)
        manager.redisHandler = redisManager
        manager.rateLimitScriptSha = "f".repeat(40)
        val request = EventsPipelineRequest.of(step)
        try {
          manager.checkRateLimit(
              request,
              step["client_ip"].toString(),
              createErrorResponse = { code: Int, message: String ->
                harness.middleware.createErrorResponse(code, message)
              },
          )
        } finally {
          manager.rateLimitScriptSha = null
          redisManager.discardClientQuietlyForCorpus()
          EventsRedisSupport.flushEventsPrefix()
        }
      }
      "bypass" -> {
        val validator =
            RequestValidator(
                ValidationContext(
                    config = harness.config,
                    logger = harness.middleware.logger,
                    eventBus = harness.eventBus,
                ),
            )
        val errorFactory =
            ErrorResponseFactory(
                ResponseContext(
                    config = harness.config,
                    logger = harness.middleware.logger,
                    metricsCollector = MetricsCollector(null, harness.config),
                    agentHandler = null,
                    responseFactory = EVENTS_RESPONSE_FACTORY,
                ),
            )
        val context =
            BypassContext(
                config = harness.config,
                logger = harness.middleware.logger,
                eventBus = harness.eventBus,
                routeResolver = RouteConfigResolver(RoutingContext(harness.config,
                    harness.middleware.logger)),
                responseFactory = errorFactory,
                validator = validator,
            )
        val handler = BypassHandler(context)
        val request = EventsPipelineRequest.of(step)
        handler.handleSecurityBypass(
            request,
            { PipelineHarness.StubResponse(200, "passthrough") },
            harness.routes[step["url_path"].toString()],
        )
      }
      "path_excluded" -> {
        val validator =
            RequestValidator(
                ValidationContext(
                    config = harness.config,
                    logger = harness.middleware.logger,
                    eventBus = harness.eventBus,
                ),
            )
        val request = EventsPipelineRequest.of(step)
        val excluded = validator.isPathExcluded(request)
        check(excluded) { "corpus expected path exclusion" }
      }
      else -> error("unknown events harness call $op")
    }
  }

  /** Python `_reset_redis_manager` (events_harness.py:669). */
  private suspend fun redisOpReset(harness: EventsCase) {
    RedisManager.resetInstance()
  }

  /** Python `_rules_from_payload` (events_harness.py:305). */
  private fun rulesFromPayload(payload: Map<String, Any?>): DynamicRules =
      DynamicRules(
          ruleId = payload["rule_id"].toString(),
          version = (payload["version"] as Number).toInt(),
          timestamp =
              java.time.OffsetDateTime.of(2026, 1, 1, 0, 0, 0, 0, java.time.ZoneOffset.UTC),
          emergencyMode = payload["emergency_mode"] as? Boolean ?: false,
          emergencyWhitelist =
              (payload["emergency_whitelist"] as? List<*>)?.map { it.toString() } ?: emptyList(),
      )
}

/** The redis flush helper behind `_flush_events_prefix` (events_harness.py:657). */
public object EventsRedisSupport {
  public fun flushEventsPrefix() {
    val url = EventsHarness.EVENTS_REDIS_URL
    val prefix = EventsHarness.EVENTS_REDIS_PREFIX
    val uri = java.net.URI(url)
    val client =
        io.lettuce.core.RedisClient.create(uri.toString())
    val connection = client.connect()
    try {
      val sync = connection.sync()
      val keys = sync.keys("$prefix*")
      if (keys.isNotEmpty()) {
        sync.del(*keys.toTypedArray())
      }
    } finally {
      connection.close()
      client.shutdown()
    }
  }
}

/** Path helper used by the geo download-failure op (kept off the main harness surface). */
public fun tempCorpusDir(): Path = Files.createTempDirectory("guard_jvm_corpus")
