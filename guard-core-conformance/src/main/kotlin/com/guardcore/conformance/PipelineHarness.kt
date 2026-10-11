package com.guardcore.conformance

import com.guardcore.config.BehaviorRuleConfig
import com.guardcore.config.LogLevel
import com.guardcore.config.RuleAction
import com.guardcore.config.RuleType
import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.behavioral.BehavioralContext
import com.guardcore.core.behavioral.BehavioralProcessor
import com.guardcore.core.checks.ChecksFactory
import com.guardcore.core.checks.SecurityCheckPipeline
import com.guardcore.core.events.MetricsCollector
import com.guardcore.core.responses.ErrorResponseFactory
import com.guardcore.core.responses.ResponseContext
import com.guardcore.decorators.RouteConfig
import com.guardcore.decorators.RouteConfigRevision
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.RateLimitManager
import com.guardcore.handlers.SecurityHeadersManager
import com.guardcore.handlers.resetIpBanGlobalState
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.MiddlewareEventBusProtocol
import com.guardcore.protocols.MiddlewareResponseFactoryProtocol
import com.guardcore.protocols.RequestState
import com.guardcore.protocols.RouteConfigResolverProtocol
import java.util.logging.Logger
import kotlinx.coroutines.runBlocking

/**
 * The W4a pipeline runner: the Kotlin port of `specs/fixtures/tools/pipeline_harness.py`. Drives
 * the REAL fixed-order check pipeline (build_default_pipeline) and the REAL response factory
 * in-process over the harness stubs, then compares per the index.json contract (pipeline_records
 * rule: only the keys present in each expected record are compared).
 */
public object PipelineHarness {
  init {
    // Facade seam registration: HandlerSeams (G-2/G-6) + DetectionEngineWiring (G-1/G-4/G-5).
    com.guardcore.handlers.HandlerSeams.register()
    com.guardcore.util.DetectionEngineWiring.register()
  }

  /** Python `CONFIG_KEYS` (pipeline_harness.py:61). */
  private val CONFIG_KEYS: Set<String> =
      setOf(
          "whitelist",
          "blacklist",
          "exempt_ips",
          "blocked_user_agents",
          "blocked_countries",
          "whitelist_countries",
          "rate_limit",
          "rate_limit_window",
          "endpoint_rate_limits",
          "passive_mode",
          "custom_error_responses",
          "security_headers",
          "enable_cors",
          "cors_allow_origins",
          "cors_allow_methods",
          "cors_allow_headers",
          "cors_allow_credentials",
          "global_behavior_rules",
          "behavior_scan_response_body",
          "enable_rate_limiting",
          "enable_penetration_detection",
          "enable_ip_banning",
          "enable_rate_limit_auto_ban",
          "auto_ban_threshold",
      )

  /** Read access for the events harness (events_harness.py:99 composes over it). */
  public fun configKeys(): Set<String> = CONFIG_KEYS

  /** Python `ROUTE_KEYS` (pipeline_harness.py:88). */
  private val ROUTE_KEYS: Set<String> =
      setOf(
          "rate_limit",
          "rate_limit_window",
          "ip_whitelist",
          "ip_blacklist",
          "blocked_countries",
          "whitelist_countries",
          "blocked_user_agents",
          "bypassed_checks",
          "enable_suspicious_detection",
          "excluded_detection_headers",
          "excluded_detection_params",
          "excluded_detection_body_fields",
          "geo_rate_limits",
      )

  /** Read access for the events harness (events_harness.py:120 composes over it). */
  public fun routeKeys(): Set<String> = ROUTE_KEYS

  /** Python `DEFAULT_STATE` (pipeline_harness.py:104). */
  private const val ENABLE_REDIS: Boolean = false
  private const val ENABLE_RATE_LIMIT_AUTO_BAN: Boolean = false
  private const val ENABLE_IP_BANNING: Boolean = false
  private const val AUTO_BAN_THRESHOLD: Int = 1000
  private val LOG_SUSPICIOUS_LEVEL: LogLevel = LogLevel.ERROR
  private val LOG_REQUEST_LEVEL: LogLevel = LogLevel.ERROR

  // ---------------------------------------------------------- harness stubs

  /** Python `_StubResponse` (pipeline_harness.py:116). */
  public class StubResponse(
      private var statusCodeValue: Int,
      defaultMessage: String = "",
  ) : GuardResponse {
    private val bodyBytes: ByteArray = defaultMessage.encodeToByteArray()
    override val headers: MutableMap<String, String> = linkedMapOf()
    override val statusCode: Int
      get() = statusCodeValue

    override val body: ByteArray
      get() = bodyBytes
  }

  /** Python `_RecordingEventBus` (pipeline_harness.py:141). */
  public class RecordingEventBus : MiddlewareEventBusProtocol {
    public val events: MutableList<Pair<String, String>> = mutableListOf()

    override suspend fun sendMiddlewareEvent(
        eventType: String,
        request: GuardRequest,
        actionTaken: String,
        reason: String,
        metadata: Map<String, Any?>,
    ) {
      events.add(eventType to actionTaken)
    }

    override suspend fun sendHttpsViolationEvent(request: GuardRequest, routeConfig: Any?) {
      events.add("https_enforced" to "https_redirect")
    }

    override suspend fun sendCloudDetectionEvents(
        request: GuardRequest,
        clientIp: String,
        cloudProvidersToCheck: List<String>,
        routeConfig: Any?,
        cloudHandler: Any?,
        passiveMode: Boolean,
    ) {
      if (routeConfig != null) {
        events.add(
            "decorator_violation" to (if (!passiveMode) "request_blocked" else "logged_only"),
        )
      }
    }
  }

  /** Python `_RecordingOnBlock` (pipeline_harness.py:153). */
  public class RecordingOnBlock {
    public val payloads: MutableList<Map<String, Any?>> = mutableListOf()

    public operator fun invoke(request: GuardRequest, payload: Map<String, Any?>) {
      val keys =
          listOf(
              "check_name",
              "reason",
              "trigger_info",
              "passive_mode",
              "client_ip",
              "path",
              "method",
              "status_code",
          )
      payloads.add(keys.associateWith { payload[it] })
    }
  }

  /** Python `_StubGeoHandler` (pipeline_harness.py:174). */
  public class StubGeoHandler(
      private val table: Map<String, String>,
  ) : GeoIPHandler {
    override val isInitialized: Boolean = true

    override fun getCountry(ip: String): String? = table[ip]

    override suspend fun initialize() {}

    override suspend fun initializeRedis(
        redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
    ) {}

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {}

    override suspend fun refresh() {}

    override fun close() {}
  }

  /** Python `_HarnessDecorator` (pipeline_harness.py:224). */
  public class HarnessDecorator(
      config: SecurityConfig,
      routes: Map<String, RouteConfig>,
  ) : com.guardcore.decorators.RouteConfigProvider {
    public val routeConfigTable: Map<String, RouteConfig> = routes
    public val routeConfigRevisionToken: RouteConfigRevision = RouteConfigRevision()
    public val behaviorTracker: BehaviorTracker = BehaviorTracker(config)

    override fun getRouteConfigs(): Map<String, RouteConfig> = routeConfigTable

    override fun getRevisionValue(): Int = routeConfigRevisionToken.value
  }

  /** Python `_StubRouteResolver` (pipeline_harness.py:204). */
  public class StubRouteResolver(
      private val routes: Map<String, RouteConfig>,
  ) : RouteConfigResolverProtocol {
    override fun getRouteConfig(request: GuardRequest): RouteConfig? = routes[request.urlPath]

    override fun shouldBypassCheck(checkName: String, routeConfig: Any?): Boolean {
      val rc = routeConfig as? RouteConfig ?: return false
      return checkName in rc.bypassedChecks
    }

    override fun getCloudProvidersToCheck(routeConfig: Any?): List<String>? {
      val rc = routeConfig as? RouteConfig ?: return null
      return if (rc.blockCloudProviders.isEmpty()) null else rc.blockCloudProviders.toList()
    }
  }

  /** Python `_HarnessResponseFactory` (pipeline_harness.py:277). */
  public class HarnessResponseFactory : MiddlewareResponseFactoryProtocol {
    override fun createResponse(content: Any?, statusCode: Int): GuardResponse {
      val body = content as? String ?: content?.toString() ?: ""
      return StubResponse(statusCode, body)
    }

    override fun createRedirectResponse(url: Any?, statusCode: Int): GuardResponse {
      val response = StubResponse(statusCode)
      response.headers["Location"] = url.toString()
      return response
    }

    override suspend fun createHttpsRedirect(request: GuardRequest): GuardResponse =
        createRedirectResponse(request.urlReplaceScheme("https"), 301)

    override suspend fun applyModifier(response: GuardResponse): GuardResponse = response
  }

  /** Python `_HarnessMiddleware` (pipeline_harness.py:234). */
  public class HarnessMiddleware(
      override val config: SecurityConfig,
      public val rateLimitHandlerValue: RateLimitManager,
      public val geoIpHandlerValue: GeoIPHandler?,
      routes: Map<String, RouteConfig>,
      public val eventBusValue: RecordingEventBus,
      public val onBlockRecorder: RecordingOnBlock,
  ) : GuardMiddlewareProtocol {
    override val logger: Logger = Logger.getLogger("corpus.harness")
    override var lastCloudIpRefresh: Int = 0
    override val suspiciousRequestCounts: MutableMap<String, MutableMap<String, Int>> =
        linkedMapOf()
    override val eventBus: MiddlewareEventBusProtocol = eventBusValue
    override val routeResolver: RouteConfigResolverProtocol = StubRouteResolver(routes)
    public val guardDecoratorValue: HarnessDecorator = HarnessDecorator(config, routes)
    override val guardDecorator: Any? = guardDecoratorValue
    override val responseFactory: MiddlewareResponseFactoryProtocol = HARNESS_RESPONSE_FACTORY
    override val rateLimitHandler: Any? = rateLimitHandlerValue
    override val agentHandler: com.guardcore.protocols.AgentHandlerProtocol? = null
    override val geoIpHandler: GeoIPHandler? = geoIpHandlerValue
    override val guardResponseFactory: com.guardcore.protocols.GuardResponseFactory? = null

    override suspend fun createErrorResponse(
        statusCode: Int,
        defaultMessage: String,
    ): GuardResponse = createHarnessErrorResponse(config, statusCode, defaultMessage)

    override suspend fun refreshCloudIpRanges() {}
  }

  public val HARNESS_RESPONSE_FACTORY: HarnessResponseFactory = HarnessResponseFactory()

  /** Python `create_harness_error_response` (pipeline_harness.py:295). */
  public suspend fun createHarnessErrorResponse(
      config: SecurityConfig,
      statusCode: Int,
      defaultMessage: String,
  ): GuardResponse {
    val customMessage = config.customErrorResponses[statusCode] ?: defaultMessage
    val response = HARNESS_RESPONSE_FACTORY.createResponse(customMessage, statusCode)
    val headersConfig = config.securityHeaders
    if (headersConfig != null && (headersConfig["enabled"] as? Boolean ?: true)) {
      val securityHeaders = SecurityHeadersManager.getInstance().getHeaders(null, config = config)
      for ((headerName, headerValue) in securityHeaders) {
        response.headers[headerName] = headerValue
      }
    }
    return response
  }

  // ---------------------------------------------------------- case construction

  /** Python `_build_route` (pipeline_harness.py:318). */
  private fun buildRoute(path: String, overrides: Map<String, Any?>): RouteConfig {
    val routeConfig = RouteConfig()
    for ((key, value) in overrides) {
      if (key !in ROUTE_KEYS) continue
      when (key) {
        "rate_limit" -> routeConfig.rateLimit = (value as Number).toInt()
        "rate_limit_window" -> routeConfig.rateLimitWindow = (value as Number).toInt()
        "ip_whitelist" -> routeConfig.ipWhitelist = (value as List<*>).map { it.toString() }
        "ip_blacklist" -> routeConfig.ipBlacklist = (value as List<*>).map { it.toString() }
        "blocked_countries" ->
            routeConfig.blockedCountries = (value as List<*>).map { it.toString() }
        "whitelist_countries" ->
            routeConfig.whitelistCountries = (value as List<*>).map { it.toString() }
        "blocked_user_agents" ->
            routeConfig.blockedUserAgents = (value as List<*>).map { it.toString() }.toMutableList()
        "bypassed_checks" ->
            routeConfig.bypassedChecks = (value as List<*>).map { it.toString() }.toMutableSet()
        "enable_suspicious_detection" -> routeConfig.enableSuspiciousDetection = value as Boolean
        "excluded_detection_headers" ->
            routeConfig.excludedDetectionHeaders = (value as List<*>).map { it.toString() }.toSet()
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

  /** Python `_make_config` (pipeline_harness.py:333). */
  private fun makeConfig(caseConfig: Map<String, Any?>, geo: StubGeoHandler): SecurityConfig {
    val builder = SecurityConfigBuilder()
    builder.enableRedis = ENABLE_REDIS
    builder.enableRateLimitAutoBan = ENABLE_RATE_LIMIT_AUTO_BAN
    builder.enableIpBanning = ENABLE_IP_BANNING
    builder.autoBanThreshold = AUTO_BAN_THRESHOLD
    builder.logSuspiciousLevel = LOG_SUSPICIOUS_LEVEL
    builder.logRequestLevel = LOG_REQUEST_LEVEL

    for ((key, value) in caseConfig) {
      if (key !in CONFIG_KEYS) continue
      applyPipelineConfigKey(builder, key, value, geo)
    }
    if (
        caseConfig.containsKey("blocked_countries") || caseConfig.containsKey("whitelist_countries")
    ) {
      builder.geoIpHandler = geo
    }
    return builder.build()
  }

  /** The per-key config mapping shared with the events harness (events_harness.py:209). */
  public fun applyPipelineConfigKey(
      builder: SecurityConfigBuilder,
      key: String,
      value: Any?,
      geo: StubGeoHandler,
  ) {
    when (key) {
      "whitelist" -> builder.whitelist = (value as List<*>).map { it.toString() }
      "blacklist" -> builder.blacklist = (value as List<*>).map { it.toString() }
      "exempt_ips" -> builder.exemptIps = (value as List<*>).map { it.toString() }
      "blocked_user_agents" ->
          builder.blockedUserAgents = (value as List<*>).map { it.toString() }
      "blocked_countries" ->
          builder.blockedCountries = (value as List<*>).map { it.toString() }.toSet()
      "whitelist_countries" ->
          builder.whitelistCountries = (value as List<*>).map { it.toString() }.toSet()
      "rate_limit" -> builder.rateLimit = (value as Number).toInt()
      "rate_limit_window" -> builder.rateLimitWindow = (value as Number).toInt()
      "endpoint_rate_limits" -> {
        @Suppress("UNCHECKED_CAST") val map = value as Map<String, List<Number>>
        builder.endpointRateLimits = map.mapValues { (_, lw) -> lw[0].toInt() to lw[1].toInt() }
      }
      "passive_mode" -> builder.passiveMode = value as Boolean
      "custom_error_responses" -> {
        @Suppress("UNCHECKED_CAST") val map = value as Map<String, String>
        builder.customErrorResponses = map.mapKeys { (k, _) -> k.toInt() }
      }
      "security_headers" ->
          builder.securityHeaders = jsonValueToKotlin(value) as? Map<String, Any?>
      "enable_cors" -> builder.enableCors = value as Boolean
      "cors_allow_origins" -> builder.corsAllowOrigins = (value as List<*>).map { it.toString() }
      "cors_allow_methods" -> builder.corsAllowMethods = (value as List<*>).map { it.toString() }
      "cors_allow_headers" -> builder.corsAllowHeaders = (value as List<*>).map { it.toString() }
      "cors_allow_credentials" -> builder.corsAllowCredentials = value as Boolean
      "global_behavior_rules" -> {
        @Suppress("UNCHECKED_CAST") val rules = value as List<Map<String, Any?>>
        builder.globalBehaviorRules = rules.map { rule ->
          BehaviorRuleConfig(
              ruleType = RuleType.entries.first { it.pythonName == rule["rule_type"] },
              threshold = (rule["threshold"] as Number).toInt(),
              window = (rule["window"] as? Number)?.toInt() ?: 3600,
              pattern = rule["pattern"]?.toString(),
              action =
                  rule["action"]?.let { a -> RuleAction.entries.first { it.pythonName == a } }
                      ?: RuleAction.LOG,
              banDuration = (rule["ban_duration"] as? Number)?.toInt(),
          )
        }
      }
      "behavior_scan_response_body" -> builder.behaviorScanResponseBody = value as Boolean
      "enable_rate_limiting" -> builder.enableRateLimiting = value as Boolean
      "enable_penetration_detection" -> builder.enablePenetrationDetection = value as Boolean
      "enable_ip_banning" -> builder.enableIpBanning = value as Boolean
      "enable_rate_limit_auto_ban" -> builder.enableRateLimitAutoBan = value as Boolean
      "auto_ban_threshold" -> builder.autoBanThreshold = (value as Number).toInt()
    }
  }

  /** Converts a parsed-JSON tree into plain Kotlin collections (the harness payload shapes). */
  private fun jsonValueToKotlin(value: Any?): Any? =
      when (value) {
        is Map<*, *> -> value.entries.associate { it.key.toString() to jsonValueToKotlin(it.value) }
        is List<*> -> value.map { jsonValueToKotlin(it) }
        else -> value
      }

  /** Python `_PipelineRequest` (pipeline_harness.py:368). */
  public class PipelineRequest
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
    override val headers: Map<String, String> = CaseInsensitiveHeaders(headerMap)
    override val queryParams: Map<String, String> = emptyMap()
    override val state: RequestState = PipelineRequestState()
    override val scope: Map<String, Any?> = emptyMap()

    override fun urlReplaceScheme(scheme: String): String = "$scheme://example.com"

    override suspend fun body(): ByteArray = bodyBytes

    public companion object {
      public fun of(drive: Map<String, Any?>): PipelineRequest {
        @Suppress("UNCHECKED_CAST")
        val rawHeaders = (drive["headers"] as? Map<String, String>) ?: emptyMap()
        val mutable = rawHeaders.mapKeys { it.key.lowercase() }.toMutableMap()
        val bodyBytes = (drive["body"] as? String ?: "").encodeToByteArray()
        if (bodyBytes.isNotEmpty() && "content-length" !in mutable) {
          mutable["content-length"] = bodyBytes.size.toString()
        }
        return PipelineRequest(drive, mutable, bodyBytes)
      }
    }
  }

  /** Python `_CaseInsensitiveHeaders` (pipeline_harness.py:352): case-insensitive lookup. */
  public class CaseInsensitiveHeaders(items: Map<String, String>) : Map<String, String> {
    private val backing: Map<String, String> = items.mapKeys { it.key.lowercase() }

    override val size: Int
      get() = backing.size

    override val keys: Set<String>
      get() = backing.keys

    override val values: Collection<String>
      get() = backing.values

    override val entries: Set<Map.Entry<String, String>>
      get() = backing.entries

    override fun isEmpty(): Boolean = backing.isEmpty()

    override fun containsKey(key: String): Boolean = backing.containsKey(key.lowercase())

    override fun containsValue(value: String): Boolean = backing.containsValue(value)

    override fun get(key: String): String? = backing[key.lowercase()]
  }

  /** The python `request.state` bag over attribute names. */
  public class PipelineRequestState : RequestState {
    private val attrs: MutableMap<String, Any?> = linkedMapOf()

    override fun getAttr(name: String): Any? = attrs[name]

    override fun setAttr(name: String, value: Any?) {
      attrs[name] = value
    }
  }

  /** Python `HarnessCase` (pipeline_harness.py:393). */
  public class HarnessCase(case: Map<String, Any?>) {
    public val geo: StubGeoHandler =
        StubGeoHandler((case["geo_countries"] as? Map<String, String>) ?: emptyMap())
    public val onBlock: RecordingOnBlock = RecordingOnBlock()
    public val config: SecurityConfig =
        makeConfig(case["config"] as? Map<String, Any?> ?: emptyMap(), geo)
    public val routes: Map<String, RouteConfig> =
        (case["routes"] as? Map<String, Map<String, Any?>>)?.mapValues { (path, overrides) ->
          buildRoute(path, overrides)
        } ?: emptyMap()
    public val eventBus: RecordingEventBus = RecordingEventBus()
    public val rateLimitHandler: RateLimitManager = RateLimitManager.getInstance(config)
    public val middleware: HarnessMiddleware =
        HarnessMiddleware(config, rateLimitHandler, geo, routes, eventBus, onBlock)
    public val pipeline: SecurityCheckPipeline = ChecksFactory.buildDefaultPipeline(middleware)
    public val errorFactory: ErrorResponseFactory =
        ErrorResponseFactory(
            ResponseContext(
                config = config,
                logger = middleware.logger,
                metricsCollector = MetricsCollector(null, config),
                agentHandler = null,
                responseFactory = HARNESS_RESPONSE_FACTORY,
            ),
        )
    public val behaviorProcessor: BehavioralProcessor =
        BehavioralProcessor(
            BehavioralContext(
                config = config,
                logger = middleware.logger,
                eventBus = eventBus,
                guardDecorator = null,
                behaviorTracker = middleware.guardDecoratorValue.behaviorTracker,
                middleware = middleware,
            ),
        )

    init {
      config.onBlock = { request, payload -> onBlock(request, payload) }
    }
  }

  /** Python `run_case` (pipeline_harness.py:443). */
  public fun runCase(case: Map<String, Any?>): List<Map<String, Any?>> = runBlocking {
    resetIpBanGlobalState()
    SecurityHeadersManager.getInstance().headersCache.clear()
    val harness = HarnessCase(case)
    harness.rateLimitHandler.reset()
    val observed = mutableListOf<Map<String, Any?>>()
    for (drive in case["drives"] as? List<Map<String, Any?>> ?: emptyList()) {
      val request = PipelineRequest.of(drive)
      val record = linkedMapOf<String, Any?>()
      harness.eventBus.events.clear()
      harness.onBlock.payloads.clear()
      val stage = drive["stage"] as? String ?: "pipeline"
      val response: GuardResponse? =
          if (stage == "pipeline") {
            harness.pipeline.execute(request)
          } else if (stage == "process_response") {
            val initial =
                HARNESS_RESPONSE_FACTORY.createResponse(
                    drive["response_body"] ?: "ok",
                    (drive["response_status"] as? Number)?.toInt() ?: 200,
                )
            val routeResolver = harness.middleware.routeResolver as StubRouteResolver
            harness.errorFactory.processResponse(
                request,
                initial,
                0.0,
                routeResolver.getRouteConfig(request),
                { req, resp, ip, rc ->
                  harness.behaviorProcessor.processReturnRules(req, resp, ip, rc)
                },
                { req, resp, ip, rules ->
                  harness.behaviorProcessor.processGlobalReturnRules(req, resp, ip, rules)
                },
            )
          } else {
            throw IllegalArgumentException("unknown drive stage $stage")
          }
      if (response == null) {
        record["status"] = null
      } else {
        record["status"] = response.statusCode
        record["body"] = response.body?.decodeToString() ?: ""
        if (response.headers.isNotEmpty()) {
          record["headers"] = response.headers.toMap()
        }
      }
      (request.state.getAttr("is_exempt") as? Boolean)?.let { record["is_exempt"] = it }
      (request.state.getAttr("is_whitelisted") as? Boolean)?.let { record["is_whitelisted"] = it }
      if (harness.eventBus.events.isNotEmpty()) {
        record["events"] = harness.eventBus.events.map { listOf(it.first, it.second) }
      }
      if (harness.onBlock.payloads.isNotEmpty()) {
        record["on_block"] = harness.onBlock.payloads.map { it.toMap() }
      }
      observed.add(record)
    }
    observed
  }
}
