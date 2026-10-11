package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.MiddlewareEventBusProtocol
import com.guardcore.protocols.MiddlewareResponseFactoryProtocol
import com.guardcore.protocols.RequestState
import java.util.logging.Logger

/**
 * Test support for the W4a core test surface: the python tests' MockGuardMiddleware /
 * MockGuardRequest analogs (tests/test_core/conftest.py).
 */

/** Recording middleware event bus (the AsyncMock event_bus of the python tests). */
public class RecordingBus : MiddlewareEventBusProtocol {
  public val events: MutableList<Map<String, Any?>> = mutableListOf()

  override suspend fun sendMiddlewareEvent(
      eventType: String,
      request: GuardRequest,
      actionTaken: String,
      reason: String,
      metadata: Map<String, Any?>,
  ) {
    events.add(
        linkedMapOf(
            "event_type" to eventType,
            "action_taken" to actionTaken,
            "reason" to reason,
        ) + metadata,
    )
  }

  override suspend fun sendHttpsViolationEvent(request: GuardRequest, routeConfig: Any?) {
    events.add(linkedMapOf("event_type" to "https_enforced", "action_taken" to "https_redirect"))
  }

  override suspend fun sendCloudDetectionEvents(
      request: GuardRequest,
      clientIp: String,
      cloudProvidersToCheck: List<String>,
      routeConfig: Any?,
      cloudHandler: Any?,
      passiveMode: Boolean,
  ) {}
}

/** Mutable test response (the MagicMock response with real attribute semantics). */
public class TestResponse(
    override val statusCode: Int,
    override var body: ByteArray? = "".encodeToByteArray(),
) : GuardResponse {
  override val headers: MutableMap<String, String> = linkedMapOf()
}

/** Case-insensitive header map like the adapters'. */
public class TestHeaders(items: Map<String, String> = emptyMap()) : Map<String, String> {
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

/** MockGuardRequest: fixed client IP, path, scheme, headers, body over a real state bag. */
public class TestRequest(
    override val clientHost: String? = "192.0.2.10",
    override val urlPath: String = "/api",
    override val urlScheme: String = "http",
    headers: Map<String, String> = emptyMap(),
    private val bodyBytes: ByteArray = "".encodeToByteArray(),
    override val method: String = "GET",
) : GuardRequest {
  override val headers: Map<String, String> = TestHeaders(headers)
  override val urlFull: String = "http://example.com$urlPath"
  override val queryParams: Map<String, String> = emptyMap()
  override val state: RequestState = TestState()
  override val scope: Map<String, Any?> = emptyMap()

  override fun urlReplaceScheme(scheme: String): String = "$scheme://example.com$urlPath"

  override suspend fun body(): ByteArray = bodyBytes
}

/** The python request.state bag. */
public class TestState : RequestState {
  private val attrs: MutableMap<String, Any?> = linkedMapOf()

  override fun getAttr(name: String): Any? = attrs[name]

  override fun setAttr(name: String, value: Any?) {
    attrs[name] = value
  }
}

/** Test middleware carrying real config + the recording bus (MockGuardMiddleware analog). */
public class TestMiddleware(
    override val config: SecurityConfig,
    bus: RecordingBus? = null,
    geoIpHandler: GeoIPHandler? = null,
    resolver: com.guardcore.protocols.RouteConfigResolverProtocol? = null,
) : GuardMiddlewareProtocol {
  public val bus: RecordingBus = bus ?: RecordingBus()

  /**
   * Swap-in point for a misbehaving bus (the python tests assign
   * `mw.event_bus.send_middleware_event = AsyncMock(side_effect=...)`).
   */
  public var eventBusOverride: MiddlewareEventBusProtocol? = null

  public constructor(
      config: SecurityConfig,
      bus: RecordingBus?,
      geoIpHandler: GeoIPHandler?,
  ) : this(config, bus, geoIpHandler, null)

  init {
    HandlerSeamsRegister.register()
    this.bus.let {}
  }

  override val logger: Logger = Logger.getLogger("test.core")
  override var lastCloudIpRefresh: Int = 0
  override val suspiciousRequestCounts: MutableMap<String, MutableMap<String, Int>> = linkedMapOf()
  override val eventBus: MiddlewareEventBusProtocol
    get() = eventBusOverride ?: this.bus

  override val routeResolver: com.guardcore.protocols.RouteConfigResolverProtocol? = resolver
  override val responseFactory: MiddlewareResponseFactoryProtocol = TestResponseFactory()
  override val rateLimitHandler: Any? = com.guardcore.handlers.RateLimitManager.getInstance(config)
  override val agentHandler: com.guardcore.protocols.AgentHandlerProtocol? = null
  override val geoIpHandler: GeoIPHandler? = geoIpHandler
  override val guardResponseFactory: com.guardcore.protocols.GuardResponseFactory? = null

  override suspend fun createErrorResponse(statusCode: Int, defaultMessage: String): GuardResponse =
      TestResponse(statusCode, defaultMessage.encodeToByteArray())

  override suspend fun refreshCloudIpRanges() {}
}

/** The response-factory test double (SimpleResponseFactory of tests/conftest.py). */
public class TestResponseFactory : MiddlewareResponseFactoryProtocol {
  override fun createResponse(content: Any?, statusCode: Int): GuardResponse =
      TestResponse(statusCode, content?.toString()?.encodeToByteArray())

  override fun createRedirectResponse(url: Any?, statusCode: Int): GuardResponse {
    val response = TestResponse(statusCode)
    response.headers["Location"] = url.toString()
    return response
  }

  override suspend fun createHttpsRedirect(request: GuardRequest): GuardResponse =
      createRedirectResponse(request.urlReplaceScheme("https"), 301)

  override suspend fun applyModifier(response: GuardResponse): GuardResponse = response
}

/** Idempotent seam registration for the core tests (the conftest seed). */
public object HandlerSeamsRegister {
  private val seeded: Boolean = run {
    com.guardcore.handlers.HandlerSeams.register()
    com.guardcore.util.DetectionEngineWiring.register()
    true
  }

  public fun register() {
    check(seeded)
  }
}

/** A default no-redis SecurityConfig with the common test knobs. */
public fun coreTestConfig(apply: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig {
  val builder =
      SecurityConfigBuilder().apply {
        enableRedis = false
        logSuspiciousLevel = com.guardcore.config.LogLevel.ERROR
        logRequestLevel = null
      }
  builder.apply(apply)
  return builder.build()
}

/** runBlocking helper. */
public fun coreRunTest(block: suspend () -> Unit) {
  kotlinx.coroutines.runBlocking { block() }
}
