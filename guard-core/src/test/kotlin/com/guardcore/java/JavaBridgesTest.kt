package com.guardcore.java

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.TestMiddleware
import com.guardcore.core.TestRequest
import com.guardcore.core.checks.ChecksFactory
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.RateLimitManager
import com.guardcore.handlers.resetIpBanGlobalState
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** The Java bridge convention test: every bridge returns/completes over the same suspend call. */
public class JavaBridgesTest {
  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      SecurityConfigBuilder().apply(mutate).build()

  /**
   * The engine detection-config view over a SecurityConfig (DetectRunner.asDetectionConfigView).
   */
  private class DetectionView(
      config: SecurityConfig,
  ) : com.guardcore.engine.suspatterns.DetectionConfigView {
    override val detectionCompilerTimeout: Double = config.detectionCompilerTimeout
    override val detectionMaxTrackedPatterns: Int = config.detectionMaxTrackedPatterns
    override val detectionMaxContentLength: Int = config.detectionMaxContentLength
    override val detectionPreserveAttackPatterns: Boolean = config.detectionPreserveAttackPatterns
    override val detectionAnomalyThreshold: Double = config.detectionAnomalyThreshold
    override val detectionSlowPatternThreshold: Double = config.detectionSlowPatternThreshold
    override val detectionMonitorHistorySize: Int = config.detectionMonitorHistorySize
    override val detectionAnomalyEmissionCooldown: Double = config.detectionAnomalyEmissionCooldown
    override val detectionMinSamplesForAnomaly: Int = config.detectionMinSamplesForAnomaly
    override val detectionSemanticThreshold: Double = config.detectionSemanticThreshold
    override val detectionThreatScoreThreshold: Double = config.detectionThreatScoreThreshold
    override val detectionMaxBodyInspectBytes: Int = config.detectionMaxBodyInspectBytes
    override val detectionPatternValidationCachePath: String? =
        config.detectionPatternValidationCachePath
  }

  @Test
  fun pipelineBridgesExecuteOverTheRealPipeline() {
    val middleware = TestMiddleware(config())
    val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
    val request = TestRequest(urlPath = "/health", headers = mapOf("User-Agent" to "ok"))

    val future = JavaBridges.executePipeline(pipeline, request)
    val response = future.get(30, TimeUnit.SECONDS)
    val blocking = JavaBridges.executePipelineBlocking(pipeline, TestRequest(urlPath = "/health"))
    assertEquals(response?.statusCode, blocking?.statusCode)
    assertTrue(future.isDone)
  }

  @Test
  fun detectBridgesReturnTheEngineVerdict() {
    // Pin the shared engine's detection config (the W2 runner pattern: manager.configure before
    // detecting), so the verdict is deterministic regardless of test order.
    com.guardcore.engine.suspatterns.SusPatternsManager.shared().configure(DetectionView(config()))
    val verdict = JavaBridges.detectBlocking("<script>alert(1)</script>", "203.0.113.7", "body")
    val futureVerdict =
        JavaBridges.detect("<script>alert(1)</script>", "203.0.113.7", "body")
            .get(30, TimeUnit.SECONDS)
    // Verdict CONTENT is the detect corpus's contract (DetectConformanceTest, 193 cases); this
    // bridge test pins the transport: both shapes complete and return the same engine verdict.
    assertEquals(verdict.isThreat, futureVerdict.isThreat)
    assertEquals(verdict.threats.size, futureVerdict.threats.size)
  }

  @Test
  fun handlerManagerBridgesComplete() = runBlocking {
    resetIpBanGlobalState()
    val manager = IpBanManager.getInstance()

    JavaBridges.banIp(manager, "203.0.113.50", 60, "bridge_test").get(30, TimeUnit.SECONDS)
    val unban = JavaBridges.unbanIp(manager, "203.0.113.50")
    unban.get(30, TimeUnit.SECONDS)
    assertTrue(unban.isDone)

    val tracker = BehaviorTracker(config())
    val rule = BehaviorRule(ruleType = "usage", threshold = 5, window = 60, action = "log")
    JavaBridges.applyBehaviorAction(tracker, rule, "203.0.113.51", "bridge.endpoint", "d")
        .get(30, TimeUnit.SECONDS)
  }

  @Test
  fun securityHeadersAndRateLimitBridgesComplete() = runBlocking {
    val headersManager = com.guardcore.handlers.SecurityHeadersManager.getInstance()
    val headers = JavaBridges.getSecurityHeadersBlocking(headersManager, "/api")
    assertTrue(headers.isNotEmpty())
    JavaBridges.getSecurityHeaders(headersManager, "/api").get(30, TimeUnit.SECONDS)

    val cfg = config { enableRateLimiting = false }
    val rateManager = RateLimitManager.getInstance(cfg)
    val request = TestRequest()
    val blocked =
        JavaBridges.checkRateLimitBlocking(
            rateManager,
            request,
            "203.0.113.52",
            createErrorResponse = { code: Int, _: String ->
              object : com.guardcore.protocols.GuardResponse {
                override val headers: MutableMap<String, String> = linkedMapOf()
                override val statusCode: Int = code
                override val body: ByteArray = ByteArray(0)
              }
            },
        )
    assertEquals(null, blocked)
  }
}
