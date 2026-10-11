package com.guardcore.java

import com.guardcore.core.checks.SecurityCheckPipeline
import com.guardcore.engine.suspatterns.DetectResult
import com.guardcore.engine.suspatterns.SusPatternsManager
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.RateLimitManager
import com.guardcore.handlers.RedisManager
import com.guardcore.handlers.SecurityHeadersManager
import com.guardcore.handlers.applyAction
import com.guardcore.handlers.banIp
import com.guardcore.handlers.unbanIp
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import java.util.concurrent.CompletableFuture
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.future.future
import kotlinx.coroutines.runBlocking

/**
 * The Java bridge surface (specs/impl/jvm.md, "Sync, suspend, and CompletableFuture surfaces all
 * ship via the facade"): the public async entry points exposed as
 * `java.util.concurrent.CompletableFuture`-returning statics so Java-only shops consume the same
 * engine with no source-level coupling to coroutines.
 *
 * The convention, for every bridged entry point:
 * - Kotlin callers use the suspend member directly (structured concurrency);
 * - Java callers either block on `Xxx.blocking(...)` (the runBlocking bridge confined to the entry
 *   point, the unasync analog) or take a `CompletableFuture` from `Xxx.future(...)` (composed with
 *   thenApply/thenCompose like any JDK future).
 *
 * Every bridge is a thin wrapper over the SAME suspend call - no behavior lives here.
 */
public object JavaBridges {
  private val bridgeScope =
      kotlinx.coroutines.CoroutineScope(Dispatchers.IO + kotlinx.coroutines.SupervisorJob())

  // ---------------------------------------------------------- pipeline run

  /** Async variant of [SecurityCheckPipeline.execute]. */
  @JvmStatic
  public fun executePipeline(
      pipeline: SecurityCheckPipeline,
      request: GuardRequest,
  ): CompletableFuture<GuardResponse?> = bridgeScope.future { pipeline.execute(request) }

  /** Blocking variant of [SecurityCheckPipeline.execute]. */
  @JvmStatic
  public fun executePipelineBlocking(
      pipeline: SecurityCheckPipeline,
      request: GuardRequest,
  ): GuardResponse? = runBlocking { pipeline.execute(request) }

  // ---------------------------------------------------------- SusPatternsManager.detect

  /** Async variant of [SusPatternsManager.detect]. */
  @JvmStatic
  public fun detect(
      content: String,
      ipAddress: String,
      context: String = "unknown",
  ): CompletableFuture<DetectResult> = bridgeScope.future {
    SusPatternsManager.shared().detect(content, ipAddress, context)
  }

  /** Blocking variant of [SusPatternsManager.detect]. */
  @JvmStatic
  public fun detectBlocking(
      content: String,
      ipAddress: String,
      context: String = "unknown",
  ): DetectResult = SusPatternsManager.shared().detect(content, ipAddress, context)

  // ---------------------------------------------------------- handler managers

  /** Async variant of [IpBanManager.banIp]. */
  @JvmStatic
  public fun banIp(
      manager: IpBanManager,
      ip: String,
      duration: Int,
      reason: String = "threshold_exceeded",
  ): CompletableFuture<Boolean> = bridgeScope.future { manager.banIp(ip, duration, reason) }

  /** Blocking variant of [IpBanManager.banIp]. */
  @JvmStatic
  public fun banIpBlocking(
      manager: IpBanManager,
      ip: String,
      duration: Int,
      reason: String = "threshold_exceeded",
  ): Boolean = runBlocking { manager.banIp(ip, duration, reason) }

  /** Async variant of [IpBanManager.unbanIp]. */
  @JvmStatic
  public fun unbanIp(
      manager: IpBanManager,
      ip: String,
  ): CompletableFuture<Void?> = bridgeScope.future {
    manager.unbanIp(ip)
    null
  }

  /** Blocking variant of [IpBanManager.unbanIp]. */
  @JvmStatic
  public fun unbanIpBlocking(
      manager: IpBanManager,
      ip: String,
  ) {
    runBlocking { manager.unbanIp(ip) }
  }

  /**
   * Async variant of [RateLimitManager.checkRateLimit]; the adapter supplies its error-response
   * factory exactly like the suspend call.
   */
  @JvmStatic
  public fun checkRateLimit(
      manager: RateLimitManager,
      request: GuardRequest,
      clientIp: String,
      createErrorResponse: suspend (Int, String) -> GuardResponse,
      endpointPath: String = "",
  ): CompletableFuture<GuardResponse?> = bridgeScope.future {
    manager.checkRateLimit(request, clientIp, createErrorResponse, endpointPath)
  }

  /** Blocking variant of [RateLimitManager.checkRateLimit]. */
  @JvmStatic
  public fun checkRateLimitBlocking(
      manager: RateLimitManager,
      request: GuardRequest,
      clientIp: String,
      createErrorResponse: suspend (Int, String) -> GuardResponse,
      endpointPath: String = "",
  ): GuardResponse? = runBlocking {
    manager.checkRateLimit(request, clientIp, createErrorResponse, endpointPath)
  }

  /** Async variant of [SecurityHeadersManager.getHeaders]. */
  @JvmStatic
  public fun getSecurityHeaders(
      manager: SecurityHeadersManager,
      requestPath: String?,
  ): CompletableFuture<Map<String, String>> = bridgeScope.future { manager.getHeaders(requestPath) }

  /** Blocking variant of [SecurityHeadersManager.getHeaders]. */
  @JvmStatic
  public fun getSecurityHeadersBlocking(
      manager: SecurityHeadersManager,
      requestPath: String?,
  ): Map<String, String> = runBlocking { manager.getHeaders(requestPath) }

  /** Async variant of [RedisManager.initialize]. */
  @JvmStatic
  public fun initializeRedis(manager: RedisManager): CompletableFuture<Boolean> =
      bridgeScope.future {
        manager.initialize()
        true
      }

  /** Blocking variant of [RedisManager.initialize]. */
  @JvmStatic
  public fun initializeRedisBlocking(manager: RedisManager): Boolean = runBlocking {
    manager.initialize()
    true
  }

  /** Async variant of [BehaviorTracker.applyAction] extension. */
  @JvmStatic
  public fun applyBehaviorAction(
      tracker: BehaviorTracker,
      rule: BehaviorRule,
      clientIp: String,
      endpointId: String,
      details: String,
  ): CompletableFuture<Void?> = bridgeScope.future {
    tracker.applyAction(rule, clientIp, endpointId, details)
    null
  }

  /** Blocking variant of [BehaviorTracker.applyAction] extension. */
  @JvmStatic
  public fun applyBehaviorActionBlocking(
      tracker: BehaviorTracker,
      rule: BehaviorRule,
      clientIp: String,
      endpointId: String,
      details: String,
  ) {
    runBlocking { tracker.applyAction(rule, clientIp, endpointId, details) }
  }
}
