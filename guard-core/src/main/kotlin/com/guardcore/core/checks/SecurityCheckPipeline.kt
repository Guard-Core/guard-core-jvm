package com.guardcore.core.checks

import com.guardcore.config.SecurityConfig
import com.guardcore.errors.GuardRedisError
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.BlockEvents
import com.guardcore.util.RequestLogging

/**
 * Port of `guard_core/core/checks/pipeline.py`: SecurityCheckPipeline (pipeline.py:16). Runs the
 * fixed-order checks, rebuilds on config/revision staleness, fails open or secure per config, and
 * fires the on_block hook for every blocking check.
 */
public class SecurityCheckPipeline(
    public var checks: List<SecurityCheck>,
    public var mutedCheckLogs: Set<String> = emptySet(),
    private val config: SecurityConfig? = null,
    private val rebuildChecks: (() -> List<SecurityCheck>)? = null,
    private val watchedContainerFields: List<String> = emptyList(),
    private val routeConfigRevision: (() -> Int?)? = null,
) {
  public val logger: java.util.logging.Logger =
      java.util.logging.Logger.getLogger("guard_core.core.checks.pipeline")

  private val rebuildLock = Any()
  private var builtRevision: Int? = config?.revision
  private var builtSignature: List<Int> =
      if (config != null) containerSignature(config) else emptyList()
  private var builtRouteConfigRevision: Int? = currentRouteConfigRevision()

  /** Python `_container_size` static (pipeline.py:41). */
  private fun containerSize(value: Any?): Int =
      when (value) {
        null -> 0
        is Collection<*> -> value.size
        is Map<*, *> -> value.size
        else -> 0
      }

  /** Python `_container_signature` (pipeline.py:45). */
  private fun containerSignature(config: SecurityConfig): List<Int> =
      watchedContainerFields.map { field ->
        containerSize(readContainerField(config, field))
      }

  /** The container fields watched by the default checks, read off SecurityConfig. */
  private fun readContainerField(config: SecurityConfig, field: String): Any? =
      when (field) {
        "block_cloud_providers" -> config.blockCloudProviders
        "blocked_user_agents" -> config.blockedUserAgents
        "endpoint_rate_limits" -> config.endpointRateLimits
        else -> null
      }

  /** Python `_current_route_config_revision` (pipeline.py:51). */
  private fun currentRouteConfigRevision(): Int? = routeConfigRevision?.invoke()

  /** Python `_is_stale` (pipeline.py:56). */
  private fun isStale(config: SecurityConfig): Boolean {
    if (config.revision != builtRevision) {
      return true
    }
    if (containerSignature(config) != builtSignature) {
      return true
    }
    return currentRouteConfigRevision() != builtRouteConfigRevision
  }

  /** Python `_rebuild_if_stale` (pipeline.py:65). */
  private fun rebuildIfStale() {
    val cfg = config ?: return
    val rebuild = rebuildChecks ?: return
    if (!isStale(cfg)) {
      return
    }
    val revision = cfg.revision
    val signature = containerSignature(cfg)
    val routeRevision = currentRouteConfigRevision()
    val muted = cfg.mutedCheckLogs
    val checks = rebuild()
    synchronized(rebuildLock) {
      this.checks = checks
      this.mutedCheckLogs = muted
      this.builtRevision = revision
      this.builtSignature = signature
      this.builtRouteConfigRevision = routeRevision
    }
  }

  /** Python `_log_extra` (pipeline.py:83): the structured log fields. */
  private fun logExtra(check: SecurityCheck, request: GuardRequest): Map<String, Any?> =
      linkedMapOf(
          "check" to check.checkName,
          "path" to request.urlPath,
          "method" to request.method,
      )

  /** Python async `_handle_check_error` (pipeline.py:90). */
  private suspend fun handleCheckError(
      check: SecurityCheck,
      request: GuardRequest,
      error: Throwable,
  ): GuardResponse? {
    val muted = check.checkName in mutedCheckLogs

    if (error is GuardRedisError && check.config.redisFailOpen) {
      if (!muted) {
        logger.warning(
            "Skipping check ${check.checkName}: Redis unavailable, failing open " +
                "(redis_fail_open=True)",
        )
      }
      return null
    }

    if (!muted) {
      val safeMessage =
          RequestLogging.redactHeaderValueForDisplay(
              error.toString(),
              check.config.logSensitiveParams,
              check.config.logSensitiveBodyFields,
              check.config.logSensitiveHeaders,
          )
      logger.severe(
          "Error in security check ${check.checkName} " +
              "(${error::class.java.simpleName}): $safeMessage",
      )
    }

    if (check.config.failSecure) {
      if (!muted) {
        logger.warning(
            "Blocking request due to check error in fail-secure mode: ${check.checkName}",
        )
      }
      return check.createErrorResponse(statusCode = 500, defaultMessage = "Security check failed")
    }

    return null
  }

  /** Python async `_fire_block_hook` (pipeline.py:130). */
  private suspend fun fireBlockHook(
      check: SecurityCheck,
      request: GuardRequest,
      response: GuardResponse,
  ) {
    @Suppress("UNCHECKED_CAST")
    val stash = request.state.getAttr("_guard_block_stash") as? Map<String, Any?>
    BlockEvents.fireBlockHook(
        check.config.onBlock,
        request,
        check.checkName,
        stash?.get("reason") as? String ?: "",
        stash?.get("trigger_info") as? String ?: "",
        false,
        response.statusCode,
        check.config.logSensitiveParams,
        check.config.logSensitiveBodyFields,
        check.config.logSensitiveHeaders,
    )
  }

  /** Python async `_handle_rebuild_error` (pipeline.py:147). */
  private suspend fun handleRebuildError(request: GuardRequest, error: Throwable): GuardResponse? {
    logger.severe("Error rebuilding security checks: $error")
    val cfg = config ?: return null
    if (!cfg.failSecure) {
      return null
    }
    if (checks.isEmpty()) {
      throw error
    }
    logger.warning("Blocking request due to rebuild error in fail-secure mode")
    return checks[0].createErrorResponse(statusCode = 500, defaultMessage = "Security check failed")
  }

  /** Python async `execute` (pipeline.py:166). */
  public suspend fun execute(request: GuardRequest): GuardResponse? {
    try {
      rebuildIfStale()
    } catch (e: Throwable) {
      val response = handleRebuildError(request, e)
      if (response != null) {
        return response
      }
    }

    request.state.setAttr("_guard_pipeline_start", System.nanoTime() / 1_000_000_000.0)
    val exclusionScoped = request.state.getAttr("guard_exclusion_scoped") == true

    for (check in checks) {
      if (exclusionScoped && !check.enforcedOnExcludedPaths) {
        continue
      }
      try {
        val response = check.check(request)
        if (response != null) {
          if (check.checkName !in mutedCheckLogs) {
            logger.fine("Request blocked by ${check.checkName}")
          }
          fireBlockHook(check, request, response)
          return response
        }
      } catch (e: Throwable) {
        val errorResponse = handleCheckError(check, request, e)
        if (errorResponse != null) {
          return errorResponse
        }
      }
    }

    return null
  }

  /** Python `add_check` (pipeline.py:200). */
  public fun addCheck(check: SecurityCheck) {
    checks = checks + check
  }

  /** Python `insert_check` (pipeline.py:203). */
  public fun insertCheck(index: Int, check: SecurityCheck) {
    checks = checks.toMutableList().apply { add(index, check) }
  }

  /** Python `remove_check` (pipeline.py:206). */
  public fun removeCheck(checkName: String): Boolean {
    val index = checks.indexOfFirst { it.checkName == checkName }
    if (index < 0) {
      return false
    }
    checks = checks.toMutableList().apply { removeAt(index) }
    return true
  }

  /** Python `get_check_names` (pipeline.py:213). */
  public fun getCheckNames(): List<String> = checks.map { it.checkName }

  public val size: Int
    get() = checks.size

  override fun toString(): String =
      "SecurityCheckPipeline(${checks.size} checks: ${checks.joinToString(", ") { it.checkName }})"
}
