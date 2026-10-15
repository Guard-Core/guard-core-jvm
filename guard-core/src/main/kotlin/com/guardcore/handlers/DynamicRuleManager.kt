package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.engine.detection.PatternCompiler
import com.guardcore.util.DetectionEngineWiring
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.util.logging.Logger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout

/**
 * Python `DYNAMIC_RULES_REDIS_NAMESPACE` / `LAST_KNOWN_RULES_KEY` (_dynamic_rule_persistence.py:4).
 */
public const val DYNAMIC_RULES_REDIS_NAMESPACE: String = "dynamic_rules"
public const val LAST_KNOWN_RULES_KEY: String = "last_known"

/** The event surface `match_event` reads via getattr (dynamic_rule_handler.py:89). */
public interface DynamicRuleEvent {
  public val ipAddress: String?
  public val country: String?
  public val eventType: String?
}

/**
 * Port of `guard_core/handlers/dynamic_rule_handler.py` (DynamicRuleManager) with its mixin files:
 * - `_dynamic_rule_application.py` -> [com.guardcore.handlers] dynamic-rule application extensions
 *   (applyIpRules/applyBlockingRules/... in DynamicRuleApplication.kt)
 * - `_dynamic_rule_events.py` -> DynamicRuleEvents.kt extensions
 * - `_dynamic_rule_snapshot.py` -> snapshot/hydration extensions (DynamicRuleSnapshot.kt)
 * - `_dynamic_rule_persistence.py` -> the two namespace constants above
 */
public open class DynamicRuleManager
internal constructor(
    config: SecurityConfig,
) {
  public companion object {
    @Volatile private var instance: DynamicRuleManager? = null

    /** Python `DynamicRuleManager(config)` singleton dispatch (dynamic_rule_handler.py:55). */
    public fun getInstance(config: SecurityConfig): DynamicRuleManager {
      val existing = instance
      if (existing != null) return existing
      synchronized(this) {
        instance?.let {
          return it
        }
        val created = DynamicRuleManager(config)
        instance = created
        return created
      }
    }

    /** Test seam mirroring `DynamicRuleManager._instance = None`. */
    public fun resetInstance() {
      synchronized(this) { instance = null }
    }
  }

  public var config: SecurityConfig = config

  @Volatile public var agentHandler: AgentDynamicRulesSource? = null

  @Volatile public var redisHandler: RedisManager? = null

  public val logger: Logger = Logger.getLogger("guard_core.handlers.dynamic_rule")

  @Volatile public var lastUpdate: Double = 0.0

  @Volatile public var currentRules: DynamicRules? = null

  public var updateTask: Job? = null
    private set

  public val lock: Mutex = Mutex()

  @Volatile private var stopSignal: CompletableDeferred<Unit> = CompletableDeferred()

  @Volatile public var activeBaseSnapshot: Map<String, Any?>? = null

  @Volatile public var lastSkippedExpiredRule: Pair<String, Int>? = null

  @Volatile public var hydratedLastKnownRules: Boolean = false

  /** The agent surface the manager polls and emits to (get_dynamic_rules + send_event). */
  public interface AgentDynamicRulesSource {
    public suspend fun getDynamicRules(): DynamicRules?

    public suspend fun sendEvent(event: Map<String, Any?>)
  }

  private val scope = CoroutineScope(Dispatchers.Default)

  /** Port of `initialize_agent` (dynamic_rule_handler.py:74). */
  public suspend fun initializeAgent(agentHandler: AgentDynamicRulesSource?) {
    this.agentHandler = agentHandler

    if (config.enableDynamicRules) {
      if (!hydratedLastKnownRules) {
        hydratedLastKnownRules = true
        hydrateLastKnownRules()
      }
      if (updateTask == null) {
        startUpdateLoop()
        logger.info("Started dynamic rule update loop")
      }
    }
  }

  /** Port of `initialize_redis` (dynamic_rule_handler.py:86). */
  public suspend fun initializeDynamicRuleRedis(redisHandler: RedisManager?) {
    this.redisHandler = redisHandler
  }

  private fun startUpdateLoop() {
    stopSignal = CompletableDeferred()
    updateTask = scope.launch {
      while (!stopSignal.isCompleted) {
        try {
          updateRules()
          interruptibleSleep(config.dynamicRuleInterval.toDouble())
        } catch (e: kotlinx.coroutines.CancellationException) {
          logger.info("Dynamic rule update loop cancelled")
          break
        } catch (e: Exception) {
          logger.severe("Error in dynamic rule update loop: $e")
          interruptibleSleep(minOf(60.0, config.dynamicRuleInterval.toDouble()))
        }
      }
    }
  }

  private suspend fun interruptibleSleep(timeoutSeconds: Double) {
    try {
      withTimeout((timeoutSeconds * 1000).toLong()) {
        stopSignal.await()
      }
    } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
      // Python: asyncio.TimeoutError swallowed.
    }
  }

  /** Port of `match_event` (dynamic_rule_handler.py:89). */
  public fun matchEvent(event: DynamicRuleEvent): Pair<String, Int>? {
    val rules = currentRules ?: return null
    if (
        eventMatchesIp(event, rules) ||
            eventMatchesCountry(event, rules) ||
            eventMatchesType(event, rules)
    ) {
      return rules.ruleId to rules.version
    }
    return null
  }

  /** Port of `_event_matches_ip` (dynamic_rule_handler.py:101). */
  private fun eventMatchesIp(event: DynamicRuleEvent, rules: DynamicRules): Boolean {
    val ip = event.ipAddress ?: return false
    return ip in (rules.ipBlacklist) || ip in (rules.ipWhitelist)
  }

  /** Port of `_event_matches_country` (dynamic_rule_handler.py:107). */
  private fun eventMatchesCountry(event: DynamicRuleEvent, rules: DynamicRules): Boolean {
    val country = event.country ?: return false
    return country.isNotEmpty() && country in rules.blockedCountries
  }

  /** Port of `_event_matches_type` (dynamic_rule_handler.py:111). */
  private fun eventMatchesType(event: DynamicRuleEvent, rules: DynamicRules): Boolean {
    return when (event.eventType) {
      "rate_limited" -> rules.globalRateLimit != null || rules.endpointRateLimits.isNotEmpty()
      "cloud_blocked" -> rules.blockedCloudProviders.isNotEmpty()
      "user_agent_blocked" -> rules.blockedUserAgents.isNotEmpty()
      else -> false
    }
  }

  /** Port of `_should_update_rules` (dynamic_rule_handler.py:143). */
  public fun shouldUpdateRules(rules: DynamicRules): Boolean {
    val current = currentRules ?: return true
    return !(rules.ruleId == current.ruleId && rules.version <= current.version)
  }

  /** Port of `_check_rule_expiry` (dynamic_rule_handler.py:152). */
  public suspend fun checkRuleExpiry() {
    lock.withLock {
      val rules = currentRules ?: return
      val expiresAt = rules.expiresAt ?: return
      if (OffsetDateTime.now(ZoneOffset.UTC) <= coerceNaiveUtc(expiresAt)) {
        return
      }

      val snapshot = activeBaseSnapshot
      if (snapshot != null) {
        restoreConfig(config, snapshot)
      }
      currentRules = null
      activeBaseSnapshot = null
      logger.info(
          "Dynamic rule ${rules.ruleId} v${rules.version} expired; restored base config",
      )
    }
  }

  /** Python `_coerce_naive_utc` (dynamic_rule_handler.py:16). */
  public fun coerceNaiveUtc(value: OffsetDateTime): OffsetDateTime = value

  /** Port of `_has_rule_expired` (dynamic_rule_handler.py:169). */
  public fun hasRuleExpired(rules: DynamicRules): Boolean {
    val expiresAt = rules.expiresAt ?: return false
    return OffsetDateTime.now(ZoneOffset.UTC) > coerceNaiveUtc(expiresAt)
  }

  /** Port of `_reject_if_already_expired` (dynamic_rule_handler.py:174). */
  public fun rejectIfAlreadyExpired(rules: DynamicRules): Boolean {
    if (!hasRuleExpired(rules)) {
      return false
    }
    val key = rules.ruleId to rules.version
    if (lastSkippedExpiredRule != key) {
      lastSkippedExpiredRule = key
      logger.warning(
          "Dynamic rule ${rules.ruleId} v${rules.version} already expired on receipt; ignoring",
      )
    }
    return true
  }

  /** Port of `update_rules` (dynamic_rule_handler.py:187). */
  public suspend fun updateRules() {
    val agent = agentHandler
    if (!config.enableDynamicRules || agent == null) {
      return
    }

    try {
      checkRuleExpiry()

      val rules = agent.getDynamicRules() ?: return

      if (rejectIfAlreadyExpired(rules)) {
        return
      }

      if (!shouldUpdateRules(rules)) {
        return
      }

      sendRuleReceivedEvent(rules)

      logger.info("Applying dynamic rules: ${rules.ruleId} v${rules.version}")
      applyRules(rules)

      currentRules = rules
      lastUpdate = nowSeconds()

      sendRuleAppliedEvent(rules)
    } catch (e: Exception) {
      logger.severe("Failed to update dynamic rules: $e")
    }
  }

  /**
   * Port of `_apply_rules` (dynamic_rule_handler.py:234): each version overlays the true base. The
   * active base snapshot is restored first, so the emergency halving and the replaced collections
   * never compound across versions, and a failed apply restores the config as it was before the
   * call (the active version), not the base.
   */
  public suspend fun applyRules(rules: DynamicRules) {
    lock.withLock {
      val previous = snapshotConfig(config)
      activeBaseSnapshot?.let { restoreConfig(config, it) }
      val snapshot = snapshotConfig(config)
      try {
        applyIpRules(rules)
        applyBlockingRules(rules)
        if (rules.globalRateLimit != null || rules.endpointRateLimits.isNotEmpty()) {
          applyRateLimitRules(rules)
        }
        applyFeatureToggles(rules)
        if (rules.emergencyMode) {
          activateEmergencyMode(rules.emergencyWhitelist)
        }
      } catch (e: Exception) {
        restoreConfig(config, previous)
        logger.severe("Failed to apply dynamic rules: $e")
        throw e
      }

      captureActiveBaseSnapshot(this, snapshot)

      persistLastKnownRules(rules)
    }
  }

  /** Port of `_activate_emergency_mode` (_dynamic_rule_application.py:210). */
  public open suspend fun activateEmergencyMode(emergencyWhitelist: List<String>) {
    logger.severe("[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled")

    config.emergencyMode = true
    config.emergencyWhitelist = emergencyWhitelist

    val originalThreshold = config.autoBanThreshold
    config.autoBanThreshold = maxOf(1, originalThreshold / 2)
    val message = "Reduced auto-ban threshold"
    val details = "from $originalThreshold to ${config.autoBanThreshold}"
    logger.warning("[EMERGENCY MODE] $message $details")

    if (agentHandler != null) {
      sendEmergencyEvent(emergencyWhitelist)
    }
  }

  /** Port of `get_current_rules` (dynamic_rule_handler.py:259). */
  public suspend fun getCurrentRules(): DynamicRules? = currentRules

  /** Port of `force_update` (dynamic_rule_handler.py:262). */
  public suspend fun forceUpdate() {
    updateRules()
  }

  // ------------------------------------------------------------------
  // _dynamic_rule_application.py (DynamicRuleApplicationMixin) as open
  // members: the python tests override `_apply_blocking_rules` to drive the
  // rollback path, and open members preserve that seam.

  /** Port of `_redact_pattern_list` (_dynamic_rule_application.py:8). */
  private fun redactPatternList(patterns: List<String>): List<String> = patterns.map {
    DetectionScanRedaction.redactPatternSource(it)
  }

  /** Port of `_redact_rejected_patterns` (_dynamic_rule_application.py:12). */
  private fun redactRejectedPatterns(
      rejected: List<Pair<String, String>>,
  ): List<Pair<String, String>> = rejected.map { (pattern, reason) ->
    DetectionScanRedaction.redactPatternSource(pattern) to reason
  }

  /** Port of `_apply_ip_rules` (_dynamic_rule_application.py:22). */
  public open suspend fun applyIpRules(rules: DynamicRules) {
    if (rules.ipBlacklist.isNotEmpty()) {
      applyIpBans(rules.ipBlacklist, rules.ipBanDuration)
    }
    if (rules.ipWhitelist.isNotEmpty()) {
      applyIpWhitelist(rules.ipWhitelist)
    }
  }

  /** Port of `_apply_blocking_rules` (_dynamic_rule_application.py:29). */
  public open suspend fun applyBlockingRules(rules: DynamicRules) {
    if (rules.blockedCountries.isNotEmpty() || rules.whitelistCountries.isNotEmpty()) {
      applyCountryRules(rules.blockedCountries, rules.whitelistCountries)
    }
    if (rules.blockedCloudProviders.isNotEmpty()) {
      applyCloudProviderRules(rules.blockedCloudProviders)
    }
    if (rules.blockedUserAgents.isNotEmpty()) {
      applyUserAgentRules(rules.blockedUserAgents)
    }
    if (rules.suspiciousPatterns.isNotEmpty()) {
      applyPatternRules(rules.suspiciousPatterns)
    }
  }

  /** Port of `_apply_ip_bans` (_dynamic_rule_application.py:44). */
  public open suspend fun applyIpBans(ipList: List<String>, duration: Int) {
    val ipBanManager = IpBanManager.getInstance()
    for (ip in ipList) {
      try {
        val applied = ipBanManager.banIp(ip, duration, "dynamic_rule")
        if (applied) {
          logger.info("Dynamic rule: Banned IP $ip for ${duration}s")
        }
      } catch (e: Exception) {
        logger.severe("Failed to ban IP $ip: $e")
      }
    }
  }

  /** Port of `_apply_ip_whitelist` (_dynamic_rule_application.py:55). */
  public open suspend fun applyIpWhitelist(ipList: List<String>) {
    val ipBanManager = IpBanManager.getInstance()
    for (ip in ipList) {
      try {
        ipBanManager.unbanIp(ip)
        logger.info("Dynamic rule: Whitelisted IP $ip")
      } catch (e: Exception) {
        logger.severe("Failed to whitelist IP $ip: $e")
      }
    }
  }

  /** Port of `_apply_country_rules` (_dynamic_rule_application.py:65). */
  public open suspend fun applyCountryRules(blocked: List<String>, allowed: List<String>) {
    if (
        (blocked.isNotEmpty() || allowed.isNotEmpty()) &&
            config.geoIpHandler == null &&
            config.ipinfoToken.isNullOrEmpty()
    ) {
      logger.warning(
          "Dynamic rule: country rules cannot take effect (blocked=" +
              "$blocked, allowed=$allowed); no geo_ip_handler or " +
              "ipinfo_token is configured to resolve IPs to countries",
      )
      return
    }

    if (blocked.isNotEmpty()) {
      val normalizedBlocked = blocked.map { it.uppercase() }.toSet()
      config.blockedCountries = normalizedBlocked
      logger.info("Dynamic rule: Blocked countries ${normalizedBlocked.toSortedSet()}")
    }

    if (allowed.isNotEmpty()) {
      val normalizedAllowed = allowed.map { it.uppercase() }.toSet()
      config.whitelistCountries = normalizedAllowed
      logger.info("Dynamic rule: Whitelisted countries ${normalizedAllowed.toSortedSet()}")
    }
  }

  /** Port of `_apply_rate_limit_rules` (_dynamic_rule_application.py:94). */
  public open suspend fun applyRateLimitRules(rules: DynamicRules) {
    val globalLimit = rules.globalRateLimit
    if (globalLimit != null) {
      config.rateLimit = globalLimit
      val globalWindow = rules.globalRateWindow
      if (globalWindow != null) {
        config.rateLimitWindow = globalWindow
      }
      val message = "Global rate limit $globalLimit"
      val details = "per ${globalWindow ?: 0}s"
      logger.info("Dynamic rule: $message $details")
    }

    if (rules.endpointRateLimits.isNotEmpty()) {
      config.endpointRateLimits = rules.endpointRateLimits.toMap()
      logger.info(
          "Dynamic rule: Applied endpoint-specific rate limits for " +
              "${rules.endpointRateLimits.size} endpoints: " +
              "${rules.endpointRateLimits.keys.toList()}",
      )
    }
  }

  /** Port of `_apply_cloud_provider_rules` (_dynamic_rule_application.py:111). */
  public open suspend fun applyCloudProviderRules(providers: Set<String>) {
    val valid = providers.filter { it.substringBefore(":!") in VALID_CLOUD_PROVIDERS }.toSet()
    config.blockCloudProviders = valid
    val invalid = providers - valid
    if (invalid.isNotEmpty()) {
      logger.warning("Dynamic rule: ignored unknown cloud providers ${invalid.toSortedSet()}")
    }
    logger.info("Dynamic rule: Blocked cloud providers $valid")
  }

  /** Port of `_apply_user_agent_rules` (_dynamic_rule_application.py:123). */
  public open suspend fun applyUserAgentRules(userAgents: List<String>) {
    val cachePath = config.detectionPatternValidationCachePath
    val validationCache = cachePath?.let {
      com.guardcore.engine.detection.PatternValidationCache(
          java.nio.file.Path.of(it),
          com.guardcore.engine.GuardCoreEngine.VERSION,
      )
    }
    val compiler = PatternCompiler(validationCache = validationCache)
    val valid = mutableListOf<String>()
    val rejected = mutableListOf<Pair<String, String>>()
    for (pattern in userAgents) {
      val (isSafe, reason) =
          compiler.validatePatternSafety(
              pattern,
              maxContentLength = DetectionEngineWiring.MAX_USER_AGENT_MATCH_LENGTH,
          )
      if (isSafe) {
        valid.add(pattern)
      } else {
        rejected.add(pattern to reason)
      }
    }

    config.setPrevalidated("blocked_user_agents", valid)
    if (rejected.isNotEmpty()) {
      logger.warning(
          "Dynamic rule: rejected blocked_user_agents patterns failing the " +
              "ReDoS validator: ${redactRejectedPatterns(rejected)}",
      )
    }
    logger.info("Dynamic rule: Blocked user agents ${redactPatternList(valid)}")
  }

  /** Port of `_apply_pattern_rules` (_dynamic_rule_application.py:159). */
  public open suspend fun applyPatternRules(patterns: List<String>) {
    val known = SusPatternsRegistry.getAllPatterns().toSet()
    @Suppress("NAME_SHADOWING") val patterns = patterns.filter { it !in known }
    val added = patterns.filter { SusPatternsRegistry.addPattern(it) }
    if (added.isNotEmpty()) {
      logger.info("Dynamic rule: Added suspicious patterns ${redactPatternList(added)}")
    }

    val rejected = patterns.filter { it !in added }
    if (rejected.isNotEmpty()) {
      logger.warning("Dynamic rule: rejected patterns ${redactPatternList(rejected)}")
    }
  }

  /** Port of `_apply_feature_toggles` (_dynamic_rule_application.py:174). */
  public open suspend fun applyFeatureToggles(rules: DynamicRules) {
    rules.enablePenetrationDetection?.let {
      config.enablePenetrationDetection = it
      val details = "Penetration detection $it"
      logger.info("Dynamic rule: $details")
    }

    rules.enableIpBanning?.let {
      config.enableIpBanning = it
      logger.info("Dynamic rule: IP banning $it")
    }

    rules.enableRateLimiting?.let {
      config.enableRateLimiting = it
      logger.info("Dynamic rule: Rate limiting $it")
    }

    rules.enableRateLimitAutoBan?.let {
      config.enableRateLimitAutoBan = it
      logger.info("Dynamic rule: Rate-limit auto-ban $it")
    }

    rules.autoBanThreshold?.let {
      config.autoBanThreshold = it
      logger.info("Dynamic rule: Auto-ban threshold $it")
    }

    rules.autoBanDuration?.let {
      config.autoBanDuration = it
      logger.info("Dynamic rule: Auto-ban duration $it")
    }
  }

  /** Port of `stop` (dynamic_rule_handler.py:265). */
  public suspend fun stop() {
    val task = updateTask
    if (task != null) {
      stopSignal.complete(Unit)
      task.cancel()
      try {
        task.join()
      } catch (e: kotlinx.coroutines.CancellationException) {
        // Python: CancelledError swallowed.
      }
      updateTask = null
      logger.info("Stopped dynamic rule update loop")
    }
  }
}

/**
 * Port of `guard_core/handlers/_dynamic_rule_snapshot.py` (DynamicRuleSnapshotMixin) as extensions
 * over [DynamicRuleManager].
 */

/** Port of `_hydrate_last_known_rules` (_dynamic_rule_snapshot.py:30). */
public suspend fun DynamicRuleManager.hydrateLastKnownRules() {
  try {
    val rules = loadLastKnownRules() ?: return
    applyRules(rules)
    currentRules = rules
    lastUpdate = nowSeconds()
    logger.info(
        "Hydrated last-known dynamic rules ${rules.ruleId} " +
            "v${rules.version} before the update loop started",
    )
  } catch (e: Exception) {
    logger.severe("Failed to hydrate last-known dynamic rules: $e")
  }
}

/** Port of `_load_last_known_rules` (_dynamic_rule_snapshot.py:45). */
public suspend fun DynamicRuleManager.loadLastKnownRules(): DynamicRules? {
  val redisPayload = readRedisPayload()
  val filePayload = readFilePayload()
  for (payload in listOf(redisPayload, filePayload)) {
    if (payload == null) {
      continue
    }
    val rules = parseLastKnownRules(payload) ?: continue
    if (hasRuleExpired(rules)) {
      logger.severe(
          "Discarding expired last-known dynamic rules " +
              "${rules.ruleId} v${rules.version}; trying the next store",
      )
      continue
    }
    return rules
  }
  return null
}

/** Port of `_read_redis_payload` (_dynamic_rule_snapshot.py:63). */
public suspend fun DynamicRuleManager.readRedisPayload(): String? {
  val redis = redisHandler ?: return null
  val raw =
      try {
        redis.getKey(DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_KEY)
      } catch (e: Exception) {
        logger.severe("Failed to read last-known dynamic rules from Redis: $e")
        return null
      }
  if (raw == null || raw == "") {
    return null
  }
  return when (raw) {
    is ByteArray -> String(raw, Charsets.UTF_8)
    else -> raw.toString()
  }
}

/** Port of `_read_file_payload` (_dynamic_rule_snapshot.py:83). */
public fun DynamicRuleManager.readFilePayload(): String? {
  val path = config.dynamicRulesCachePath ?: return null
  if (!Files.isRegularFile(path)) {
    return null
  }
  return try {
    String(Files.readAllBytes(path), Charsets.UTF_8)
  } catch (e: Exception) {
    logger.severe("Failed to read dynamic rules cache file $path: $e")
    null
  }
}

/** Port of `_parse_last_known_rules` (_dynamic_rule_snapshot.py:93). */
public fun DynamicRuleManager.parseLastKnownRules(payload: String): DynamicRules? {
  return try {
    loadLastKnownRulesSnapshot(payload)
  } catch (e: Exception) {
    logger.severe("Discarding unusable last-known dynamic rules payload: $e")
    null
  }
}

/** Port of `_persist_last_known_rules` (_dynamic_rule_snapshot.py:102). */
public suspend fun DynamicRuleManager.persistLastKnownRules(rules: DynamicRules) {
  val payload =
      try {
        dumpLastKnownRulesSnapshot(rules)
      } catch (e: Exception) {
        logger.severe("Failed to build last-known dynamic rules snapshot: $e")
        return
      }

  val redis = redisHandler
  if (redis != null) {
    try {
      redis.setKey(DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_KEY, payload)
    } catch (e: Exception) {
      logger.severe("Failed to persist dynamic rules to Redis: $e")
    }
  }

  val cachePath = config.dynamicRulesCachePath
  if (cachePath == null) {
    return
  }
  try {
    writeLastKnownRulesFile(cachePath, payload)
  } catch (e: Exception) {
    logger.severe("Failed to persist dynamic rules to cache file $cachePath: $e")
  }
}

/** Port of `_write_last_known_rules_file` (_dynamic_rule_snapshot.py:131): atomic tmp + replace. */
public fun DynamicRuleManager.writeLastKnownRulesFile(cachePath: Path, payload: String) {
  Files.createDirectories(cachePath.parent)
  val tempPath = Files.createTempFile(cachePath.parent, "${cachePath.fileName}.", ".tmp")
  try {
    Files.write(tempPath, payload.toByteArray(Charsets.UTF_8))
    Files.move(
        tempPath,
        cachePath,
        StandardCopyOption.REPLACE_EXISTING,
        StandardCopyOption.ATOMIC_MOVE,
    )
  } catch (e: Exception) {
    try {
      Files.deleteIfExists(tempPath)
    } catch (ignored: Exception) {}
    throw e
  }
}

/** Port of `resolve_redis_value` (_dynamic_rule_persistence.py:8): Kotlin values are direct. */
public suspend fun resolveRedisValue(value: Any?): Any? = value
