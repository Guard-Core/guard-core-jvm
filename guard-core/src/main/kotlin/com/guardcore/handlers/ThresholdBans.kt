package com.guardcore.handlers

import com.guardcore.config.SecurityConfig

/**
 * Port of `_resolve_and_apply_threshold_ban` (guard_core/core/checks/helpers.py:375-411): the pure
 * threshold resolution plus the ban_ip call, shared by the middleware auto-ban path (W4) and the
 * request-free rate-limit primitive.
 *
 * The W4 pipeline wave owns the rest of helpers.py (`_try_threshold_ban` with its log_activity
 * wiring); this file lands the exact surface the rate-limit auto-ban path needs so the behavior is
 * real, not a stub. Tracked in KNOWN_GAPS.md (G-9, closes W4).
 */
public object ThresholdBans {
  /**
   * Tries `threat_ban_config` per-category entries first (in threatCategories order), then the flat
   * auto_ban_threshold/auto_ban_duration against the total of all categories. Returns (duration,
   * banReason, category) with category null for the flat fallback, or null when banning is
   * disabled, no threshold crossed, or ban_ip refused the ban (self-DoS guard).
   */
  public suspend fun resolveAndApplyThresholdBan(
      ipCounts: Map<String, Int>,
      config: SecurityConfig,
      ipBanManager: IpBanManager,
      clientIp: String,
      threatCategories: Collection<String>,
      reason: String,
  ): Triple<Int, String, String?>? {
    if (!config.enableIpBanning) {
      return null
    }
    for (category in threatCategories) {
      val entry = config.threatBanConfig[category] ?: continue
      val count = ipCounts[category] ?: 0
      if (count < entry.threshold) {
        continue
      }
      val banReason = "$reason:$category"
      val applied = ipBanManager.banIp(clientIp, entry.duration, banReason)
      if (!applied) {
        return null
      }
      return Triple(entry.duration, banReason, category)
    }
    val total = ipCounts.values.sum()
    if (total < config.autoBanThreshold) {
      return null
    }
    val applied = ipBanManager.banIp(clientIp, config.autoBanDuration, reason)
    if (!applied) {
      return null
    }
    return Triple(config.autoBanDuration, reason, null)
  }
}
