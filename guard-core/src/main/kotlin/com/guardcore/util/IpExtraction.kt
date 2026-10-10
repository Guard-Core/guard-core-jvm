package com.guardcore.util

import com.guardcore.protocols.AgentHandlerProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.util.py.IPv6Address
import com.guardcore.util.py.IpAddress
import com.guardcore.util.py.IpNetwork
import com.guardcore.util.py.parseAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.logging.Level

/**
 * Port of `guard_core/_utils/ip_extraction.py` (ip_extraction.py:1-368): trusted-proxy-aware client
 * IP resolution from the connecting peer and the X-Forwarded-For chain.
 */
public object IpExtraction {
  /** Port of `UNKNOWN_CLIENT_IDENTITY` (ip_extraction.py:12). */
  public const val UNKNOWN_CLIENT_IDENTITY: String = "unknown"

  /** `request.state.client_ip` cache read (ip_extraction.py:329). */
  internal fun stateClientIp(request: GuardRequest): String? =
      request.state.getAttr("client_ip") as? String

  /** Python's module-level once-only warning flags (ip_extraction.py:146ff). */
  private val onceFlags = ConcurrentHashMap<String, Boolean>()

  internal fun resetOnceFlags() {
    onceFlags.clear()
  }

  /** Port of `_proxy_matches` (ip_extraction.py:15). */
  private fun proxyMatches(
      connectingIp: String,
      connectingIpObj: IpAddress,
      proxy: String,
  ): Boolean =
      if ("/" in proxy) {
        try {
          IpNetwork.parse(proxy).contains(connectingIpObj)
        } catch (_: com.guardcore.errors.ConfigValidationError) {
          false
        }
      } else {
        connectingIp == proxy
      }

  /** Port of `_is_trusted_proxy` (ip_extraction.py:21). */
  internal fun isTrustedProxy(connectingIp: String, trustedProxies: List<String>): Boolean =
      try {
        val connectingIpObj = parseAddress(connectingIp)
        trustedProxies.any { proxyMatches(connectingIp, connectingIpObj, it) }
      } catch (_: com.guardcore.errors.ConfigValidationError) {
        false
      }

  /** Port of `_canonical_ip_text` (ip_extraction.py:32). */
  internal fun canonicalIpText(addr: IpAddress): String {
    if (addr is IPv6Address && addr.ipv4Mapped != null && addr.scopeId == null) {
      return addr.ipv4Mapped!!.text
    }
    return addr.text
  }

  /** Port of `_strip_ip_brackets` (ip_extraction.py:42). */
  internal fun stripIpBrackets(value: String): String =
      if (value.startsWith("[") && value.endsWith("]")) value.substring(1, value.length - 1)
      else value

  /** Port of `_strip_forwarded_entry_port` (ip_extraction.py:48). */
  internal fun stripForwardedEntryPort(value: String): String {
    if (value.startsWith("[")) {
      val closing = value.indexOf(']')
      if (closing == -1) return value
      val remainder = value.substring(closing + 1)
      if (
          remainder.isNotEmpty() &&
              !(remainder.startsWith(":") && remainder.substring(1).all { it in '0'..'9' })
      ) {
        return value
      }
      return value.substring(1, closing)
    }
    if (value.count { it == ':' } == 1) {
      val idx = value.indexOf(':')
      val host = value.substring(0, idx)
      val port = value.substring(idx + 1)
      if (port.isNotEmpty() && port.all { it in '0'..'9' }) return host
    }
    return value
  }

  /** Port of `_canonicalize_ip` (ip_extraction.py:64). */
  public fun canonicalizeIp(value: String): String =
      try {
        canonicalIpText(parseAddress(stripIpBrackets(value)))
      } catch (_: com.guardcore.errors.ConfigValidationError) {
        value
      }

  /** Port of `_forwarded_header_candidate_has_metachar` (ip_extraction.py:72). */
  private fun forwardedHeaderCandidateHasMetachar(candidate: String): Boolean = candidate.any {
    it == '*' || it == '?' || it == '[' || it == ']' || it == '\\'
  }

  /** Port of `_forwarded_header_candidate` (ip_extraction.py:76). */
  private fun forwardedHeaderCandidate(forwardedFor: String, proxyDepth: Int): String? {
    val ips = forwardedFor.split(",").map { it.trim() }
    if (ips.size < proxyDepth) return null
    return stripForwardedEntryPort(ips[ips.size - proxyDepth])
  }

  private fun forwardedHeaderCandidateAddr(candidate: String): IpAddress? =
      try {
        parseAddress(candidate)
      } catch (_: com.guardcore.errors.ConfigValidationError) {
        null
      }

  /** Port of `_extract_from_forwarded_header` (ip_extraction.py:92). */
  private fun extractFromForwardedHeader(forwardedFor: String, proxyDepth: Int): String? {
    if (forwardedFor.isEmpty()) return null
    val candidate = forwardedHeaderCandidate(forwardedFor, proxyDepth) ?: return null
    val addr = forwardedHeaderCandidateAddr(candidate) ?: return null
    if (forwardedHeaderCandidateHasMetachar(candidate)) return null
    return canonicalIpText(addr)
  }

  /** Port of `_forwarded_header_ips` (ip_extraction.py:110). */
  private fun forwardedHeaderIps(forwardedFor: String): List<String> =
      forwardedFor.split(",").map { stripForwardedEntryPort(it.trim()) }

  /** Port of `_forwarded_header_right_side_unlisted_count` (ip_extraction.py:114). */
  private fun forwardedHeaderRightSideUnlistedCount(
      ips: List<String>,
      proxyDepth: Int,
      trustedProxies: List<String>,
  ): Int {
    val rightSide = ips.drop(maxOf(0, ips.size - proxyDepth + 1))
    return rightSide.count { !isTrustedProxy(canonicalizeIp(it), trustedProxies) }
  }

  /** Port of `_resolve_forwarded_chain_right_to_left` (ip_extraction.py:125). */
  private fun resolveForwardedChainRightToLeft(
      ips: List<String>,
      trustedProxies: List<String>,
  ): String? {
    for (entry in ips.reversed()) {
      if (isTrustedProxy(canonicalizeIp(entry), trustedProxies)) continue
      val addr = forwardedHeaderCandidateAddr(entry) ?: return null
      if (forwardedHeaderCandidateHasMetachar(entry)) return null
      return canonicalIpText(addr)
    }
    return null
  }

  /** Port of `_is_private_or_loopback` (ip_extraction.py:138). */
  internal fun isPrivateOrLoopback(ip: String): Boolean =
      try {
        val addr = parseAddress(ip)
        addr.isPrivate || addr.isLoopback || addr.isLinkLocal
      } catch (_: com.guardcore.errors.ConfigValidationError) {
        false
      }

  /** Port of `_warn_forwarded_header_preempted` (ip_extraction.py:149). */
  private fun warnForwardedHeaderPreempted(connectingIp: String, forwardedFor: String?) {
    if (onceFlags.getOrPut("preempted") { false } || forwardedFor.isNullOrEmpty()) return
    val entries = forwardedFor.split(",").map { it.trim() }
    if (connectingIp !in entries) return
    onceFlags["preempted"] = true
    DetectionScanContext.guardLogger.warning(
        "The connecting IP (${LoggingUtils.sanitizeForLog(connectingIp)}) already appears inside its own " +
            "X-Forwarded-For chain: the application server resolved the client " +
            "from that header before guard-core ran, most likely because the " +
            "server's own forwarded-header handling is enabled (uvicorn " +
            "defaults to proxy_headers=True). While it is, the address " +
            "guard-core sees is whatever the client claimed, so a rotating " +
            "X-Forwarded-For defeats rate limiting and IP banning. To make " +
            "guard-core the single authority, disable the server's handling " +
            "(`uvicorn --no-proxy-headers`, or `proxy_headers=False` in " +
            "uvicorn.run; gunicorn/hypercorn/WSGI servers have equivalent " +
            "settings) AND declare the proxy via trusted_proxies / " +
            "trusted_proxy_depth so guard-core resolves the real client itself. " +
            "Disabling proxy_headers alone is not enough: if you also use " +
            "enforce_https, set trust_x_forwarded_proto=True with the same " +
            "trusted_proxies, otherwise the server stops forwarding the URL " +
            "scheme and HTTPS detection breaks (infinite redirect loop) on " +
            "TLS-terminating hosts such as Render or Heroku. This warning is " +
            "logged once.",
    )
  }

  /** Port of `_display_forwarded_chain` (ip_extraction.py:184). */
  internal fun displayForwardedChain(value: String): String =
      value.split(",").joinToString(",") { part ->
        val candidate = stripForwardedEntryPort(part.trim())
        if (forwardedHeaderCandidateAddr(candidate) != null) part else "[REDACTED]"
      }

  /** Port of `_handle_untrusted_proxy` (ip_extraction.py:195). */
  private suspend fun handleUntrustedProxy(
      request: GuardRequest,
      connectingIp: String,
      canonicalConnectingIp: String,
      forwardedFor: String?,
      agentHandler: AgentHandlerProtocol?,
  ): String {
    if (!forwardedFor.isNullOrEmpty()) {
      warnForwardedHeaderPreempted(connectingIp, forwardedFor)
      val displayForwardedFor = displayForwardedChain(forwardedFor)
      val safeForwardedFor = LoggingUtils.sanitizeForLog(displayForwardedFor)
      val message =
          "Potential IP spoof attempt: X-Forwarded-For header " +
              "($safeForwardedFor) received from untrusted IP " +
              LoggingUtils.sanitizeForLog(connectingIp)
      if (isPrivateOrLoopback(connectingIp)) {
        DetectionScanContext.guardLogger.fine(message)
      } else {
        DetectionScanContext.guardLogger.warning(message)
      }
      AgentEvents.sendAgentEvent(
          agentHandler,
          com.guardcore.config.EventTypes.EVENT_SUSPICIOUS_REQUEST,
          canonicalConnectingIp,
          "spoofing_detected",
          "Potential IP spoof attempt: X-Forwarded-For header $displayForwardedFor",
          request,
      )
    }
    return canonicalConnectingIp
  }

  /** Port of `_warn_forwarded_header_chain_too_short` (ip_extraction.py:231). */
  private fun warnForwardedHeaderChainTooShort(forwardedFor: String, chainLength: Int) {
    if (onceFlags.getOrPut("chain_too_short") { false }) return
    onceFlags["chain_too_short"] = true
    DetectionScanContext.guardLogger.warning(
        "The X-Forwarded-For chain has only $chainLength entries, fewer than the " +
            "configured trusted_proxy_depth; chain was " +
            LoggingUtils.sanitizeForLog(displayForwardedChain(forwardedFor)) +
            "; falling back to the connecting peer as the client. This warning is " +
            "logged once.",
    )
  }

  /** Port of `_warn_forwarded_header_selected_entry_trusted_proxy` (ip_extraction.py:250). */
  private fun warnForwardedHeaderSelectedEntryTrustedProxy(entry: String) {
    if (onceFlags.getOrPut("selected_entry_trusted") { false }) return
    onceFlags["selected_entry_trusted"] = true
    DetectionScanContext.guardLogger.warning(
        "trusted_proxy_depth selected ${LoggingUtils.sanitizeForLog(entry)} from the " +
            "X-Forwarded-For chain, but that address is itself listed in trusted_proxies; the chain " +
            "likely has more proxy hops than trusted_proxy_depth accounts for. " +
            "This warning is logged once.",
    )
  }

  /** Port of `_warn_forwarded_header_depth_overcounts_hops` (ip_extraction.py:267). */
  private fun warnForwardedHeaderDepthOvercountsHops(
      unlistedRightEntries: Int,
      forwardedFor: String,
  ) {
    if (onceFlags.getOrPut("depth_overcounts") { false }) return
    onceFlags["depth_overcounts"] = true
    DetectionScanContext.guardLogger.warning(
        "trusted_proxy_depth selected an entry from the X-Forwarded-For " +
            "chain with $unlistedRightEntries entry/entries to its right that are not listed in " +
            "trusted_proxies; chain was " +
            LoggingUtils.sanitizeForLog(displayForwardedChain(forwardedFor)) +
            "; the declared depth over-counts the " +
            "real proxy hops. Set trusted_proxy_depth to the number of proxies " +
            "that append to X-Forwarded-For. This warning is logged once.",
    )
  }

  /** Port of `_resolve_client_ip_from_forwarded_chain` (ip_extraction.py:285). */
  private fun resolveClientIpFromForwardedChain(
      canonicalConnectingIp: String,
      forwardedFor: String?,
      proxyDepth: Int,
      trustedProxies: List<String>,
  ): String {
    try {
      if (forwardedFor.isNullOrEmpty()) return canonicalConnectingIp
      val ips = forwardedHeaderIps(forwardedFor)
      val chainLength = ips.size
      if (chainLength < proxyDepth) {
        warnForwardedHeaderChainTooShort(forwardedFor, chainLength)
        return canonicalConnectingIp
      }
      if (trustedProxies.isNotEmpty()) {
        val unlistedRightEntries =
            forwardedHeaderRightSideUnlistedCount(ips, proxyDepth, trustedProxies)
        if (unlistedRightEntries > 0) {
          warnForwardedHeaderDepthOvercountsHops(unlistedRightEntries, forwardedFor)
          val resolved = resolveForwardedChainRightToLeft(ips, trustedProxies)
          return resolved ?: canonicalConnectingIp
        }
      }
      val clientIp = extractFromForwardedHeader(forwardedFor, proxyDepth)
      if (clientIp != null) {
        if (isTrustedProxy(clientIp, trustedProxies)) {
          warnForwardedHeaderSelectedEntryTrustedProxy(clientIp)
        }
        return clientIp
      }
    } catch (e: Exception) {
      DetectionScanContext.guardLogger.log(Level.WARNING, "Error processing client IP: $e")
    }
    return canonicalConnectingIp
  }

  /** Port of `extract_client_ip` (ip_extraction.py:324-368). */
  public suspend fun extractClientIp(
      request: GuardRequest,
      config: com.guardcore.config.SecurityConfig,
      agentHandler: AgentHandlerProtocol? = null,
  ): String {
    val cachedIp = stateClientIp(request)
    if (!cachedIp.isNullOrEmpty()) return cachedIp

    val clientHost = request.clientHost
    if (clientHost == null) {
      if ("unix" in config.trustedProxies) {
        val forwardedFor = request.headers["X-Forwarded-For"]
        return resolveClientIpFromForwardedChain(
            UNKNOWN_CLIENT_IDENTITY,
            forwardedFor,
            config.trustedProxyDepth,
            config.trustedProxies,
        )
      }
      return UNKNOWN_CLIENT_IDENTITY
    }

    val connectingIp = clientHost
    val canonicalConnectingIp = canonicalizeIp(connectingIp)
    val forwardedFor = request.headers["X-Forwarded-For"]

    if (config.trustedProxies.isEmpty()) {
      warnForwardedHeaderPreempted(connectingIp, forwardedFor)
      return canonicalConnectingIp
    }

    val isTrusted = isTrustedProxy(connectingIp, config.trustedProxies)
    if (!isTrusted) {
      return handleUntrustedProxy(
          request,
          connectingIp,
          canonicalConnectingIp,
          forwardedFor,
          agentHandler,
      )
    }

    return resolveClientIpFromForwardedChain(
        canonicalConnectingIp,
        forwardedFor,
        config.trustedProxyDepth,
        config.trustedProxies,
    )
  }
}
