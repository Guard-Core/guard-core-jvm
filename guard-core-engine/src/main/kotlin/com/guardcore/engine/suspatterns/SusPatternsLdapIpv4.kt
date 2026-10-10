package com.guardcore.engine.suspatterns

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.PyReMatch
import com.guardcore.engine.py.PyRePattern

/**
 * Log4Shell pattern, legacy IPv4 host decoding, and the LDAP filter break-out validators.
 *
 * Port of guard_core/handlers/_suspatterns_ldap_ipv4.py.
 */
public const val LOG4SHELL_JNDI_LOOKUP_RE: String =
    "(?i)\\$\\{(?:jndi:(?:ldap|rmi|dns)://" + "|\\$?\\{?(?:lower|upper):j\\}ndi" + "|::-j\\}ndi)"

public val ALWAYS_SCAN_HEADER_PATTERNS: Set<PyRePattern> =
    setOf(PyRe.compile(LOG4SHELL_JNDI_LOOKUP_RE, 0))

private const val LEGACY_IPV4_PART_RE: String = "(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\\d*|0)"

public const val LEGACY_IPV4_HOST_RE: String =
    "://(?:[^/@\\s]*@)?(" +
        LEGACY_IPV4_PART_RE +
        "(?:\\." +
        LEGACY_IPV4_PART_RE +
        "){0,3})(?=[:/\\s]|\$)"

public class IPv4Network(private val base: Long, private val prefix: Int) {
  private val mask: Long = (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL

  public fun contains(address: Long): Boolean = (address and mask) == (base and mask)
}

public val LEGACY_IPV4_BLOCKED_NETWORKS: List<IPv4Network> =
    listOf(
        IPv4Network(0x00000000L, 8),
        IPv4Network(0x7F000000L, 8),
        IPv4Network(0x0A000000L, 8),
        IPv4Network(0xAC100000L, 12),
        IPv4Network(0xC0A80000L, 16),
        IPv4Network(0xA9FE0000L, 16),
        IPv4Network(0x646464C8L, 32),
    )

/** _decode_legacy_ipv4_part. */
public fun decodeLegacyIpv4Part(part: String): Long? {
  if (part.startsWith("0x") || part.startsWith("0X")) {
    val digits = part.substring(2)
    return if (digits.isEmpty()) null else digits.toLongOrNull(16)
  }
  if (part.startsWith("0") && part.length > 1) {
    val digits = part.substring(1)
    return if (digits.all { it in '0'..'7' }) digits.toLongOrNull(8) else null
  }
  return if (part.all { it in '0'..'9' }) part.toLongOrNull(10) else null
}

private const val MIN_BARE_DECIMAL_LEGACY_IPV4: Long = 1L shl 24

private fun isBareDecimalLegacyIpv4Part(part: String): Boolean = part == "0" || part[0] != '0'

private fun isAmbiguousBareDecimalPort(parts: List<String>, decoded: List<Long>): Boolean {
  if (decoded.size != 1 || decoded[0] == 0L) return false
  val isSmallValue = decoded[0] < MIN_BARE_DECIMAL_LEGACY_IPV4
  val isBareDecimal = isBareDecimalLegacyIpv4Part(parts[0])
  return isSmallValue && isBareDecimal
}

/** _decode_legacy_ipv4_host. */
public fun decodeLegacyIpv4Host(host: String): Long? {
  val parts = host.split(".")
  if (parts.size !in 1..4) return null
  val decoded = ArrayList<Long>(parts.size)
  for (part in parts) {
    val value = decodeLegacyIpv4Part(part) ?: return null
    decoded.add(value)
  }
  if (isAmbiguousBareDecimalPort(parts, decoded)) return null
  for (value in decoded.dropLast(1)) {
    if (value > 255) return null
  }
  val remainingBits = 8 * (5 - decoded.size)
  if (decoded.last() >= (1L shl remainingBits)) return null
  var result = 0L
  for (value in decoded.dropLast(1)) {
    result = (result shl 8) or value
  }
  return (result shl remainingBits) or decoded.last()
}

/** _is_blocked_legacy_ipv4. */
public fun isBlockedLegacyIpv4(ipInt: Long): Boolean = LEGACY_IPV4_BLOCKED_NETWORKS.any {
  it.contains(ipInt)
}

/** _legacy_ipv4_match_is_blocked. */
public fun legacyIpv4MatchIsBlocked(match: PyReMatch): Boolean {
  val ipInt = decodeLegacyIpv4Host(match.group(1)) ?: return false
  return isBlockedLegacyIpv4(ipInt)
}

/** _ldap_breakout_backward_window: (window, depth, depth_unresolved). */
public fun ldapBreakoutBackwardWindow(
    text: String,
    closeParenPos: Int,
): Triple<String, Int, Boolean> {
  var depth = 0
  val backwardStart = maxOf(0, closeParenPos - LDAP_BREAKOUT_LOCAL_SCAN_CHARS)
  var position = closeParenPos - 1
  while (position >= backwardStart && text[position] !in LDAP_BREAKOUT_BACKWARD_BOUNDARY_CHARS) {
    when (text[position]) {
      ')' -> depth -= 1
      '(' -> depth += 1
    }
    position -= 1
  }
  val backwardWindow = text.substring(position + 1, closeParenPos)
  val depthUnresolved = backwardStart > 0 && position < backwardStart
  return Triple(backwardWindow, depth, depthUnresolved)
}

/** _ldap_next_candidate_scan_limit. */
public fun ldapNextCandidateScanLimit(match: PyReMatch, after: Int): Int {
  val nextMatch = matchNext(match, after)
  return nextMatch?.charEnd() ?: match.subject().length
}

private fun matchNext(match: PyReMatch, after: Int): PyReMatch? {
  // python match.re.search(string, after): re-run the same pattern from a position.
  // The compiled pattern object is not carried on PyReMatch; callers pass the pattern
  // through the windowed finders instead, so this helper uses the pattern from the match's
  // pattern field.
  val pattern = match.pattern ?: return null
  return pattern.search(match.subject(), after, Long.MAX_VALUE)
}

/** _ldap_filter_expression_forward_extent. */
public fun ldapFilterExpressionForwardExtent(text: String, start: Int, scanLimit: Int): Int {
  var position = start
  var depth = 0
  while (true) {
    val boundary =
        LDAP_FILTER_EXPRESSION_STRUCTURE_RE.search(text, position, scanLimit, Long.MAX_VALUE)
            ?: return scanLimit
    val char = boundary.group()
    if (char[0] in LDAP_BREAKOUT_FORWARD_BOUNDARY_CHARS) return boundary.charStart()
    when (char[0]) {
      '(' -> depth += 1
      else -> if (depth == 0) return boundary.charStart() else depth -= 1
    }
    position = boundary.charEnd()
  }
}

/** _ldap_breakout_forward_window. */
public fun ldapBreakoutForwardWindow(match: PyReMatch, closeParenPos: Int): String {
  val text = match.subject()
  val scanLimit = ldapNextCandidateScanLimit(match, match.charEnd())
  val extent = ldapFilterExpressionForwardExtent(text, closeParenPos + 1, scanLimit)
  return text.substring(closeParenPos, extent)
}

/** _ldap_wildcard_chain_is_injection. */
public fun ldapWildcardChainIsInjection(match: PyReMatch): Boolean {
  val text = match.subject()
  val groupText = match.group()
  val closeParenPos = match.charStart() + groupText.indexOf(')')

  val (backwardWindow, depth, depthUnresolved) = ldapBreakoutBackwardWindow(text, closeParenPos)
  val forwardWindow = ldapBreakoutForwardWindow(match, closeParenPos)

  val wildcardAdjacent = groupText.startsWith("*")
  val depthProvesBreakout = depth <= 0 && (wildcardAdjacent || !depthUnresolved)
  val depthOrWildcardClause =
      depthProvesBreakout ||
          LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE.search(backwardWindow, 0, Long.MAX_VALUE) != null
  if (!depthOrWildcardClause) return false
  return LDAP_BREAKOUT_ATTACK_TOKEN_RE.search(backwardWindow, 0, Long.MAX_VALUE) != null ||
      LDAP_BREAKOUT_ATTACK_TOKEN_RE.search(forwardWindow, 0, Long.MAX_VALUE) != null
}

/** _ldap_paren_conjunction_is_injection. */
public fun ldapParenConjunctionIsInjection(match: PyReMatch): Boolean {
  val text = match.subject()
  val scanLimit = ldapNextCandidateScanLimit(match, match.charEnd())
  val tailEnd = ldapFilterExpressionForwardExtent(text, match.charEnd(), scanLimit)
  val tail = text.substring(match.charEnd(), tailEnd)
  if (
      LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE.matchAt(tail, 0, tail.length, Long.MAX_VALUE) !=
          null
  ) {
    return true
  }
  if (!tail.contains('=')) return false
  return LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE.matchAt(tail, 0, tail.length, Long.MAX_VALUE) !=
      null
}
