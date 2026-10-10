package com.guardcore.util.py

import com.guardcore.errors.ConfigValidationError

/**
 * Port of the `ipaddress` module surface guard-core uses: `ip_address`, `ip_network(...,
 * strict=False)`, prefix length, network containment, and the `is_loopback` / `is_private` /
 * `is_link_local` / `ipv4_mapped` properties. Semantics verified against CPython 3.10 (the
 * reference interpreter).
 *
 * Addresses are stored as unsigned values: IPv4 in the low 32 bits of a Long, IPv6 as a 128-bit
 * high/low Long pair plus an optional scope id (zone).
 */
public sealed class IpAddress {
  /** `str(addr)` exactly as Python renders it. */
  public abstract val text: String

  public abstract val isLoopback: Boolean

  public abstract val isPrivate: Boolean

  public abstract val isLinkLocal: Boolean

  public abstract val version: Int

  public override fun toString(): String = text
}

public class IPv4Address
internal constructor(
    /** Unsigned 32-bit value in the low bits. */
    public val value: Long,
) : IpAddress() {
  public override val version: Int
    get() = 4

  public override val text: String =
      "${(value ushr 24) and 0xFF}.${(value ushr 16) and 0xFF}.${(value ushr 8) and 0xFF}.${value and 0xFF}"

  public override val isLoopback: Boolean
    get() = (value ushr 24) == 127L

  // CPython 3.10 IPv4Address._constants._private_networks (verbatim).
  public override val isPrivate: Boolean
    get() = V4_PRIVATE_NETWORKS.any { (net, prefix) -> (value xor net) and v4Mask(prefix) == 0L }

  public override val isLinkLocal: Boolean
    get() = (value xor 0xA9FE0000L) and v4Mask(16) == 0L

  public companion object {
    internal val V4_PRIVATE_NETWORKS: List<Pair<Long, Int>> by lazy {
      listOf(
              "0.0.0.0/8",
              "10.0.0.0/8",
              "127.0.0.0/8",
              "169.254.0.0/16",
              "172.16.0.0/12",
              "192.0.0.0/29",
              "192.0.0.170/31",
              "192.0.0.171/31",
              "192.0.2.0/24",
              "192.168.0.0/16",
              "198.18.0.0/15",
              "198.51.100.0/24",
              "203.0.113.0/24",
              "240.0.0.0/4",
              "255.255.255.255/32",
          )
          .map { parseV4NetworkValue(it) }
    }

    internal fun parseV4NetworkValue(cidr: String): Pair<Long, Int> {
      val slash = cidr.indexOf('/')
      val addr = parseV4OrThrow(cidr.substring(0, slash)).value
      val prefix = cidr.substring(slash + 1).toInt()
      return (addr and v4Mask(prefix)) to prefix
    }
  }
}

public class IPv6Address
internal constructor(
    public val high: Long,
    public val low: Long,
    public val scopeId: String?,
) : IpAddress() {
  public override val version: Int
    get() = 6

  public override val isLoopback: Boolean
    get() = high == 0L && low == 1L && scopeId == null

  // CPython 3.10 IPv6Address._constants._private_networks (verbatim).
  public override val isPrivate: Boolean
    get() = V6_PRIVATE_NETWORKS.any { (nh, nl, p) -> v6Matches(high, low, nh, nl, p) }

  public override val isLinkLocal: Boolean
    get() = v6Matches(high, low, 0xFE80L shl 48, 0L, 10)

  /** Port of `IPv6Address.ipv4_mapped` (None unless bits 32-127 are 0xffff). */
  public val ipv4Mapped: IPv4Address?
    get() =
        if (high == 0L && (low ushr 32) == 0xFFFFL) {
          IPv4Address(low and 0xFFFFFFFFL)
        } else {
          null
        }

  public override val text: String
    get() {
      val mapped = ipv4Mapped
      val body =
          if (mapped != null) {
            // Python _ipv4_mapped_ipv6_to_str: the high 96 bits of a
            // v4-mapped address always compress to "::ffff".
            "::ffff:" + mapped.text
          } else {
            compressHextets128(high, low)
          }
      return if (scopeId != null) "$body%$scopeId" else body
    }

  public companion object {
    internal val V6_PRIVATE_NETWORKS: List<Triple<Long, Long, Int>> by lazy {
      listOf(
              "::1/128",
              "::/128",
              "::ffff:0.0.0.0/96",
              "64:ff9b:1::/48",
              "100::/64",
              "2001::/23",
              "2001:db8::/32",
              "2002::/16",
              "3fff::/20",
              "fc00::/7",
              "fe80::/10",
          )
          .map { parseV6NetworkValue(it) }
    }

    internal fun parseV6NetworkValue(cidr: String): Triple<Long, Long, Int> {
      val slash = cidr.indexOf('/')
      val addr = parseV6OrThrow(cidr.substring(0, slash))
      val prefix = cidr.substring(slash + 1).toInt()
      val (nh, nl) = v6MaskAddress(addr.high, addr.low, prefix)
      return Triple(nh, nl, prefix)
    }

    /** Port of CPython `_BaseV6._compress_hextets` over rendered hextets. */
    internal fun compressHextets(hextets: List<String>): String {
      val result = hextets.toMutableList()
      var bestStart = -1
      var bestLen = 0
      var curStart = -1
      var curLen = 0
      for ((index, hextet) in result.withIndex()) {
        if (hextet == "0") {
          curLen++
          if (curStart == -1) curStart = index
          if (curLen > bestLen) {
            bestLen = curLen
            bestStart = curStart
          }
        } else {
          curLen = 0
          curStart = -1
        }
      }
      if (bestLen > 1) {
        val bestEnd = bestStart + bestLen
        if (bestEnd == result.size) result.add("")
        result.subList(bestStart, bestEnd).clear()
        result.add(bestStart, "")
        if (bestStart == 0) result.add(0, "")
      }
      return result.joinToString(":")
    }

    internal fun compressHextets128(high: Long, low: Long): String {
      val hextets = ArrayList<String>(8)
      for (shift in 48 downTo 0 step 16) {
        hextets.add(java.lang.Long.toHexString((high ushr shift) and 0xFFFF))
      }
      for (shift in 48 downTo 0 step 16) {
        hextets.add(java.lang.Long.toHexString((low ushr shift) and 0xFFFF))
      }
      return compressHextets(hextets)
    }
  }
}

internal fun v4Mask(prefixLen: Int): Long =
    when {
      prefixLen <= 0 -> 0L
      prefixLen >= 32 -> -1L
      else -> ((1L shl prefixLen) - 1) shl (32 - prefixLen)
    }

internal fun v6MaskHigh(prefixLen: Int): Long =
    when {
      prefixLen <= 0 -> 0L
      prefixLen >= 64 -> -1L
      else -> (-1L) shl (64 - prefixLen)
    }

internal fun v6MaskLow(prefixLen: Int): Long =
    if (prefixLen <= 64) 0L else (-1L) shl (128 - prefixLen)

internal fun v6Matches(
    high: Long,
    low: Long,
    netHigh: Long,
    netLow: Long,
    prefixLen: Int,
): Boolean =
    (high xor netHigh) and v6MaskHigh(prefixLen) == 0L &&
        (low xor netLow) and v6MaskLow(prefixLen) == 0L

internal fun v6MaskAddress(high: Long, low: Long, prefixLen: Int): Pair<Long, Long> =
    (high and v6MaskHigh(prefixLen)) to (low and v6MaskLow(prefixLen))

/**
 * Port of `ipaddress.ip_network(address, strict=False)`: a network address and prefix length with
 * containment checks.
 */
public class IpNetwork
private constructor(
    public val networkHigh: Long,
    public val networkLow: Long,
    public val prefixLen: Int,
    public val version: Int,
) {
  /** `(ip in network)` per Python's `__contains__`. */
  public fun contains(addr: IpAddress): Boolean {
    if (addr.version != version) return false
    return when (addr) {
      is IPv4Address -> (addr.value xor networkLow) and v4Mask(prefixLen) == 0L
      is IPv6Address -> v6Matches(addr.high, addr.low, networkHigh, networkLow, prefixLen)
    }
  }

  /** `str(network)` exactly as Python renders it. */
  public val text: String
    get() {
      val body =
          when (version) {
            4 -> IPv4Address(networkLow).text
            else -> {
              val mapped =
                  if (networkHigh == 0L && (networkLow ushr 32) == 0xFFFFL) {
                    "::ffff:" + IPv4Address(networkLow and 0xFFFFFFFFL).text
                  } else {
                    IPv6Address.compressHextets128(networkHigh, networkLow)
                  }
              mapped
            }
          }
      return "$body/$prefixLen"
    }

  public override fun toString(): String = text

  public companion object {
    /** Port of `ip_network(entry, strict=False)` (host bits are masked off). */
    public fun parse(entry: String): IpNetwork {
      val slash = entry.indexOf('/')
      if (slash == -1) {
        return when (val addr = parseAddress(entry)) {
          is IPv4Address -> IpNetwork(0L, addr.value, 32, 4)
          is IPv6Address -> IpNetwork(addr.high, addr.low, 128, 6)
        }
      }
      val addrPart = entry.substring(0, slash)
      val lenPart = entry.substring(slash + 1)
      val addr = parseAddress(addrPart)
      val prefix =
          lenPart.toIntOrNull() ?: throw ConfigValidationError("Invalid prefix length in '$entry'")
      val maxPrefix = if (addr is IPv4Address) 32 else 128
      if (prefix < 0 || prefix > maxPrefix) {
        throw ConfigValidationError("Prefix length $prefix out of range in '$entry'")
      }
      return when (addr) {
        is IPv4Address -> IpNetwork(0L, addr.value and v4Mask(prefix), prefix, 4)
        is IPv6Address -> {
          val (nh, nl) = v6MaskAddress(addr.high, addr.low, prefix)
          IpNetwork(nh, nl, prefix, 6)
        }
      }
    }
  }
}

/** Port of `ipaddress.ip_address` (tries IPv4 then IPv6, then ValueError). */
public fun parseAddress(text: String): IpAddress {
  try {
    return parseV4OrThrow(text)
  } catch (_: ConfigValidationError) {
    // fall through to IPv6, mirroring ip_address()
  }
  try {
    return parseV6OrThrow(text)
  } catch (_: ConfigValidationError) {
    // fall through to the generic ValueError, mirroring ip_address()
  }
  throw ConfigValidationError(
      "'" + text + "' does not appear to be an IPv4 or IPv6 address",
  )
}

internal fun parseV4OrThrow(text: String): IPv4Address {
  if (text.isEmpty()) throw ConfigValidationError("Address cannot be empty")
  if (text.length > 15) throw ConfigValidationError("At most 15 characters permitted in '$text'")
  val octets = text.split(".")
  if (octets.size != 4) {
    throw ConfigValidationError("Expected 4 octets in '$text'")
  }
  var value = 0L
  for (octet in octets) {
    if (octet.isEmpty() || octet.length > 3) {
      throw ConfigValidationError("At most 3 characters permitted in '$text'")
    }
    var partValue = 0
    for (c in octet) {
      if (c !in '0'..'9') {
        throw ConfigValidationError("Only decimal digits permitted in '$text'")
      }
      partValue = partValue * 10 + (c - '0')
    }
    if (octet.length > 1 && octet[0] == '0') {
      throw ConfigValidationError("Leading zeros are not permitted in '$text'")
    }
    if (partValue > 255) {
      throw ConfigValidationError("Octet $partValue (> 255) not permitted in '$text'")
    }
    value = (value shl 8) or partValue.toLong()
  }
  return IPv4Address(value)
}

internal fun parseV6OrThrow(rawText: String): IPv6Address {
  // Scope id (zone) split, mirroring IPv6Address.__init__.
  var text = rawText
  var scopeId: String? = null
  val percent = text.indexOf('%')
  if (percent != -1) {
    val zone = text.substring(percent + 1)
    scopeId = zone.ifEmpty { null }
    text = text.substring(0, percent)
  }
  if (text.isEmpty()) throw ConfigValidationError("Address cannot be empty")
  if (text.length > 45) throw ConfigValidationError("At most 45 characters expected in '$text'")

  val maxParts = 9
  val parts = text.split(":", limit = maxParts)
  if (parts.size < 3) {
    throw ConfigValidationError("At least 3 parts expected in '$rawText'")
  }
  val mutableParts = parts.toMutableList()
  // IPv4-style suffix conversion.
  if ('.' in mutableParts.last()) {
    val v4 =
        try {
          parseV4OrThrow(mutableParts.removeAt(mutableParts.size - 1))
        } catch (e: ConfigValidationError) {
          throw ConfigValidationError("${e.message} in '$rawText'")
        }
    mutableParts.add(java.lang.Long.toHexString((v4.value ushr 16) and 0xFFFF))
    mutableParts.add(java.lang.Long.toHexString(v4.value and 0xFFFF))
  }
  if (mutableParts.size > maxParts) {
    throw ConfigValidationError("At most 8 colons permitted in '$rawText'")
  }
  // Locate the single '::' (empty part between others).
  var skipIndex = -1
  for (i in 1 until mutableParts.size - 1) {
    if (mutableParts[i].isEmpty()) {
      if (skipIndex != -1) {
        throw ConfigValidationError("At most one '::' permitted in '$rawText'")
      }
      skipIndex = i
    }
  }
  var partsHi: Int
  var partsLo: Int
  val partsSkipped: Int
  if (skipIndex != -1) {
    partsHi = skipIndex
    partsLo = mutableParts.size - skipIndex - 1
    if (mutableParts[0].isEmpty()) {
      partsHi -= 1
      if (partsHi != 0) {
        throw ConfigValidationError("Leading ':' only permitted as part of '::' in '$rawText'")
      }
    }
    if (mutableParts.last().isEmpty()) {
      partsLo -= 1
      if (partsLo != 0) {
        throw ConfigValidationError("Trailing ':' only permitted as part of '::' in '$rawText'")
      }
    }
    partsSkipped = 8 - (partsHi + partsLo)
    if (partsSkipped < 1) {
      throw ConfigValidationError("Expected at most 8 other parts with '::' in '$rawText'")
    }
  } else {
    partsHi = mutableParts.size
    partsLo = 0
    if (mutableParts.size != 8) {
      throw ConfigValidationError("Exactly 8 parts expected without '::' in '$rawText'")
    }
    if (mutableParts[0].isEmpty()) {
      throw ConfigValidationError("Leading ':' only permitted as part of '::' in '$rawText'")
    }
    if (mutableParts.last().isEmpty()) {
      throw ConfigValidationError("Trailing ':' only permitted as part of '::' in '$rawText'")
    }
    partsSkipped = 0
  }

  fun parseHextet(part: String): Int {
    if (part.isEmpty() || part.length > 4) {
      throw ConfigValidationError("Expected 1 to 4 hex digits in '$part' in '$rawText'")
    }
    var v = 0
    for (c in part) {
      val d = Character.digit(c, 16)
      if (d < 0) {
        throw ConfigValidationError("Only hex digits permitted in '$part' in '$rawText'")
      }
      v = (v shl 4) or d
    }
    return v
  }

  val hextets = LongArray(8)
  for (i in 0 until partsHi) {
    hextets[i] = parseHextet(mutableParts[i]).toLong()
  }
  for (i in 0 until partsLo) {
    hextets[8 - partsLo + i] = parseHextet(mutableParts[mutableParts.size - partsLo + i]).toLong()
  }
  var high = 0L
  var low = 0L
  for (i in 0 until 8) {
    if (i < 4) high = (high shl 16) or hextets[i] else low = (low shl 16) or hextets[i]
  }
  return IPv6Address(high, low, scopeId)
}
