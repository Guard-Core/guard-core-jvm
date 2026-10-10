package com.guardcore.handlers

import com.guardcore.util.py.IpNetwork

/** Port of `guard_core/handlers/_cloud_provider_registry.py`. */

/** Python `_ALL_PROVIDERS` (_cloud_provider_registry.py:4). */
public val ALL_PROVIDERS: Set<String> =
    setOf("AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr")

/** Port of `_parse_cloud_selectors` (_cloud_provider_registry.py:7). */
public fun parseCloudSelectors(
    selectors: Set<String>,
): Pair<Set<String>, Map<String, MutableSet<String>>> {
  val blocked = linkedSetOf<String>()
  val carveouts = linkedMapOf<String, MutableSet<String>>()
  for (selector in selectors) {
    val provider = selector.substringBefore(":!")
    val region = selector.substringAfter(":!", "")
    blocked.add(provider)
    if (region.isNotEmpty() && selector.contains(":!")) {
      carveouts.getOrPut(provider) { linkedSetOf() }.add(region)
    }
  }
  return blocked to carveouts
}

/** Port of `_bare_provider_names` (_cloud_provider_registry.py:20). */
public fun bareProviderNames(providers: Collection<String>): Set<String> =
    providers.map { it.substringBefore(":!") }.toSet()

/** Port of `_encode_cached` (_cloud_provider_registry.py:24): "net|region" or "net". */
public fun encodeCached(
    ranges: Set<IpNetwork>,
    regions: Map<String, String>,
): Set<String> {
  val encoded = linkedSetOf<String>()
  for (network in ranges) {
    val key = network.text
    val region = regions[key]
    encoded.add(if (region != null) "$key|$region" else key)
  }
  return encoded
}

/** Port of `_decode_cached` (_cloud_provider_registry.py:36). */
public fun decodeCached(
    entries: Set<String>,
): Pair<Set<IpNetwork>, Map<String, String>> {
  val networks = linkedSetOf<IpNetwork>()
  val regions = linkedMapOf<String, String>()
  for (entry in entries) {
    val prefix = entry.substringBefore("|")
    val separator = if (entry.contains("|")) "|" else ""
    val region = entry.substringAfter("|", "")
    val network = IpNetwork.parse(prefix)
    networks.add(network)
    if (separator.isNotEmpty() && region.isNotEmpty()) {
      regions[network.text] = region
    }
  }
  return networks to regions
}
