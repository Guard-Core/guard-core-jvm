package com.guardcore.util

import com.guardcore.config.ConfigValidators
import com.guardcore.util.py.IpNetwork
import com.guardcore.util.py.parseAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Ports of tests/test_utils/test_ip_identity_canonicalization.py (canonical form table) and the
 * CPython ipaddress probes backing PyIp.kt.
 */
class PyIpTest {
  // SIX_RAW_FORMS / CANONICAL_BY_RAW_FORM
  // (tests/test_utils/test_ip_identity_canonicalization.py:14-27).
  private val rawForms =
      mapOf(
          "2001:db8::1" to "2001:db8::1",
          "2001:0db8::1" to "2001:db8::1",
          "2001:DB8::1" to "2001:db8::1",
          "2001:db8:0:0:0:0:0:1" to "2001:db8::1",
          "::ffff:1.2.3.4" to "1.2.3.4",
          "1.2.3.4" to "1.2.3.4",
      )

  @Test
  fun testCanonicalizeIpSixForms() {
    for ((raw, canonical) in rawForms) {
      assertEquals(canonical, IpExtraction.canonicalizeIp(raw), "raw=$raw")
    }
  }

  @Test
  fun testCanonicalizeIpBracketsAndPort() {
    assertEquals("2001:db8::1", IpExtraction.stripIpBrackets("[2001:db8::1]"))
    assertEquals("1.2.3.4", IpExtraction.stripForwardedEntryPort("1.2.3.4:8080"))
    assertEquals("2001:db8::1", IpExtraction.stripForwardedEntryPort("[2001:db8::1]:443"))
    assertEquals("[2001:db8::1]x", IpExtraction.stripForwardedEntryPort("[2001:db8::1]x"))
    assertEquals("1.2.3.4:80x", IpExtraction.stripForwardedEntryPort("1.2.3.4:80x"))
  }

  @Test
  fun testCanonicalizeIpInvalidPassthrough() {
    assertEquals("unix", IpExtraction.canonicalizeIp("unix"))
    assertEquals("not-an-ip", IpExtraction.canonicalizeIp("not-an-ip"))
  }

  @Test
  fun testZoneIdentifierStaysDistinct() {
    // test_zone_identifier_link_local_stays_distinct_by_design
    // (test_ip_identity_canonicalization.py:80): a scoped address keeps
    // its zone in the canonical text and is not v4-mapped.
    val addr = parseAddress("fe80::1%eth0") as com.guardcore.util.py.IPv6Address
    assertEquals("fe80::1%eth0", addr.text)
    assertEquals("eth0", addr.scopeId)
  }

  @Test
  fun testNetworkParseAndContains() {
    val net = IpNetwork.parse("1.2.3.4/24")
    assertEquals("1.2.3.0/24", net.text)
    assertEquals(24, net.prefixLen)
    assertTrue(net.contains(parseAddress("1.2.3.200")))
    assertFalse(net.contains(parseAddress("1.2.4.1")))
    val bare = IpNetwork.parse("1.2.3.4")
    assertEquals("1.2.3.4/32", bare.text)
    assertTrue(bare.contains(parseAddress("1.2.3.4")))
  }

  @Test
  fun testIpv6NetworkCanonicalization() {
    assertEquals("::/0", IpNetwork.parse("::/0").text)
    assertEquals(
        "::ffff:1.2.3.0/120",
        IpNetwork.parse("::ffff:1.2.3.4/120").text,
    )
    assertTrue(IpNetwork.parse("::/0").contains(parseAddress("2001:db8::1")))
  }

  @Test
  fun testPrefixZeroDetection() {
    assertTrue(ConfigValidators.isPrefixZeroNetworkEntry("0.0.0.0/0"))
    assertTrue(ConfigValidators.isPrefixZeroNetworkEntry("::/0"))
    assertFalse(ConfigValidators.isPrefixZeroNetworkEntry("10.0.0.0/8"))
    assertFalse(ConfigValidators.isPrefixZeroNetworkEntry("not-an-ip"))
  }

  @Test
  fun testAddressClassification() {
    val loopback = parseAddress("127.0.0.1")
    assertTrue(loopback.isLoopback)
    assertTrue(parseAddress("::1").isLoopback)
    assertTrue(parseAddress("169.254.1.1").isLinkLocal)
    assertTrue(parseAddress("fe80::1").isLinkLocal)
    assertTrue(parseAddress("192.168.1.1").isPrivate)
    assertFalse(parseAddress("8.8.8.8").isPrivate)
    assertTrue(parseAddress("2001:db8::1").isPrivate)
    assertTrue(parseAddress("0.0.0.0").isPrivate)
    assertTrue(parseAddress("255.255.255.255").isPrivate)
    assertFalse(parseAddress("192.0.0.10").isPrivate)
    assertTrue(parseAddress("192.0.0.1").isPrivate)
  }

  @Test
  fun testRejectedAddresses() {
    val rejects =
        listOf(
            "01.2.3.4",
            "1.2.3.4/32",
            "256.1.1.1",
            "1.2.3",
            "unix",
            "",
            "1.2.3.4.5",
            "::::",
            "1:2:3:4:5:6:7:8:9",
            "1::2::3",
            "1.2.3.4:",
        )
    for (bad in rejects) {
      try {
        parseAddress(bad)
        throw AssertionError("expected rejection: '$bad'")
      } catch (_: com.guardcore.errors.ConfigValidationError) {
        // expected
      }
    }
  }
}
