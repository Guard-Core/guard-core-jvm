package com.guardcore.config

import com.guardcore.protocols.GeoIPHandler

/**
 * W1 seams for config behaviors whose implementing modules land in later waves. Each seam is a
 * function reference registered by the owning wave; until then the config layer behaves exactly as
 * documented in docs/w1-config-parity.md and tracks the closure in KNOWN_GAPS.md.
 */
public object ConfigSeams {
  /**
   * ReDoS gate for blocked_user_agents patterns
   * (guard_core/_security_config_field_validators.py:324-340). The W2 detection engine registers
   * the PatternCompiler-backed gate here. Receives the pattern list; throws ConfigValidationError
   * on rejection.
   */
  public var blockedUserAgentsPatternGate: ((List<String>) -> Unit)? = null

  /**
   * Geo-IP handler construction (guard_core/_security_config_geo_validators.py:86-92). The W3
   * handlers wave registers the IPInfoManager-backed factory here. Receives (token, dbPath, maxAge)
   * and returns the handler.
   */
  public var geoIpHandlerFactory:
      ((token: String, dbPath: java.nio.file.Path?, maxAge: Int) -> GeoIPHandler)? =
      null

  /**
   * Guard Agent AgentConfig construction for `to_agent_config` (guard_core/models.py:317-365). The
   * guard-agent-jvm integration (W7) registers the factory. Receives the same keyword mapping the
   * Python builds and returns the constructed agent config object.
   */
  public var agentConfigFactory: ((Map<String, Any?>) -> Any?)? = null
}
