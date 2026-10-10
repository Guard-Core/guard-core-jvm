package com.guardcore.config

/**
 * Port of the detection category constants the config layer validates against.
 *
 * Provenance: `ALL_DETECTION_CATEGORIES` is defined at
 * guard_core/handlers/_suspatterns_sources.py:89 and re-exported through
 * guard_core/handlers/suspatterns_handler.py:328. The W1 facade ports the constant (it is config
 * validation data); the W2 engine module owns the pattern engine that consumes it.
 */
public object DetectionCategories {
  /** Verbatim value set of `ALL_DETECTION_CATEGORIES` (_suspatterns_sources.py:89-110). */
  public val ALL_DETECTION_CATEGORIES: Set<String> =
      setOf(
          "xss",
          "sqli",
          "dir_traversal",
          "path_traversal",
          "cmd_injection",
          "file_inclusion",
          "ldap",
          "xml",
          "ssrf",
          "nosql",
          "file_upload",
          "template",
          "http_split",
          "sensitive_file",
          "cms_probing",
          "recon",
          "proto_pollution",
          "code_injection",
          "deserialization",
      )

  /** Port of `THREAT_BAN_CONFIG_CATEGORIES` (_security_config_field_validators.py:84). */
  public val THREAT_BAN_CONFIG_CATEGORIES: Set<String> =
      ALL_DETECTION_CATEGORIES + setOf("rate_limit")
}

/**
 * Port of `CloudProvider` / `VALID_CLOUD_PROVIDERS` (_security_config_field_validators.py:37-38).
 */
public object CloudProviders {
  public const val AWS: String = "AWS"
  public const val GCP: String = "GCP"
  public const val AZURE: String = "Azure"
  public const val DIGITAL_OCEAN: String = "DigitalOcean"
  public const val LINODE: String = "Linode"
  public const val VULTR: String = "Vultr"

  /** Verbatim `VALID_CLOUD_PROVIDERS` frozenset. */
  public val VALID_CLOUD_PROVIDERS: Set<String> =
      setOf(AWS, GCP, AZURE, DIGITAL_OCEAN, LINODE, VULTR)
}
