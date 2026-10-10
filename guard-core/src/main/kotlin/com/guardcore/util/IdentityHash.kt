package com.guardcore.util

import java.security.MessageDigest

/**
 * Port of `guard_core/_utils/identity_hash.py` (guard_core/_utils/identity_hash.py:4): SHA-256 hex
 * digest of the utf-8 encoding of the value.
 */
public object IdentityHash {
  /** Port of `_hash_identity_segment`. */
  public fun hashIdentitySegment(value: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
    return digest.joinToString("") { "%02x".format(it) }
  }
}
