package com.guardcore.protocols

/**
 * Port of `guard_core/protocols/__init__.py` (protocols/__init__.py:1-21): the protocol package's
 * public re-exports. Kotlin imports replace the Python re-export surface; this file documents the
 * mapping.
 *
 * Re-exported names and their Kotlin homes:
 * - AgentHandlerProtocol -> AgentProtocol.kt
 * - BoundedBodyReader, GuardRequest -> RequestProtocol.kt
 * - BoundedResponseBodyReader, GuardResponse, GuardResponseFactory -> ResponseProtocol.kt
 * - GeoIPHandler -> GeoIpProtocol.kt
 * - GuardMiddlewareProtocol -> MiddlewareProtocol.kt
 * - RedisHandlerProtocol -> RedisProtocol.kt
 */
public object Protocols
