package com.guardcore.errors

/**
 * Root of the guard-core error hierarchy.
 *
 * Port of `guard_core/exceptions.py` GuardCoreError (guard_core/exceptions.py:1).
 */
public open class GuardCoreError(message: String) : RuntimeException(message)

/**
 * Port of `guard_core/exceptions.py` GuardRedisError (guard_core/exceptions.py:5). Carries the HTTP
 * status code and detail the Python version attaches.
 */
public class GuardRedisError(
    public val statusCode: Int,
    public val detail: String,
) : GuardCoreError(detail)

/**
 * Port of `guard_core/exceptions.py` AgentPackageNotInstalledError (guard_core/exceptions.py:12).
 */
public class AgentPackageNotInstalledError(message: String) : GuardCoreError(message)

/**
 * Port of the Python `ValueError` raised inside SecurityConfig field and model validators. Pydantic
 * wraps those ValueError instances into ValidationError at construction time; the JVM port surfaces
 * the same rejection as this error type carrying the identical message.
 */
public open class ConfigValidationError(message: String) : GuardCoreError(message)

/**
 * Port of Python's `RecursionError` where the guard-core code catches it around JSON parsing
 * (guard_core/_utils/embedded_json_scan.py:17, guard_core/_utils/request_logging.py:78).
 */
public class PyRecursionError(message: String) : ConfigValidationError(message)
