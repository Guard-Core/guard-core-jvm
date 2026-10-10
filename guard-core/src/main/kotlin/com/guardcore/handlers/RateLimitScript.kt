package com.guardcore.handlers

/**
 * Port of `guard_core/scripts/rate_lua.py` (RATE_LIMIT_SCRIPT): byte-exact Lua for the sliding
 * window rate limiter. Loaded once via SCRIPT LOAD and reloaded on NOSCRIPT.
 */
public const val RATE_LIMIT_SCRIPT: String =
    """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_start = now - window

redis.call('ZADD', key, now, now)

redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

local count = redis.call('ZCARD', key)

redis.call('EXPIRE', key, window * 2)

return count
"""
