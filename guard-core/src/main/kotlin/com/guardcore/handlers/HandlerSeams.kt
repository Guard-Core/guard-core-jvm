package com.guardcore.handlers

import com.guardcore.config.ConfigSeams
import com.guardcore.util.AccessControl

/**
 * W3 seam registration: closes the W1 gaps whose implementing handlers landed in this wave
 * (KNOWN_GAPS.md G-2 and G-6). Python resolves these lazily at validation time
 * (_security_config_geo_validators.py:69-94 imports IPInfoManager inside the validator;
 * access_control.py:197-215 resolves the cloud manager through the middleware); the JVM facade
 * wires the same implementations through [register], called from the facade entry point and the
 * handler tests.
 */
public object HandlerSeams {
  @Volatile private var registered: Boolean = false

  /** Idempotent registration of the W3-backed config and access-control seams. */
  public fun register() {
    if (registered) {
      return
    }
    synchronized(this) {
      if (registered) {
        return
      }
      // G-2: country-rule configs construct the IPInfoManager-backed geo handler
      // (_security_config_geo_validators.py:86-92).
      ConfigSeams.geoIpHandlerFactory = { token, dbPath, maxAge ->
        IpInfoManager.getInstance(token, dbPath, maxAge)
      }
      // G-6: the cloud-provider block branch resolves through CloudManager
      // (access_control.py:197-215).
      AccessControl.cloudIpChecker = { ip, providers ->
        CloudManager.getInstance().getCloudProviderDetails(ip, providers)?.let { (provider, network)
          ->
          AccessControl.CloudProviderDetails(provider, network)
        }
      }
      registered = true
    }
  }
}
