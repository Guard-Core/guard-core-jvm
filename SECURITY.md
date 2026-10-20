# Security Policy for Guard Core JVM

## Supported Versions

I provide security updates for the following versions of guard-core-jvm:

| Version | Supported |
| ------- | --------- |
| 4.x | :white_check_mark: bug and security fixes |

## Reporting a Vulnerability

I take the security of Guard Core JVM seriously. If you believe you've found a security vulnerability, please follow these steps:

1. **Do not disclose the vulnerability publicly** until I have fixed it.
2. **Report the vulnerability through GitHub's security advisory feature**:
   - Go to the [Security tab](https://github.com/Guard-Core/guard-core-jvm/security/advisories) of the Guard Core JVM repository
   - Click on "New draft security advisory"
   - Fill in the details of the vulnerability
   - Submit the advisory

   Alternatively, you can report vulnerabilities through [GitHub's private vulnerability reporting feature](https://github.com/Guard-Core/guard-core-jvm/security/advisories/new).

3. Include the following information in your report:
   - A description of the vulnerability and its potential impact
   - Steps to reproduce the issue
   - Affected versions
   - Any potential mitigations or workarounds

I will acknowledge your report within 48 hours and send a detailed response within 7 days, including the next steps in handling the vulnerability.

## Security Considerations

Guard Core JVM is a security library: report anything that weakens detection, bypasses rate limiting, leaks secrets into logs, or trusts unvalidated input.

This repository is the engine and facade of the JVM family. Vulnerabilities in
the adapters (spring-boot-guard, ktor-guard) or the telemetry agent
(guard-agent-jvm) belong in those repositories' security advisories.
