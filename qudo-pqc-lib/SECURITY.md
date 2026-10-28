# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

The ZenV Quantum team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

**Do not report security vulnerabilities through public GitHub issues.**

### How to Report

Send vulnerability reports to: **john@zenv.ai**

Please include the following information in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Affected component(s) (qudo-mlkem, qudo-mldsa, qudo-slhdsa, or libqudo-pqc)
- Potential impact assessment
- Any suggested fixes (if applicable)

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Acknowledgment of report | Within 48 hours |
| Initial assessment | Within 7 days |
| Status update to reporter | Within 14 days |
| Fix development and testing | Within 60 days |
| Public disclosure | Within 90 days of report |

### Disclosure Policy

- We follow a **90-day coordinated disclosure** timeline
- We will work with you to understand and resolve the issue before public disclosure
- We will credit reporters in the security advisory (unless anonymity is requested)
- If a fix requires more than 90 days, we will negotiate an extended timeline with the reporter

### Scope

The following are in scope for security reports:

- Cryptographic implementation flaws in ML-KEM, ML-DSA, or SLH-DSA operations
- Side-channel vulnerabilities (timing, cache, power analysis)
- Key material leakage or improper cleanup
- Buffer overflows or memory corruption
- Incorrect algorithm parameter validation

### Out of Scope

- Vulnerabilities in upstream dependencies (mlkem-native, mldsa-native, slhdsa-native) -- report these to the respective projects
- Denial of service through resource exhaustion with valid inputs
- Issues requiring physical access to the device

## Security Best Practices

When using this library:

1. Always use the latest supported version
2. Use ML-KEM-768 or higher for key encapsulation
3. Use ML-DSA-65 or higher for digital signatures
4. Never reuse ephemeral keypairs across sessions
5. Derive symmetric keys from shared secrets using a KDF (e.g., HKDF-SHA256)
6. Zero sensitive data after use (the library does this automatically for managed objects)
