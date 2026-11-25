# SMB Microsoft 365 & Cybersecurity Baseline Evaluator

Automated tenant security posture auditor covering Conditional Access MFA, phishing/DMARC email controls, leaked-credential rotation SLAs, immutable backup/DR RPO verification, and VoIP SIP TLS readiness.

## Problem

Managed IT teams supporting small-to-medium organizations across Microsoft 365 and Azure regularly verify the same recurring defensive controls across dozens of client tenants:

1. **Identity & Legacy Auth**: Phishing-resistant or Conditional Access MFA coverage, blocking legacy IMAP/POP3/SMTP auth, and break-glass admin separation.
2. **Email Phishing Protection**: Enforcing SPF (`-all`), DKIM signing, and DMARC (`quarantine`/`reject`) across primary mail domains.
3. **Backup & Disaster Recovery**: Verifying snapshot RPO recency, immutable storage flags, and recent restore drills.
4. **Breached Credentials & VoIP**: Checking unrotated dark-web credential exposure and TLS/SRTP configuration on cloud VoIP trunks.

## Running Tests

```bash
PYTHONPATH=src python3 -m pytest -v
```
