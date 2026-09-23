# Security policy

## Project status

CipherShield is educational research software, not a production security
product. Do not use it to protect sensitive or regulated data. No release is
currently supported for production deployment.

## Reporting a vulnerability

Do not post exploit details, private keys, credentials, or sensitive files in a
public issue. Use GitHub's private vulnerability-reporting flow from the
repository's **Security** tab when available. If that flow is unavailable,
contact the repository owner through the public GitHub profile before sharing
details.

Include:

- the affected commit and dependency versions;
- a minimal reproduction using synthetic data;
- the expected and observed behavior;
- the impact and any suggested mitigation.

General bugs and documentation errors that do not expose sensitive details may
be filed as ordinary issues.

## Scope

Useful reports include misuse of cryptographic APIs, authentication failures
that are silently accepted, unsafe secret handling, dependency confusion, and
misleading security claims. The absence of production key storage, networking,
access control, certification, and side-channel hardening is already documented
and is not itself a vulnerability in this educational scope.
