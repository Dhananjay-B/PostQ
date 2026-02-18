# PostQ

PostQ is a tool for discovering and inventorying cryptographic assets inside network (TLS/HTTPS endpoint, SSH, Email infra etc), with a focus on post-quantum risk assessment.

## What it does

- Connects to public TLS endpoints
- Performs controlled TLS handshakes
- Extracts cryptographic facts (TLS versions, cipher suites, certificates)
- Lays the groundwork for quantum-risk classification

> PostQ discovers what is deployed, not what is intended.

## Current Scope

- TCP + TLS (HTTPS)
- Leaf certificate inspection
- Negotiated TLS version and cipher

## Planned Scope

### HTTPS (Extended TLS Intelligence)

- OCSP / CRL endpoint inspection
- QUIC / HTTP-3 probing

### SSH

- SSH version detection
- Host key algorithm and key size extraction
- Key exchange (KEX) algorithm enumeration
- Encryption and MAC algorithm enumeration
- Deprecated / weak algorithm detection
- Post-quantum risk classification

### Email Infrastructure

#### SMTP
- STARTTLS detection
- TLS enforcement posture (opportunistic vs strict)
- MX record resolution and multi-host scanning
- TLS parameter extraction
- MTA-STS policy detection
- DANE / DNSSEC validation checks

#### IMAP / POP3
- STARTTLS support detection
- Implicit TLS (993 / 995) probing
- TLS parameter extraction
- Certificate chain inspection
- Post-quantum risk classification

## Project structure

```text
cmd/
  api/            REST API server exposing scan & asset endpoints
  postq/          CLI tool for local scanning and experimentation

internal/
  api/            Gin handlers and background scan orchestration
  config/         Configuration management and environment loading
  helper/         Reusable helper functions
  probe/          TLS and network probing logic
  model/          Domain models
    db/            Database schema representations (TLS assets, scans)

Project root
  go.mod / go.sum Dependency and module management
```
## Contribution

We welcome contributions of all sizes.

Refer to [CONTRIBUTING.md](CONTRIBUTING.md) for contribution steps & guidelines