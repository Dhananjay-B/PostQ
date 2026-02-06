# PostQ

PostQ is a backend tool for discovering and inventorying cryptographic assets exposed by public TLS/HTTPS endpoints, with a focus on post-quantum risk assessment.

## What it does

- Connects to public TLS endpoints
- Performs controlled TLS handshakes
- Extracts cryptographic facts (TLS versions, cipher suites, certificates)
- Lays the groundwork for quantum-risk classification

> PostQ discovers what is deployed, not what is intended.

## Current scope

- TCP + TLS (HTTPS)
- Leaf certificate inspection
- Negotiated TLS version and cipher

## Planned

- TLS version and cipher enumeration
- Certificate chain analysis
- Post-quantum risk classification
- Historical cryptographic drift tracking
- QUIC / HTTP-3 probing

## Project structure

```text
cmd/        Entry points
internal/
  probe/    Network and TLS probes
  model/    Canonical data models