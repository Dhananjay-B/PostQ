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