# PostQ

PostQ is a tool for discovering and inventorying cryptographic assets inside network (TLS/HTTPS endpoint, SSH, Email infra etc), with a focus on post-quantum risk assessment.

## What it does

- Connects to public TLS endpoints
- Performs controlled TLS handshakes
- Extracts cryptographic facts (TLS versions, cipher suites, certificates)
- Lays the groundwork for quantum-risk classification

> PostQ discovers what is deployed, not what is intended.

## Current Scope

- TCP + TLS (HTTPS) quantum risk assessment
- Leaf certificate inspection for quantum risks

## Planned Scope

### Output Format

- Making output in standard CBOM format (current JSON format)

### HTTPS (Extended TLS Intelligence)

- OCSP / CRL endpoint inspection
- QUIC / HTTP-3 probing

### SSH

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

```
├── cmd/                         # Cobra CLI commands
│   ├── postq/                   # Local manual test file(non cobra)
│   ├── root.go                  # Root command (Cobra cli entry point)
│   ├── scan.go                  # scan parent command
│   ├── tls.go                   # scan tls command
│   ├── ssh.go                   # scan ssh command
│   └── version.go               # version command
│
├── api/                         # API server entrypoint and handlers
│   ├── server.go                # Gin server bootstrap
│   └── handlers/
│       └── tls.go               # TLS scan API handler
│
├── internal/
│   ├── analysis/                # Quantum risk assessment logic
│   │   └── tlsanalysis/
│   │       ├── tls.go           # TLS assessment orchestration
│   │       ├── versions.go      # TLS protocol version analysis
│   │       ├── ciphers.go       # Cipher suite analysis (per TLS version)
│   │       └── policy.go        # Centralized quantum policy definitions
│   │
│   ├── model/                   # Domain models
│   │   └── tlsmodels/           # TLS probe & assessment structs
│   │   └── sshmodels/           # SSH probe & assessment structs
│   │
│   └── probe/                   # Network cryptography inventory logic
│       ├── tls.go               # TLS probing implementation
│       └── ssh.go               # SSH probing implementation
│
├── test/                        # Experimental / local testing code
│   └── test.go
│
├── .github/workflows/           # CI/CD (release automation)
│   └── release.yml
│
├── main.go                      # CLI entrypoint
├── go.mod / go.sum              # Go module dependencies
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

## Contribution

We welcome contributions of all sizes.

Refer to [CONTRIBUTING.md](CONTRIBUTING.md) for contribution steps & guidelines