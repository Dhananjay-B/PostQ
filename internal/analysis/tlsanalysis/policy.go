package tlsanalysis

import (
	tlsmodels "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"
)

const (
	INFORMATIONAL = "Informational"
	CRITICAL      = "Critical"
	HIGH          = "High"
	MEDIUM        = "Medium"
	LOW           = "Low"
	NONE          = "None"
)

const (
	// TLS Version Policy Keys
	PolicyTLS13Enabled      = "tls13_enabled"
	PolicyTLS13Missing      = "tls13_missing"
	PolicyClassicalFallback = "classical_fallback"
	PolicyLegacyEnabled     = "legacy_enabled"

	// TLS Cipher Policy Keys
	PolicyStaticRSAKEX      = "static_rsa_kex"
	PolicyForwardSecrecy    = "forward_secrecy_present"
	PolicyAllClassicalKEX   = "all_classical_kex"
	PolicyAllClassicalAuth  = "all_classical_auth"
	PolicyTLS13ModernCipher = "tls13_modern_cipher"
)

var TLSQuantumPolicy = map[string]tlsmodels.QuantumAssessment{

	// TLS Protocol Version Policies //

	PolicyTLS13Enabled: {
		Asset:       "VersionTLS",
		Findings:    []string{"TLS 1.3 is supported"},
		Description: []string{"Hybrid post-quantum key exchange migration is possible"},
		Risks:       []string{},
		Severity:    INFORMATIONAL,
	},

	PolicyTLS13Missing: {
		Asset:       "VersionTLS",
		Findings:    []string{"TLS 1.3 is not supported"},
		Description: []string{"TLS 1.3 is required for standardized hybrid / post-quantum key exchange"},
		Risks: []string{
			"No path to deploy ML-KEM hybrids or pure PQC key exchange",
			"Permanent dependency on classical asymmetric cryptography vulnerable to Shor's algorithm",
		},
		Severity: CRITICAL,
	},

	PolicyClassicalFallback: {
		Asset:       "VersionTLS",
		Findings:    []string{"Classical fallback / downgrade path present"},
		Description: []string{"TLS downgrade protection mechanisms may be present but are insufficient"},
		Risks: []string{
			"Hybrid / PQC negotiation can be bypassed by active downgrade",
			"Harvest-now-decrypt-later (HNDL) exposure via forced use of classical key exchange",
		},
		Severity: HIGH,
	},

	PolicyLegacyEnabled: {
		Asset:       "VersionTLS",
		Findings:    []string{"Legacy TLS versions (1.0 / 1.1) are enabled"},
		Description: []string{"Server accepts connections using very old protocol versions"},
		Risks: []string{
			"Negotiation to fully quantum-vulnerable protocol versions possible",
			"High HNDL risk due to legacy protocol support (weak ciphers + no forward secrecy in many cases)",
			"Significant compliance and attack surface increase",
		},
		Severity: HIGH,
	},

	// Cipher Suite & Key Exchange Policies //

	PolicyStaticRSAKEX: {
		Asset:       "KEXTLS",
		Findings:    []string{"Static RSA key exchange cipher suites are supported"},
		Description: []string{"Non-forward-secret key transport using RSA encryption"},
		Risks: []string{
			"No forward secrecy — long-term private key compromise allows decryption of all past sessions",
			"Immediate harvest-now-decrypt-later (HNDL) risk",
			"Strongly discouraged in modern deployments",
		},
		Severity: CRITICAL,
	},

	PolicyForwardSecrecy: {
		Asset:       "KEXTLS",
		Findings:    []string{"Forward secrecy is supported (ECDHE / DHE / hybrid)"},
		Description: []string{"Ephemeral key exchange provides session key confidentiality"},
		Risks:       []string{},
		Severity:    INFORMATIONAL,
	},

	PolicyAllClassicalKEX: {
		Asset:       "KEXTLS",
		Findings:    []string{"All supported key exchanges are classical (no PQC/hybrid detected)"},
		Description: []string{"Key exchange relies exclusively on ECDHE, DHE or RSA"},
		Risks: []string{
			"Full exposure to Shor's algorithm once a cryptographically relevant quantum computer (CRQC) exists",
			"Key exchange material vulnerable to future quantum attacks (harvest-now-decrypt-later threat)",
		},
		Severity: HIGH,
	},

	PolicyAllClassicalAuth: {
		Asset:       "AuthTLS",
		Findings:    []string{"All authentication uses classical signatures (RSA / ECDSA / EdDSA)"},
		Description: []string{"Server certificate and CertificateVerify signatures are classical"},
		Risks: []string{
			"Server identity and certificate chain vulnerable to forgery via Shor's algorithm post-CRQC",
			"Man-in-the-middle forgery / impersonation risk after quantum breakthrough",
			"Long-term trust in certificate chain compromised",
		},
		Severity: HIGH,
	},

	PolicyTLS13ModernCipher: {
		Asset:       "SymmetricTLS",
		Findings:    []string{"Modern TLS 1.3 cipher suite in use (AES-256-GCM or ChaCha20-Poly1305)"},
		Description: []string{"Strong authenticated encryption with 256-bit or equivalent keys"},
		Risks: []string{
			"Grover's algorithm halves effective key strength, but remains secure (≥128-bit post-quantum security)",
		},
		Severity: LOW,
	},
}
