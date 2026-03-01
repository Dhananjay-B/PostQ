package tlsanalysis

// TLS Version Policy Keys
const (
	PolicyTLS13Enabled      = "tls13_enabled"
	PolicyTLS13Missing      = "tls13_missing"
	PolicyClassicalFallback = "classical_fallback"
	PolicyLegacyEnabled     = "legacy_enabled"
)

var TLSVersionPolicy = map[string]string{
	PolicyTLS13Enabled:      "TLS 1.3 supported (hybrid PQ migration possible)",
	PolicyTLS13Missing:      "No TLS 1.3 support (PQ migration constrained)",
	PolicyClassicalFallback: "TLS 1.2 fallback present (hybrid bypass surface)",
	PolicyLegacyEnabled:     "Legacy TLS versions enabled",
}

// TLS Cipher Policy Keys
const (
	PolicyStaticRSAKEX      = "static_rsa_kex"
	PolicyForwardSecrecy    = "forward_secrecy_present"
	PolicyAllClassicalKEX   = "all_classical_kex"
	PolicyAllClassicalAuth  = "all_classical_auth"
	PolicyTLS13ModernCipher = "tls13_modern_cipher"
)

var TLSCipherPolicy = map[string]string{

	PolicyStaticRSAKEX:      "Static RSA key exchange detected (no forward secrecy, immediate harvest-now-decrypt-later risk)",
	PolicyForwardSecrecy:    "Forward secrecy supported (limits passive decryption window)",
	PolicyAllClassicalKEX:   "All supported key exchanges rely on classical cryptography (Shor vulnerable)",
	PolicyAllClassicalAuth:  "All authentication mechanisms rely on classical signatures (Shor vulnerable)",
	PolicyTLS13ModernCipher: "TLS 1.3 modern symmetric cipher detected",
}
