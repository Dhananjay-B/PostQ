package smtpanalysis

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

	// STARTTLS Policies

	PolicySTARTTLSSupported     = "starttls_supported"
	PolicySTARTTLSMissing       = "starttls_missing"
	PolicyAUTHBeforeSTARTTLS    = "auth_before_starttls"
	PolicyAUTHWithoutTLSAllowed = "auth_without_tls_allowed"
	PolicySTARTTLSEnforcedAuth  = "starttls_enforced_for_auth"

	// AUTH Mechanism Policies

	PolicyWeakAuthMechanisms = "weak_auth_mechanisms"
	PolicyLegacyCRAMMD5      = "legacy_cram_md5"
	PolicyModernXOAUTH2      = "modern_xoauth2"

	// SMTP TLS Policies

	PolicySMTPAllClassicalTLS = "smtp_all_classical_tls"
	PolicySMTPForwardSecrecy  = "smtp_forward_secrecy"
	PolicySMTPStaticRSAKEX    = "smtp_static_rsa_kex"
	PolicySMTPTLS13Supported  = "smtp_tls13_supported"
	PolicySMTPLegacyTLS       = "smtp_legacy_tls"

	// SMTP HNDL Policies

	PolicySMTPHNDLExposure = "smtp_hndl_exposure"
)

var SMTPQuantumPolicy = map[string]tlsmodels.QuantumAssessment{

	// STARTTLS Policies //

	PolicySTARTTLSSupported: {
		Asset:       "STARTTLS",
		Findings:    []string{"SMTP server supports STARTTLS"},
		Description: []string{"Encrypted transport for SMTP sessions is available"},
		Risks:       []string{},
		Severity:    INFORMATIONAL,
	},

	PolicySTARTTLSMissing: {
		Asset:       "STARTTLS",
		Findings:    []string{"SMTP server does not support STARTTLS"},
		Description: []string{"SMTP communication occurs entirely in plaintext"},
		Risks: []string{
			"Complete exposure of email contents and credentials to passive interception",
			"No confidentiality guarantees for SMTP transport",
			"Maximum harvest-now-decrypt-later (HNDL) exposure due to absence of encryption",
		},
		Severity: CRITICAL,
	},

	PolicyAUTHBeforeSTARTTLS: {
		Asset:       "AUTHSMTP",
		Findings:    []string{"AUTH mechanisms advertised before STARTTLS"},
		Description: []string{"Authentication capabilities exposed on plaintext SMTP channel"},
		Risks: []string{
			"Clients may attempt credential submission without encryption",
			"Increased downgrade and credential interception risk",
		},
		Severity: HIGH,
	},

	PolicyAUTHWithoutTLSAllowed: {
		Asset:       "AUTHSMTP",
		Findings:    []string{"SMTP server accepts AUTH before TLS establishment"},
		Description: []string{"Authentication is permitted over plaintext SMTP"},
		Risks: []string{
			"Credentials can be captured by passive network attackers",
			"STARTTLS downgrade protection ineffective for authentication",
		},
		Severity: CRITICAL,
	},

	PolicySTARTTLSEnforcedAuth: {
		Asset:       "AUTHSMTP",
		Findings:    []string{"SMTP server enforces STARTTLS before AUTH"},
		Description: []string{"Authentication only allowed after encrypted transport established"},
		Risks:       []string{},
		Severity:    INFORMATIONAL,
	},

	// AUTH Mechanism Policies //

	PolicyWeakAuthMechanisms: {
		Asset:       "AUTHSMTP",
		Findings:    []string{"Weak SMTP authentication mechanisms detected (PLAIN / LOGIN)"},
		Description: []string{"Legacy authentication methods relying on transport encryption"},
		Risks: []string{
			"Credential exposure possible if TLS downgraded or absent",
			"No cryptographic protection at authentication layer itself",
		},
		Severity: MEDIUM,
	},

	PolicyLegacyCRAMMD5: {
		Asset:       "AUTHSMTP",
		Findings:    []string{"CRAM-MD5 authentication supported"},
		Description: []string{"Legacy challenge-response authentication mechanism detected"},
		Risks: []string{
			"Relies on deprecated MD5 cryptographic primitive",
			"Outdated authentication security design",
		},
		Severity: MEDIUM,
	},

	PolicyModernXOAUTH2: {
		Asset:       "AUTHSMTP",
		Findings:    []string{"Modern XOAUTH2 authentication supported"},
		Description: []string{"OAuth2-based delegated authentication detected"},
		Risks:       []string{},
		Severity:    INFORMATIONAL,
	},

	// SMTP TLS Policies //

	PolicySMTPAllClassicalTLS: {
		Asset:       "KEXSMTP",
		Findings:    []string{"SMTP transport relies entirely on classical cryptography"},
		Description: []string{"No post-quantum or hybrid cryptography detected"},
		Risks: []string{
			"SMTP traffic vulnerable to future cryptographically relevant quantum computers (CRQC)",
			"Harvest-now-decrypt-later (HNDL) exposure for archived email traffic",
		},
		Severity: HIGH,
	},

	PolicySMTPForwardSecrecy: {
		Asset:       "KEXSMTP",
		Findings:    []string{"Forward secrecy supported for SMTP transport"},
		Description: []string{"Ephemeral key exchange mechanisms detected"},
		Risks: []string{
			"Still quantum-vulnerable under Shor's algorithm despite forward secrecy",
		},
		Severity: LOW,
	},

	PolicySMTPStaticRSAKEX: {
		Asset:       "KEXSMTP",
		Findings:    []string{"Static RSA key exchange supported for SMTP"},
		Description: []string{"Non-forward-secret RSA transport encryption detected"},
		Risks: []string{
			"Past SMTP sessions decryptable if long-term key compromised",
			"Very high HNDL exposure for stored email traffic",
		},
		Severity: CRITICAL,
	},

	PolicySMTPTLS13Supported: {
		Asset:       "VersionSMTP",
		Findings:    []string{"TLS 1.3 supported for SMTP"},
		Description: []string{"Modern TLS protocol available for SMTP transport"},
		Risks: []string{
			"Still dependent on classical cryptography unless PQ/hybrid deployed",
		},
		Severity: INFORMATIONAL,
	},

	PolicySMTPLegacyTLS: {
		Asset:       "VersionSMTP",
		Findings:    []string{"Legacy TLS versions enabled for SMTP"},
		Description: []string{"TLS 1.0 / 1.1 supported for email transport"},
		Risks: []string{
			"Negotiation to weak and outdated cryptographic protocols possible",
			"Increased attack surface and downgrade exposure",
		},
		Severity: HIGH,
	},
}
