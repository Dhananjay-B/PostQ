package smtpanalysis

import (
	"crypto/tls"
	"strings"

	smtpmodels "github.com/Dhananjay-B/PostQ/internal/model/smtpmodels"
)

func analyzeSMTPTLSProfiles(probe smtpmodels.SMTPProbe) smtpmodels.SMTPTLSQuantum {

	result := smtpmodels.SMTPTLSQuantum{
		AllClassicalCrypto: true,
	}

	for version, profile := range probe.TLSProfiles {
		switch version {
		case tls.VersionTLS13:
			result.SupportsTLS13 = true
		case tls.VersionTLS10, tls.VersionTLS11:
			result.SupportsLegacyTLS = true
		}

		for _, cipherID := range profile.SupportedCipherSuites {

			cipherName := tls.CipherSuiteName(cipherID)

			// TLS 1.3 cipher
			if version == tls.VersionTLS13 {
				continue
			}

			parts := strings.Split(cipherName, "_WITH_")

			if len(parts) != 2 {
				continue
			}

			prefix := strings.TrimPrefix(parts[0], "TLS_")

			kexAuth := strings.Split(prefix, "_")

			if len(kexAuth) == 1 {
				if kexAuth[0] == "RSA" {
					result.SupportsStaticRSA = true
				}
				continue
			}

			kex := kexAuth[0]

			if kex == "ECDHE" || kex == "DHE" {
				result.SupportsForwardSecrecy = true
			}

			// Future PQ / Hybrid detection hook
			if kex != "ECDHE" && kex != "DHE" && kex != "RSA" {
				result.AllClassicalCrypto = false
			}
		}
	}

	// ---- Quantum Risk Evaluation ---- //

	if result.SupportsTLS13 {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicySMTPTLS13Supported])
	}

	if result.SupportsLegacyTLS {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicySMTPLegacyTLS])
	}

	if result.SupportsForwardSecrecy {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicySMTPForwardSecrecy])
	}

	if result.SupportsStaticRSA {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicySMTPStaticRSAKEX])
	}

	if result.AllClassicalCrypto {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicySMTPAllClassicalTLS])

	}

	return result
}
