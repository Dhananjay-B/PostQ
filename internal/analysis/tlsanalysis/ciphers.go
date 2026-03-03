package tlsanalysis

import (
	"crypto/tls"
	"strings"

	tlsmodels "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"
)

func analyzeTLSCiphers(probe tlsmodels.TLSProbe) tlsmodels.TLSCipherQuantum {

	result := tlsmodels.TLSCipherQuantum{
		AllKeyExchangesClassical:   true,
		AllAuthenticationClassical: true,
	}

	for version, cipherList := range probe.SupportedCiphers {

		versionAnalysis := tlsmodels.TLSVersionCipherQuantum{
			Version:                    VersionToString(version),
			AllKeyExchangesClassical:   true,
			AllAuthenticationClassical: true,
			QuantumAssessment:          []tlsmodels.QuantumAssessment{},
		}

		// TLS 1.3 is structurally different
		if version == tls.VersionTLS13 {
			versionAnalysis.TLS13Cipher = true
			versionAnalysis.QuantumAssessment = append(versionAnalysis.QuantumAssessment, TLSQuantumPolicy[PolicyTLS13ModernCipher])
			result.PerVersion = append(result.PerVersion, versionAnalysis)
			continue
		}

		kexTypes := make(map[string]bool)
		authTypes := make(map[string]bool)

		for _, cipherID := range cipherList {

			cipherName := tls.CipherSuiteName(cipherID)

			parts := strings.Split(cipherName, "_WITH_")
			if len(parts) != 2 {
				continue
			}

			prefix := strings.TrimPrefix(parts[0], "TLS_")
			kexAuth := strings.Split(prefix, "_")

			if len(kexAuth) == 1 {
				// Static RSA case
				kex := kexAuth[0]
				kexTypes[kex] = true
				authTypes[kex] = true

				if kex == "RSA" {
					versionAnalysis.StaticRSAKeyExchangePresent = true
					result.AnyStaticRSA = true
				}
			} else if len(kexAuth) >= 2 {

				kex := kexAuth[0]
				auth := kexAuth[1]

				kexTypes[kex] = true
				authTypes[auth] = true

				if kex == "ECDHE" || kex == "DHE" {
					versionAnalysis.ForwardSecrecyPresent = true
					result.AnyForwardSecrecy = true
				}

				if kex == "RSA" {
					versionAnalysis.StaticRSAKeyExchangePresent = true
					result.AnyStaticRSA = true
				}
			}
		}

		versionAnalysis.KeyExchangeTypes = MapKeys(kexTypes)
		versionAnalysis.AuthenticationTypes = MapKeys(authTypes)

		for kex := range kexTypes {
			if kex != "ECDHE" && kex != "DHE" && kex != "RSA" {
				versionAnalysis.AllKeyExchangesClassical = false
				result.AllKeyExchangesClassical = false
			}
		}

		for auth := range authTypes {
			if auth != "RSA" && auth != "ECDSA" && auth != "ED25519" {
				versionAnalysis.AllAuthenticationClassical = false
				result.AllAuthenticationClassical = false
			}
		}

		// Attach quantum assessments — per version
		if versionAnalysis.StaticRSAKeyExchangePresent {
			versionAnalysis.QuantumAssessment = append(
				versionAnalysis.QuantumAssessment,
				TLSQuantumPolicy[PolicyStaticRSAKEX],
			)
		}

		if versionAnalysis.ForwardSecrecyPresent {
			versionAnalysis.QuantumAssessment = append(
				versionAnalysis.QuantumAssessment,
				TLSQuantumPolicy[PolicyForwardSecrecy],
			)
		}

		if versionAnalysis.AllKeyExchangesClassical {
			versionAnalysis.QuantumAssessment = append(
				versionAnalysis.QuantumAssessment,
				TLSQuantumPolicy[PolicyAllClassicalKEX],
			)
		}

		if versionAnalysis.AllAuthenticationClassical {
			versionAnalysis.QuantumAssessment = append(
				versionAnalysis.QuantumAssessment,
				TLSQuantumPolicy[PolicyAllClassicalAuth],
			)
		}

		result.PerVersion = append(result.PerVersion, versionAnalysis)

		if !versionAnalysis.AllKeyExchangesClassical {
			result.AllKeyExchangesClassical = false
		}
		if !versionAnalysis.AllAuthenticationClassical {
			result.AllAuthenticationClassical = false
		}
	}

	if result.AnyStaticRSA {
		result.HarvestNowDecryptLaterRisk = true
	}

	return result
}
