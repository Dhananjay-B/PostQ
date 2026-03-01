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
			Version:                    versionToString(version),
			AllKeyExchangesClassical:   true,
			AllAuthenticationClassical: true,
		}

		kexTypes := make(map[string]bool)
		authTypes := make(map[string]bool)

		// TLS 1.3 is structurally different
		if version == tls.VersionTLS13 {
			versionAnalysis.TLS13Cipher = true
			result.PerVersion = append(result.PerVersion, versionAnalysis)
			continue
		}

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

		versionAnalysis.KeyExchangeTypes = mapKeys(kexTypes)
		versionAnalysis.AuthenticationTypes = mapKeys(authTypes)

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

		result.PerVersion = append(result.PerVersion, versionAnalysis)
	}

	if result.AnyStaticRSA {
		result.HarvestNowDecryptLaterRisk = true
	}

	// ---- Quantum Risk Evaluation ---- //

	if result.AnyStaticRSA {
		result.QuantumSignals = append(
			result.QuantumSignals,
			TLSCipherPolicy[PolicyStaticRSAKEX],
		)
	}

	if result.AnyForwardSecrecy {
		result.QuantumSignals = append(
			result.QuantumSignals,
			TLSCipherPolicy[PolicyForwardSecrecy],
		)
	}

	if result.AllKeyExchangesClassical {
		result.QuantumSignals = append(
			result.QuantumSignals,
			TLSCipherPolicy[PolicyAllClassicalKEX],
		)
	}

	if result.AllAuthenticationClassical {
		result.QuantumSignals = append(
			result.QuantumSignals,
			TLSCipherPolicy[PolicyAllClassicalAuth],
		)
	}

	for _, v := range result.PerVersion {
		if v.TLS13Cipher {
			result.QuantumSignals = append(
				result.QuantumSignals,
				TLSCipherPolicy[PolicyTLS13ModernCipher],
			)
			break
		}
	}

	return result
}

func mapKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
