package tlsanalysis

import (
	"crypto/tls"

	tlsmodels "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"
)

func analyzeTLSVersions(probe tlsmodels.TLSProbe) tlsmodels.TLSProtocolQuantum {

	var highest uint16
	var lowest uint16

	result := tlsmodels.TLSProtocolQuantum{}

	for version, supported := range probe.SupportedTLSVersions {
		if !supported {
			continue
		}

		if highest == 0 || version > highest {
			highest = version
		}

		if lowest == 0 || version < lowest {
			lowest = version
		}

		switch version {
		case tls.VersionTLS13:
			result.TLS13Enabled = true
		case tls.VersionTLS12:
			result.TLS12Enabled = true
		case tls.VersionTLS10, tls.VersionTLS11:
			result.LegacyEnabled = true
		}
	}

	if result.TLS13Enabled && result.TLS12Enabled {
		result.ClassicalFallbackPresent = true
	}

	result.HighestVersion = versionToString(highest)
	result.LowestVersion = versionToString(lowest)

	// ---- Quantum Risk Evaluation ---- //

	if result.TLS13Enabled {
		result.PQMigrationReady = true
		result.QuantumSignals = append(result.QuantumSignals,
			TLSVersionPolicy[PolicyTLS13Enabled],
		)
	} else {
		result.QuantumSignals = append(result.QuantumSignals,
			TLSVersionPolicy[PolicyTLS13Missing],
		)
	}

	if result.ClassicalFallbackPresent {
		result.HybridBypassSurface = true
		result.QuantumSignals = append(result.QuantumSignals,
			TLSVersionPolicy[PolicyClassicalFallback],
		)
	}

	if result.LegacyEnabled {
		result.QuantumSignals = append(result.QuantumSignals,
			TLSVersionPolicy[PolicyLegacyEnabled],
		)
	}

	return result
}

func versionToString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return "Unknown"
	}
}
