package tlsanalysis

import (
	tlsmodels "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"
)

func AnalyzeTLSProbe(probe tlsmodels.TLSProbe) TLSQuantumAssessment {

	versionAnalysis := analyzeTLSVersions(probe)
	cipherSuiteAnalysis := analyzeTLSCiphers(probe)

	return TLSQuantumAssessment{
		Protocol:    versionAnalysis,
		CipherSuite: cipherSuiteAnalysis,
	}
}

type TLSQuantumAssessment struct {
	Protocol    tlsmodels.TLSProtocolQuantum
	CipherSuite tlsmodels.TLSCipherQuantum
}
