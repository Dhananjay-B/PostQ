package smtpmodels

import tlsmodels "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"

type SMTPSTARTTLSQuantum struct {
	STARTTLSSupported bool
	QuantumAssessment []tlsmodels.QuantumAssessment
}

type SMTPAuthQuantum struct {
	AUTHBeforeSTARTTLS      bool
	AUTHAllowedWithoutTLS   bool
	STARTTLSEnforcedForAuth bool
	WeakAuthMechanisms      []string
	SupportsCRAMMD5         bool
	SupportsXOAUTH2         bool
	QuantumAssessment       []tlsmodels.QuantumAssessment
}

type SMTPTLSQuantum struct {
	SupportsTLS13          bool
	SupportsLegacyTLS      bool
	SupportsForwardSecrecy bool
	SupportsStaticRSA      bool
	AllClassicalCrypto     bool
	QuantumAssessment      []tlsmodels.QuantumAssessment
}
