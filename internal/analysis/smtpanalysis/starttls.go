package smtpanalysis

import (
	smtpmodels "github.com/Dhananjay-B/PostQ/internal/model/smtpmodels"
)

func analyzeSMTPSTARTTLS(probe smtpmodels.SMTPProbe) smtpmodels.SMTPSTARTTLSQuantum {

	result := smtpmodels.SMTPSTARTTLSQuantum{}

	result.STARTTLSSupported = probe.STARTTLSSupported

	// ---- Quantum Risk Evaluation ---- //

	if probe.STARTTLSSupported {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicySTARTTLSSupported])

	} else {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicySTARTTLSMissing])
	}

	return result
}
