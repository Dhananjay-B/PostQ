package smtpanalysis

import (
	smtpmodels "github.com/Dhananjay-B/PostQ/internal/model/smtpmodels"
)

func analyzeSMTPAuth(probe smtpmodels.SMTPProbe) smtpmodels.SMTPAuthQuantum {

	result := smtpmodels.SMTPAuthQuantum{
		AUTHBeforeSTARTTLS:      probe.AuthBeforeSTARTTLS != nil,
		AUTHAllowedWithoutTLS:   probe.AUTHAllowedWithoutTLS,
		STARTTLSEnforcedForAuth: probe.STARTTLSEnforcedForAuth,
	}

	weakAuthMethods := make(map[string]bool)

	// ---- Collect AUTH Before STARTTLS ---- //

	if probe.AuthBeforeSTARTTLS != nil {

		authProfile := probe.AuthBeforeSTARTTLS

		if authProfile.SupportsAuthPlain {
			weakAuthMethods["PLAIN"] = true
		}

		if authProfile.SupportsAuthLogin {
			weakAuthMethods["LOGIN"] = true
		}

		if authProfile.SupportsCRAMMD5 {
			result.SupportsCRAMMD5 = true
		}

		if authProfile.SupportsXOAUTH2 {
			result.SupportsXOAUTH2 = true
		}
	}

	// ---- Collect AUTH After STARTTLS ---- //

	for _, tlsProfile := range probe.TLSProfiles {

		if tlsProfile.AuthAfterSTARTTLS == nil {
			continue
		}

		authProfile := tlsProfile.AuthAfterSTARTTLS

		if authProfile.SupportsAuthPlain {
			weakAuthMethods["PLAIN"] = true
		}

		if authProfile.SupportsAuthLogin {
			weakAuthMethods["LOGIN"] = true
		}

		if authProfile.SupportsCRAMMD5 {
			result.SupportsCRAMMD5 = true
		}

		if authProfile.SupportsXOAUTH2 {
			result.SupportsXOAUTH2 = true
		}
	}

	for method := range weakAuthMethods {
		result.WeakAuthMechanisms = append(result.WeakAuthMechanisms, method)
	}

	// ---- Quantum Risk Evaluation ---- //

	if result.AUTHBeforeSTARTTLS {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicyAUTHBeforeSTARTTLS])
	}

	if result.AUTHAllowedWithoutTLS {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicyAUTHWithoutTLSAllowed])
	}

	if result.STARTTLSEnforcedForAuth {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicySTARTTLSEnforcedAuth])
	}

	if len(result.WeakAuthMechanisms) > 0 {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicyWeakAuthMechanisms])
	}

	if result.SupportsCRAMMD5 {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicyLegacyCRAMMD5])
	}

	if result.SupportsXOAUTH2 {
		result.QuantumAssessment = append(result.QuantumAssessment, SMTPQuantumPolicy[PolicyModernXOAUTH2])
	}

	return result
}
