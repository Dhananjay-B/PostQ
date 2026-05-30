package smtpanalysis

import (
	smtpmodels "github.com/Dhananjay-B/PostQ/internal/model/smtpmodels"
)

func AnalyzeSMTPProbe(probe smtpmodels.SMTPProbe) (SMTPQuantumAssessment, error) {

	startTLSAnalysis := analyzeSMTPSTARTTLS(probe)

	authAnalysis := analyzeSMTPAuth(probe)

	tlsAnalysis := analyzeSMTPTLSProfiles(probe)

	return SMTPQuantumAssessment{
		Host:     probe.ServerHostName,
		STARTTLS: startTLSAnalysis,
		Auth:     authAnalysis,
		TLS:      tlsAnalysis,
	}, nil
}

type SMTPQuantumAssessment struct {
	Host     string
	STARTTLS smtpmodels.SMTPSTARTTLSQuantum
	Auth     smtpmodels.SMTPAuthQuantum
	TLS      smtpmodels.SMTPTLSQuantum
}
