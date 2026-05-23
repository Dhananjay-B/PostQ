package smtpmodels

import "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"

type SMTPTLSProfile struct {
	TLSVersion uint16

	SupportedCipherSuites []uint16

	ServerCipherPreference bool

	AuthAfterSTARTTLS *SMTPAuthProfile

	PeerCertificates []*tlsmodels.TLSCertificate
}
