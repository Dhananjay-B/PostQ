package smtpmodels

import "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"

type SMTPProbe struct {
	ServerHostName    string
	ESMTPSupported    bool
	SMTPSoftware      string
	STARTTLSSupported bool
	SMTPTLSProbe      *tlsmodels.TLSProbe
}
