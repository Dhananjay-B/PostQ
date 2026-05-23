package smtpmodels

type SMTPProbe struct {
	ServerHostName    string
	ESMTPSupported    bool
	SMTPSoftware      string
	STARTTLSSupported bool

	AuthBeforeSTARTTLS *SMTPAuthProfile

	TLSProfiles map[uint16]*SMTPTLSProfile
}
