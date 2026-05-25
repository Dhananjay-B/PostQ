package smtpmodels

type SMTPProbe struct {
	ServerHostName    string
	ESMTPSupported    bool
	SMTPSoftware      string
	STARTTLSSupported bool

	AuthBeforeSTARTTLS      *SMTPAuthProfile
	AUTHAllowedWithoutTLS   bool
	STARTTLSEnforcedForAuth bool

	TLSProfiles map[uint16]*SMTPTLSProfile
}
