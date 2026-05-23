package smtpmodels

type SMTPAuthProfile struct {
	AuthMechanisms []string

	SupportsAuthPlain bool
	SupportsAuthLogin bool
	SupportsCRAMMD5   bool
	SupportsXOAUTH2   bool
}
