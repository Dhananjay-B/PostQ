package tls

import "time"

type TLSCertificate struct {
	CertID       int64
	ScanID       int64
	Position     int
	SubjectDN    string
	IssuerDN     string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	PublicKeyAlg string
	SignatureAlg string
	IsCA         bool
	IsSelfSigned bool
}
