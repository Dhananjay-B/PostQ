package model

type TLSCertificate struct {
	Subject            string
	Issuer             string
	NotBefore          string
	NotAfter           string
	SerialNumber       string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKey 		   string
}