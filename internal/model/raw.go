package model

import (
	"crypto/x509"
)

type TLSRaw struct {
	Host		     string
	Port			 int
	Version          string
	CipherSuite      string
	ServerName       string
	PeerCertificates []*x509.Certificate
}
