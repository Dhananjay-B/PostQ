package model

import (
	tlsmodel "github.com/Dhananjay-B/PostQ/internal/model/db/tls"
)

type TLSRaw struct {
	Host             string
	Port             int
	Version          string
	CipherSuite      string
	ServerName       string
	PeerCertificates []*tlsmodel.TLSCertificate
}
