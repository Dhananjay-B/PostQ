package model

import (
	tlsmodel "github.com/Dhananjay-B/PostQ/internal/model/db/tls"
)

type TLSRaw struct {
	Host                 string
	Port                 int
	SupportedTLSVersions map[uint16]bool
	SupportedCiphers     map[uint16][]uint16
	ServerName           string
	PeerCertificates     []*tlsmodel.TLSCertificate // Only for TLS 1.3
}
