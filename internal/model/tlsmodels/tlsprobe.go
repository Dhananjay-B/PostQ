package tlsmodels

type TLSProbe struct {
	Host                   string
	Port                   int
	SupportedTLSVersions   map[uint16]bool
	SupportedCiphers       map[uint16][]uint16
	ServerCipherPreference map[uint16]bool
	ServerName             string
	PeerCertificates       []*TLSCertificate // Only for TLS 1.3
}
