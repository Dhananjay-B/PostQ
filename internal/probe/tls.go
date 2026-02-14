package probe

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/Dhananjay-B/PostQ/internal/model"
	tlsmodel "github.com/Dhananjay-B/PostQ/internal/model/db/tls"
)

var dialer = &net.Dialer{
	Timeout: 3 * time.Second,
}

func ScanTLS(e model.Endpoint) (model.TLSRaw, error) {
	supportedVersions := enumerateTLSVersions(e.HostName, e.Port)
	supportedCiphers := make(map[uint16][]uint16)
	for version, supported := range supportedVersions {
		if version == tls.VersionTLS13 {
			supportedCiphers[version] = []uint16{}
			continue
		}
		if supported {
			supportedCiphers[version] = enumerateCiphers(e.HostName, e.Port, version)
		}
	}

	tlsRaw := &model.TLSRaw{}

	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10} {
		if supportedVersions[version] {

			config := &tls.Config{
				ServerName: e.HostName,
				MinVersion: version,
				MaxVersion: version,
			}

			connection, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", e.HostName, e.Port), config)
			if err != nil {
				continue
			}
			defer connection.Close()

			state := connection.ConnectionState()

			peerCerts := make([]*tlsmodel.TLSCertificate, len(state.PeerCertificates))

			for i, cert := range state.PeerCertificates {
				peerCerts[i] = &tlsmodel.TLSCertificate{
					Position:     i,
					SubjectDN:    cert.Subject.String(),
					IssuerDN:     cert.Issuer.String(),
					SerialNumber: cert.SerialNumber.String(),
					NotBefore:    cert.NotBefore,
					NotAfter:     cert.NotAfter,
					PublicKeyAlg: cert.PublicKeyAlgorithm.String(),
					SignatureAlg: cert.SignatureAlgorithm.String(),
					IsCA:         cert.IsCA,
					IsSelfSigned: IsSelfSigned(cert),
				}
			}

			// Set CipherSuite in supportedCiphers for TLS 1.3 to the negotiated cipher suite
			if state.Version == tls.VersionTLS13 {
				supportedCiphers[tls.VersionTLS13] = []uint16{state.CipherSuite}
			}

			tlsRaw.Host = e.HostName
			tlsRaw.Port = e.Port
			tlsRaw.SupportedTLSVersions = supportedVersions
			tlsRaw.SupportedCiphers = supportedCiphers
			tlsRaw.ServerName = state.ServerName
			tlsRaw.PeerCertificates = peerCerts
			break
		}
	}
	return *tlsRaw, nil
}

func enumerateTLSVersions(host string, port int) map[uint16]bool {
	supportedVersions := map[uint16]bool{
		tls.VersionTLS10: false,
		tls.VersionTLS11: false,
		tls.VersionTLS12: false,
		tls.VersionTLS13: false,
	}
	availableVersions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}

	for _, version := range availableVersions {
		config := &tls.Config{
			ServerName: host,
			MinVersion: version,
			MaxVersion: version,
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), config)
		if err == nil {
			state := conn.ConnectionState()
			switch version {
			case tls.VersionTLS10:
				if state.Version == tls.VersionTLS10 {
					supportedVersions[tls.VersionTLS10] = true
				}
			case tls.VersionTLS11:
				if state.Version == tls.VersionTLS11 {
					supportedVersions[tls.VersionTLS11] = true
				}
			case tls.VersionTLS12:
				if state.Version == tls.VersionTLS12 {
					supportedVersions[tls.VersionTLS12] = true
				}
			case tls.VersionTLS13:
				if state.Version == tls.VersionTLS13 {
					supportedVersions[tls.VersionTLS13] = true
				}
			}
			conn.Close()
		}
	}
	return supportedVersions
}

func enumerateCiphers(host string, port int, version uint16) []uint16 {
	availableCiphers := tls.CipherSuites()

	supportedCiphers := []uint16{}

	for _, cipher := range availableCiphers {
		config := &tls.Config{
			ServerName:   host,
			MinVersion:   version,
			MaxVersion:   version,
			CipherSuites: []uint16{cipher.ID},
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), config)
		if err != nil {
			continue
		} else {
			state := conn.ConnectionState()
			if state.Version == version && state.CipherSuite == cipher.ID {
				supportedCiphers = append(supportedCiphers, cipher.ID)
			}
		}
		conn.Close()
	}
	return supportedCiphers
}

func IsSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}
