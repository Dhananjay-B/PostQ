package probe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/Dhananjay-B/PostQ/internal/model"
	tlsdbmodel "github.com/Dhananjay-B/PostQ/internal/model/db/tls"
	tlsprobemodel "github.com/Dhananjay-B/PostQ/internal/model/probemodels"
)

var dialer = &net.Dialer{
	Timeout: 3 * time.Second,
}

func ScanTLS(e model.Endpoint) (tlsprobemodel.TLSRaw, error) {
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

	serverCipherPreferences := make(map[uint16]bool)
	for version, supported := range supportedVersions {
		if supported {
			serverCipherPreferences[version] = detectServerCipherPreference(e.HostName, e.Port, version, supportedCiphers[version])
		}
	}
	tlsRaw := &tlsprobemodel.TLSRaw{}

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

			peerCerts := make([]*tlsdbmodel.TLSCertificate, len(state.PeerCertificates))

			for i, cert := range state.PeerCertificates {
				peerCerts[i] = &tlsdbmodel.TLSCertificate{
					Position:        i,
					SubjectDN:       cert.Subject.String(),
					IssuerDN:        cert.Issuer.String(),
					SerialNumber:    cert.SerialNumber.String(),
					NotBefore:       cert.NotBefore,
					NotAfter:        cert.NotAfter,
					FullLifeTime:    int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24),
					LeftLifeTime:    int(time.Until(cert.NotAfter).Hours() / 24),
					PublicKeyAlg:    cert.PublicKeyAlgorithm.String(),
					PublicKeyLength: getPublicKeyLength(cert.PublicKey),
					SignatureAlg:    cert.SignatureAlgorithm.String(),
					IsCA:            cert.IsCA,
					IsSelfSigned:    IsSelfSigned(cert),
				}
			}

			// Set CipherSuite in supportedCiphers for TLS 1.3 to the negotiated cipher suite
			if state.Version == tls.VersionTLS13 {
				supportedCiphers[tls.VersionTLS13] = []uint16{state.CipherSuite}
			}

			tlsRaw.Host = e.HostName
			tlsRaw.Port = e.Port
			tlsRaw.SupportedTLSVersions = supportedVersions
			tlsRaw.ServerCipherPreference = serverCipherPreferences
			tlsRaw.ServerName = state.ServerName
			tlsRaw.PeerCertificates = peerCerts
			tlsRaw.SupportedCiphers = supportedCiphers

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

func detectServerCipherPreference(host string, port int, version uint16, cipherList []uint16) bool {

	if version >= tls.VersionTLS13 {
		return false
	}

	if len(cipherList) < 2 {
		return false
	}

	address := fmt.Sprintf("%s:%d", host, port)

	config1 := &tls.Config{
		ServerName:   host,
		MinVersion:   version,
		MaxVersion:   version,
		CipherSuites: cipherList,
	}

	conn1, err := tls.DialWithDialer(dialer, "tcp", address, config1)
	if err != nil {
		return false
	}
	negotiatedCipherSuite1 := conn1.ConnectionState().CipherSuite
	conn1.Close()

	reversedCipherList := make([]uint16, len(cipherList))
	j := 0
	for i := len(cipherList) - 1; i >= 0; i-- {
		reversedCipherList[j] = cipherList[i]
		j += 1
	}

	config2 := &tls.Config{
		ServerName:   host,
		MinVersion:   version,
		MaxVersion:   version,
		CipherSuites: reversedCipherList,
	}

	conn2, err := tls.DialWithDialer(dialer, "tcp", address, config2)
	if err != nil {
		return false
	}
	negotiatedCipherSuite2 := conn2.ConnectionState().CipherSuite
	conn2.Close()

	if negotiatedCipherSuite1 == negotiatedCipherSuite2 {
		return true
	} else {
		return false
	}

}

func IsSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}

func getPublicKeyLength(publicKey any) int {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	default:
		return 0
	}
}
