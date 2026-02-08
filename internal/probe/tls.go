package probe

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/Dhananjay-B/PostQ/internal/model"
	tlsmodel "github.com/Dhananjay-B/PostQ/internal/model/db/tls"
)

func ScanTLS(e model.Endpoint) (model.TLSRaw, error) {

	config := &tls.Config{
		ServerName: e.HostName,
	}

	connection, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", e.HostName, e.Port), config)
	if err != nil {
		return model.TLSRaw{}, err
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

	tlsRaw := &model.TLSRaw{
		Host:             e.HostName,
		Port:             e.Port,
		Version:          tls.VersionName(state.Version),
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		ServerName:       state.ServerName,
		PeerCertificates: peerCerts,
	}
	return *tlsRaw, nil
}

func IsSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}
