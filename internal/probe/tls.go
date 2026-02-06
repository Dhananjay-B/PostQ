package probe

import (
	"crypto/tls"
	"fmt"

	"github.com/Dhananjay-B/PostQ/internal/model"
)

func ScanTLS(e model.Endpoint) (model.TLSRaw, error) {
	fmt.Println(e)

	config := &tls.Config{
		ServerName: e.HostName,
	}

	connection, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", e.HostName, e.Port), config)
	if err != nil {
		return model.TLSRaw{}, err
	}
	defer connection.Close()

	state := connection.ConnectionState()

	tlsRaw := &model.TLSRaw{
		Host:		      e.HostName,
		Port:			  e.Port,
		Version:          tls.VersionName(state.Version),
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		ServerName:       state.ServerName,
		PeerCertificates: state.PeerCertificates,
	}

	return *tlsRaw, nil
}
