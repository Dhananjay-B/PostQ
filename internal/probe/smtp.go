package probe

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	smtpmodels "github.com/Dhananjay-B/PostQ/internal/model/smtpmodels"
	tlsmodels "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"
)

func ScanSMTP(target smtpmodels.SMTPTarget) (smtpmodels.SMTPProbe, error) {

	var probeResponse smtpmodels.SMTPProbe

	connection, err := net.DialTimeout(
		"tcp",
		fmt.Sprintf("%s:%d", target.HostName, target.Port),
		5*time.Second,
	)

	if err != nil {
		return probeResponse, fmt.Errorf("smtp connection failed: %w", err)
	}

	defer connection.Close()

	reader := bufio.NewReader(connection)

	banner, err := reader.ReadString('\n')
	if err != nil {
		return probeResponse, fmt.Errorf("failed to read SMTP banner: %w", err)
	}

	banner = strings.TrimSpace(banner)

	bannerFields := strings.Split(banner, " ")

	if len(bannerFields) >= 4 {

		probeResponse.ServerHostName = bannerFields[1]

		if strings.Contains(bannerFields[2], "ESMTP") {
			probeResponse.ESMTPSupported = true
		}

		probeResponse.SMTPSoftware = strings.Join(bannerFields[3:], "")
	}

	_, err = connection.Write([]byte("EHLO POSTQ\r\n"))
	if err != nil {
		return probeResponse, fmt.Errorf("failed to send EHLO command: %w", err)
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return probeResponse, fmt.Errorf("failed to read EHLO response: %w", err)
		}

		line = strings.TrimSpace(line)

		if strings.Contains(line, "250-STARTTLS") {
			probeResponse.STARTTLSSupported = true
		}

		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	if !probeResponse.STARTTLSSupported {
		return probeResponse, nil
	}

	supportedVersions := enumerateSMTPTLSVersions(
		target.HostName,
		target.Port,
	)

	supportedCiphers := make(map[uint16][]uint16)

	for version, supported := range supportedVersions {

		if version == tls.VersionTLS13 {
			supportedCiphers[version] = []uint16{}
			continue
		}

		if supported {

			supportedCiphers[version] = enumerateSMTPCiphers(
				target.HostName,
				target.Port,
				version,
			)
		}
	}

	serverCipherPreferences := make(map[uint16]bool)

	for version, supported := range supportedVersions {

		if supported {
			serverCipherPreferences[version] = detectSMTPServerCipherPreference(target.HostName, target.Port, version, supportedCiphers[version])
		}
	}

	tlsProbe := &tlsmodels.TLSProbe{}

	for _, version := range []uint16{
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		tls.VersionTLS10,
	} {

		if !supportedVersions[version] {
			continue
		}

		tlsConn, err := establishSMTPSTARTTLSConnection(
			target.HostName,
			target.Port,
			version,
			nil,
		)

		if err != nil {
			continue
		}

		state := tlsConn.ConnectionState()

		peerCerts := make([]*tlsmodels.TLSCertificate, len(state.PeerCertificates))

		for i, cert := range state.PeerCertificates {

			peerCerts[i] = &tlsmodels.TLSCertificate{
				Position:        i,
				SubjectDN:       cert.Subject.String(),
				IssuerDN:        cert.Issuer.String(),
				OCSPServer:      cert.OCSPServer,
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

		if len(state.PeerCertificates) > 1 {

			leafCert := state.PeerCertificates[0]
			issuerCert := state.PeerCertificates[1]

			peerCerts[0].OCSPStatus = getOCSPStatus(
				leafCert,
				issuerCert,
			)
		}

		if state.Version == tls.VersionTLS13 {
			supportedCiphers[tls.VersionTLS13] =
				[]uint16{state.CipherSuite}
		}

		tlsProbe.Host = target.HostName
		tlsProbe.Port = target.Port
		tlsProbe.ServerName = state.ServerName
		tlsProbe.SupportedTLSVersions = supportedVersions
		tlsProbe.SupportedCiphers = supportedCiphers
		tlsProbe.ServerCipherPreference = serverCipherPreferences
		tlsProbe.PeerCertificates = peerCerts

		tlsConn.Close()

		break
	}

	probeResponse.SMTPTLSProbe = tlsProbe

	return probeResponse, nil
}

func enumerateSMTPTLSVersions(host string, port int) map[uint16]bool {

	supportedVersions := map[uint16]bool{
		tls.VersionTLS10: false,
		tls.VersionTLS11: false,
		tls.VersionTLS12: false,
		tls.VersionTLS13: false,
	}

	availableVersions := []uint16{
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
		tls.VersionTLS13,
	}

	for _, version := range availableVersions {

		tlsConn, err := establishSMTPSTARTTLSConnection(host, port, version, nil)

		if err != nil {
			continue
		}

		state := tlsConn.ConnectionState()

		if state.Version == version {
			supportedVersions[version] = true
		}

		tlsConn.Close()
	}

	return supportedVersions
}

func enumerateSMTPCiphers(host string, port int, version uint16) []uint16 {

	supportedCiphers := []uint16{}

	for _, cipher := range tls.CipherSuites() {

		tlsConn, err := establishSMTPSTARTTLSConnection(host, port, version, []uint16{cipher.ID})

		if err != nil {
			continue
		}

		state := tlsConn.ConnectionState()

		if state.Version == version && state.CipherSuite == cipher.ID {
			supportedCiphers = append(supportedCiphers, cipher.ID)
		}
		tlsConn.Close()
	}

	return supportedCiphers
}

func establishSMTPSTARTTLSConnection(host string, port int, version uint16, cipherSuites []uint16) (*tls.Conn, error) {

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)

	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)

	_, err = reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}

	_, err = conn.Write([]byte("EHLO POSTQ\r\n"))
	if err != nil {
		conn.Close()
		return nil, err
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}

		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	_, err = conn.Write([]byte("STARTTLS\r\n"))
	if err != nil {
		conn.Close()
		return nil, err
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}

	if !strings.HasPrefix(response, "220") {
		conn.Close()
		return nil, fmt.Errorf("STARTTLS rejected")
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       cipherSuites,
		InsecureSkipVerify: true,
	})

	err = tlsConn.Handshake()
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func detectSMTPServerCipherPreference(host string, port int, version uint16, cipherList []uint16) bool {

	if version >= tls.VersionTLS13 {
		return false
	}

	if len(cipherList) < 2 {
		return false
	}

	conn1, err := establishSMTPSTARTTLSConnection(host, port, version, cipherList)

	if err != nil {
		return false
	}

	negotiatedCipherSuite1 := conn1.ConnectionState().CipherSuite

	conn1.Close()

	reversedCipherList := make([]uint16, len(cipherList))

	j := 0

	for i := len(cipherList) - 1; i >= 0; i-- {
		reversedCipherList[j] = cipherList[i]
		j++
	}

	conn2, err := establishSMTPSTARTTLSConnection(host, port, version, reversedCipherList)

	if err != nil {
		return false
	}

	negotiatedCipherSuite2 := conn2.ConnectionState().CipherSuite

	conn2.Close()

	return negotiatedCipherSuite1 == negotiatedCipherSuite2
}
