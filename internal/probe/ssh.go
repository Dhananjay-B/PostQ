package probe

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	sshmodels "github.com/Dhananjay-B/PostQ/internal/model/sshmodels"
)

func ScanSSH(target sshmodels.SSHTarget) (sshmodels.SSHProbe, error) {

	var probeResponse sshmodels.SSHProbe

	connection, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.HostName, target.Port), 5*time.Second)
	if err != nil {
		return probeResponse, fmt.Errorf("ssh connection failed: %w", err)
	}

	_, err = connection.Write([]byte("SSH-2.0-POSTQ\r\n"))
	if err != nil {
		return probeResponse, fmt.Errorf("failed to send client banner: %w", err)
	}

	reader := bufio.NewReader(connection)

	_, err = reader.ReadString('\n')
	if err != nil {
		return probeResponse, fmt.Errorf("failed to read server banner: %w", err)
	}

	packetLength := make([]byte, 4)
	if _, err := io.ReadFull(reader, packetLength); err != nil {
		return probeResponse, fmt.Errorf("failed to read packet length: %w", err)
	}

	packet := make([]byte, binary.BigEndian.Uint32(packetLength))
	io.ReadFull(reader, packet)

	payload := packet[1 : len(packet)-int(packet[0])]

	offset := 1 + 16 // Skip message code and cookies

	probeResponse.KexAlgorithms, _ = readNameList(payload, &offset)
	probeResponse.HostKeyAlgorithms, _ = readNameList(payload, &offset)
	probeResponse.EncryptionAlgorithmsClientToServer, _ = readNameList(payload, &offset)
	probeResponse.EncryptionAlgorithmsServerToClient, _ = readNameList(payload, &offset)
	probeResponse.MacAlgorithmsClientToServer, _ = readNameList(payload, &offset)
	probeResponse.MacAlgorithmsServerToClient, _ = readNameList(payload, &offset)
	probeResponse.CompressionAlgorithmsClientToServer, _ = readNameList(payload, &offset)
	probeResponse.CompressionAlgorithmsServerToClient, _ = readNameList(payload, &offset)
	probeResponse.LanguageClientToServer, _ = readNameList(payload, &offset)
	probeResponse.LanguageServerToClient, _ = readNameList(payload, &offset)

	return probeResponse, nil
}

func readNameList(payload []byte, offset *int) ([]string, error) {
	if *offset+4 > len(payload) {
		return nil, fmt.Errorf("invalid offset for name list")
	}
	length := int(binary.BigEndian.Uint32(payload[*offset : *offset+4]))
	*offset += 4

	if *offset+length > len(payload) {
		return nil, fmt.Errorf("invalid length for name list")
	}

	if length == 0 {
		return []string{}, nil
	}
	names := string(payload[*offset : *offset+length])

	*offset += length

	return strings.Split(names, ","), nil
}
