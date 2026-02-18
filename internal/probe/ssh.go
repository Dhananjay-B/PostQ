package probe

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	model "github.com/Dhananjay-B/PostQ/internal/model"
	sshprobemodel "github.com/Dhananjay-B/PostQ/internal/model/probemodels"
)

func ScanSSH(target model.SSHTarget) {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.HostName, target.Port), 5*time.Second)
	if err != nil {
		fmt.Println("Error connecting to SSH server:", err)
		return
	}

	connection.Write([]byte("SSH-2.0-POSTQ\r\n"))

	reader := bufio.NewReader(connection)
	hostVersion, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading SSH host version:", err)
		return
	}
	fmt.Println("SSH Host Version:", hostVersion)

	packetLength := make([]byte, 4)
	io.ReadFull(reader, packetLength)

	packet := make([]byte, binary.BigEndian.Uint32(packetLength))
	io.ReadFull(reader, packet)

	payload := packet[1 : len(packet)-int(packet[0])]

	offset := 1 + 16 // Skip message code and cookies

	probeResponse := &sshprobemodel.SSHAlgorithms{}

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

	fmt.Printf("SSH Probe Response: %+v\n", probeResponse)
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
