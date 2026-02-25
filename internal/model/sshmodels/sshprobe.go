package sshmodels

type SSHProbe struct {
	KexAlgorithms                       []string
	HostKeyAlgorithms                   []string
	EncryptionAlgorithmsClientToServer  []string
	EncryptionAlgorithmsServerToClient  []string
	MacAlgorithmsClientToServer         []string
	MacAlgorithmsServerToClient         []string
	CompressionAlgorithmsClientToServer []string
	CompressionAlgorithmsServerToClient []string
	LanguageClientToServer              []string
	LanguageServerToClient              []string
}
