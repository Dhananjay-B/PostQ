package tls

type ScanResult struct {
	ScanID      int    `json:"scan_id"`
	TLSVersion  string `json:"tls_version"`
	CipherSuite string `json:"cipher_suite"`
	ServerName  string `json:"server_name"`
}
