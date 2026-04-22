package tlsmodels

type TLSTarget struct {
	HostName string `json:"host_name"`
	Port     int    `json:"port"`
}
