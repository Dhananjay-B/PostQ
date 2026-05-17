package smtpmodels

type SMTPTarget struct {
	HostName string `json:"host_name"`
	Port     int    `json:"port"`
}
