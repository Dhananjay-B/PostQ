package main

import (
	"github.com/Dhananjay-B/PostQ/internal/model"
	"github.com/Dhananjay-B/PostQ/internal/probe"
)

func main() {
	// endpoint := model.Endpoint{
	// 	HostName: "google.com",
	// 	Port:     443,
	// }

	// result, err := probe.ScanTLS(endpoint)
	// if err != nil {
	// 	fmt.Println("Error scanning TLS:", err)
	// 	return
	// }
	// fmt.Println("TLS Scan Result:", result)

	sshTarget := model.SSHTarget{
		HostName: "192.168.1.2",
		Port:     22,
	}
	probe.ScanSSH(sshTarget)
}
