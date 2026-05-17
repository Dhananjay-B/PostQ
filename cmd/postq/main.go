package main

import (
	"fmt"

	smtpmodels "github.com/Dhananjay-B/PostQ/internal/model/smtpmodels"
	probe "github.com/Dhananjay-B/PostQ/internal/probe"
)

func main() {
	target := smtpmodels.SMTPTarget{
		HostName: "192.168.1.28",
		Port:     587,
	}

	results, err := probe.ScanSMTP(target)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(results)
}
