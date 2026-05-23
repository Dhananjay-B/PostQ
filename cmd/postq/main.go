package main

import (
	"encoding/json"
	"fmt"

	smtpmodels "github.com/Dhananjay-B/PostQ/internal/model/smtpmodels"
	probe "github.com/Dhananjay-B/PostQ/internal/probe"
)

func main() {

	target := smtpmodels.SMTPTarget{
		HostName: "smtp.gmail.com",
		Port:     587,
	}

	probeResponse, err := probe.ScanSMTP(target)
	if err != nil {
		fmt.Println(err)
		return
	}

	jsonOutput, err := json.MarshalIndent(
		probeResponse,
		"",
		"  ",
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(jsonOutput))
}
