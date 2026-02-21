package main

import (
	"fmt"

	"github.com/Dhananjay-B/PostQ/internal/model"
	"github.com/Dhananjay-B/PostQ/internal/probe"
)

func main() {
	endpoint := model.Endpoint{
		HostName: "example.com",
		Port:     443,
	}

	_, err := probe.ScanTLS(endpoint)
	if err != nil {
		fmt.Println(err)
	}
	// fmt.Println(results)
}
