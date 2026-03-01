package main

import (
	"fmt"

	tlsanalysis "github.com/Dhananjay-B/PostQ/internal/analysis/tlsanalysis"
	tlsmodels "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"
	probe "github.com/Dhananjay-B/PostQ/internal/probe"
)

func main() {
	target := tlsmodels.TLSTarget{
		HostName: "example.com",
		Port:     443,
	}

	results, err := probe.ScanTLS(target)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tlsanalysis.AnalyzeTLSProbe(results))
}
