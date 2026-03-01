/*
Copyright © 2026 DHANANJAY BHUJBAL <dhananjay.bhujbal19@vit.edu>
*/
package cmd

import (
	"encoding/json"
	"net"
	"os"
	"strconv"

	tlsanalysis "github.com/Dhananjay-B/PostQ/internal/analysis/tlsanalysis"
	tlsmodels "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"
	probes "github.com/Dhananjay-B/PostQ/internal/probe"
	"github.com/spf13/cobra"
)

var assessTlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "Assess TLS endpoint for quantum risks",
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]

		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			return err
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return err
		}

		endpoint := tlsmodels.TLSTarget{
			HostName: host,
			Port:     port,
		}
		probe, err := probes.ScanTLS(endpoint)
		if err != nil {
			return err
		}
		risk := tlsanalysis.AnalyzeTLSProbe(probe)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(risk)
	},
}

func init() {
	assessCmd.AddCommand(assessTlsCmd)
}
