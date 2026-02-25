/*
Copyright © 2026 DHANANJAY BHUJBAL <dhananjay.bhujbal19@vit.edu>
*/
package cmd

import (
	"encoding/json"
	"net"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	tlsmodels "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"
	probes "github.com/Dhananjay-B/PostQ/internal/probe"
)

var tlsCmd = &cobra.Command{
	Use:   "tls [endpoint:port]",
	Short: "Scan TLS endpoint",
	Long: `Scan TLS endpoint to get cryptograhpic inventory.
TLS scan performs enumerated scanning and provides complete set of supported cryptogrphic algorithms/verions for
- Supported TLS Versions
- SupportedCiphers
- Peer Certificates`,
	Args: cobra.ExactArgs(1),
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
		result, err := probes.ScanTLS(endpoint)
		if err != nil {
			return err
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	},
}

func init() {
	scanCmd.AddCommand(tlsCmd)
}
