/*
Copyright © 2026 DHANANJAY BHUJBAL <dhananjay.bhujbal19@vit.edu>
*/
package cmd

import (
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan cryptographic protocols",
	Long: `Scan protcols to get cryptographic inventory.
Currently supported porotocols
- HTTP/S, TLS
- SSH`,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
