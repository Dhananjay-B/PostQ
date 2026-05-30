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

	"github.com/Dhananjay-B/PostQ/internal/analysis/smtpanalysis"
	smtpmodels "github.com/Dhananjay-B/PostQ/internal/model/smtpmodels"
	probes "github.com/Dhananjay-B/PostQ/internal/probe"
)

var assessSMTP bool

// smtpCmd represents the smtp command
var smtpCmd = &cobra.Command{
	Use:   "smtp [host:port]",
	Short: "Scan SMTP endpoint with STARTTLS support",
	Long: `Scan SMTP host to get cryptographic inventory.
SMTP scan makes raw TCP connection to remote host on specified port and collects below information
- SMTP Banner
- SMTP Software
- ESMTP Support
- STARTTLS Support
- Supported TLS Versions
- Supported Cipher Suites
- Server Cipher Preference
- Certificate Chain
- OCSP Status`,
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

		smtpTarget := smtpmodels.SMTPTarget{
			HostName: host,
			Port:     port,
		}

		probe, err := probes.ScanSMTP(smtpTarget)
		if err != nil {
			return err
		}

		if assessSMTP {
			risks, err := smtpanalysis.AnalyzeSMTPProbe(probe)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(risks)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		return enc.Encode(probe)
	},
}

func init() {
	scanCmd.AddCommand(smtpCmd)

	smtpCmd.Flags().BoolVar(
		&assessSMTP,
		"assess",
		false,
		"Run quantum risk assessment on scan result",
	)
}
