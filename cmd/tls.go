/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"net"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	model "github.com/Dhananjay-B/PostQ/internal/model"
	probe "github.com/Dhananjay-B/PostQ/internal/probe"
)

// tlsCmd represents the tls command
var tlsCmd = &cobra.Command{
	Use:   "tls [endpoint:port]",
	Short: "Scan TLS endpoint",
	Args:  cobra.ExactArgs(1),
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

		endpoint := model.Endpoint{
			HostName: host,
			Port:     port,
		}
		result, err := probe.ScanTLS(endpoint)
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
