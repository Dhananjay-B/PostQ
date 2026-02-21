/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"net"
	"os"
	"strconv"

	model "github.com/Dhananjay-B/PostQ/internal/model"
	probe "github.com/Dhananjay-B/PostQ/internal/probe"
	"github.com/spf13/cobra"
)

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh [host:port]",
	Short: "Scan SSH handshake with remote host",
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

		sshTarget := model.SSHTarget{
			HostName: host,
			Port:     port,
		}

		result, err := probe.ScanSSH(sshTarget)
		if err != nil {
			return err
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	},
}

func init() {
	scanCmd.AddCommand(sshCmd)
}
