/*
Copyright © 2026 DHANANJAY BHUJBAL <dhananjay.bhujbal19@vit.edu>
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
	Long: `Scan SSH host to get cryptograhpic inventory.
SSH scan makes raw TCP connection to remote host on specified port and collects below information
- Kex Algorithms                       
- HostKey Algorithms                   
- EncryptionAlgorithms - ClientToServer  
- EncryptionAlgorithms - ServerToClient  
- MacAlgorithms - ClientToServer         
- MacAlgorithms - ServerToClient         
- CompressionAlgorithms - ClientToServer 
- CompressionAlgorithms - ServerToClient 
- Language - ClientToServer              
- Language - ServerToClient`,
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
