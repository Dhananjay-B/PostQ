/*
Copyright © 2026 DHANANJAY BHUJBAL <dhananjay.bhujbal19@vit.edu>
*/
package cmd

import (
	"fmt"

	api "github.com/Dhananjay-B/PostQ/api"
	"github.com/spf13/cobra"
)

var serverCmdCmd = &cobra.Command{
	Use:   "server",
	Short: "Start PostQ API server",
	Long: `Start PostQ API server to provide quantum risk assessment as a service.
API server provides below endpoints
- /api/v1/scan/tls
- /api/v1/scan/ssh

Server will be available on port 8080.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := api.StartServer(); err != nil {
			return fmt.Errorf("failed to start API server: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serverCmdCmd)
}
