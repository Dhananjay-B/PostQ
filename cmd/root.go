/*
Copyright © 2026 DHANANJAY BHUJBAL <dhananjay.bhujbal19@vit.edu>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "PostQ",
	Short: "Network cryptography inventory tool for evaluating post-quantum risk exposure.",
	Long: `PostQ is a tool for discovering and inventorying network cryptographic assets with a focus on post-quantum risk assessment.
PostQ discovers what is deployed, not what is intended.
Current scope include below network assets
- TLS/HTTPS endpoint
- SSH
- Email infrastructure`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
