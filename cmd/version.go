/*
Copyright © 2026 DHANANJAY BHUJBAL <dhananjay.bhujbal19@vit.edu>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var version = "1.0.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		if version == "" {
			return fmt.Errorf("version not found")
		}
		_, err := fmt.Println(version)
		return err
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
