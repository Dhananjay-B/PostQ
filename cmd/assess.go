/*
Copyright © 2026 DHANANJAY BHUJBAL <dhananjay.bhujbal19@vit.edu>
*/
package cmd

import (
	"github.com/spf13/cobra"
)

var assessCmd = &cobra.Command{
	Use:   "assess",
	Short: "Assess collected cryptographic inventory for quantum risks",
	Long:  `This will first perform scanning of specified target to get probe data and then assess for quantum risks.`,
}

func init() {
	rootCmd.AddCommand(assessCmd)
}
