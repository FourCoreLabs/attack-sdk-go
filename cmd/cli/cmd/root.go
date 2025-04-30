package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/fourcorelabs/attack-sdk-go/pkg/config"
	"github.com/spf13/cobra"
)

var (
	// These will hold the resolved values after considering flags, env vars, and config file
	cfg        config.Config
	apiKeyVal  string
	baseUrlVal string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "fourcore-cli",
	Version: "0.2.0", // Updated version maybe
	Short:   "CLI for FourCore ATTACK REST API",
	Long: `A command-line interface to interact with the FourCore ATTACK REST API,
allowing management and retrieval of various resources like audit logs.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load config from file first
		loadedCfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("failed to load config file: %w", err)
		}
		cfg = loadedCfg // Store loaded config

		// Determine effective API Key: Flag > Env Var > Config File
		apiKeyFromFlag, _ := cmd.Flags().GetString("api-key")
		apiKeyFromEnv := os.Getenv("FOURCORE_API_KEY")

		if apiKeyFromFlag != "" {
			apiKeyVal = apiKeyFromFlag
		} else if apiKeyFromEnv != "" {
			apiKeyVal = apiKeyFromEnv
		} else {
			apiKeyVal = cfg.APIKey // Use from loaded config
		}

		// Determine effective Base URL: Flag > Env Var > Config File > Default
		baseUrlFromFlag, _ := cmd.Flags().GetString("base-url")
		baseUrlFromEnv := os.Getenv("FOURCORE_BASE_URL")

		if baseUrlFromFlag != "" {
			baseUrlVal = baseUrlFromFlag
		} else if baseUrlFromEnv != "" {
			baseUrlVal = baseUrlFromEnv
		} else if cfg.BaseURL != "" {
			baseUrlVal = cfg.BaseURL // Use from loaded config
		} else {
			baseUrlVal = "https://prod.fourcore.io" // Default
		}

		// Update the global cfg struct *if* flags/env were used,
		// so subcommands using it directly (like config view) see the effective values
		cfg.APIKey = apiKeyVal
		cfg.BaseURL = baseUrlVal

		// Optional: You could store the resolved values in the command's context
		// ctx := context.WithValue(cmd.Context(), configKey{}, cfg)
		// cmd.SetContext(ctx) // Requires defining a configKey type

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	// Set version template
	rootCmd.SetVersionTemplate(`{{printf "%s %s\n" .Name .Version}}`)
	return rootCmd.ExecuteContext(context.Background())
}

func init() {
	// Define persistent flags valid for all subcommands
	rootCmd.PersistentFlags().StringP("api-key", "k", "", "API Key for authentication (env: FOURCORE_API_KEY)")
	rootCmd.PersistentFlags().StringP("base-url", "u", "", "Base URL for the API (env: FOURCORE_BASE_URL)")

	// Add subcommands (will be done in their respective files, e.g., config.go, audit.go)
	// Example: addConfigCmd()
	// Example: addAuditCmd()
}

// Helper function (can be moved to a utils file later)
func maskString(s string) string {
	if s == "" {
		return "<not set>"
	}
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	// Show first 4 and last 4 characters
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}
