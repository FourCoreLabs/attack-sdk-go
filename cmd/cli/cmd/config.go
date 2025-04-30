package cmd

import (
	"fmt"
	"os"

	"github.com/fourcorelabs/attack-sdk-go/pkg/config"
	"github.com/spf13/cobra"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configure the CLI settings",
	Long:  `Manage CLI configuration settings like API Key and Base URL.`,
	// No RunE needed for the parent command if it only groups subcommands
}

// configViewCmd represents the config view command
var configViewCmd = &cobra.Command{
	Use:   "view",
	Short: "View current configuration",
	Long:  `Displays the current configuration settings, masking the API Key.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Note: cfg is populated in rootCmd's PersistentPreRunE
		fmt.Println("Current Configuration (Effective):")
		fmt.Printf("API Key: %s\n", maskString(cfg.APIKey)) // Use resolved value
		fmt.Printf("Base URL: %s\n", cfg.BaseURL)           // Use resolved value
		return nil
	},
}

// configSetCmd represents the config set command
var configSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set configuration values",
	Long:  `Sets specific configuration values like API Key or Base URL in the config file.`,
}

// configSetApiKeyCmd represents the config set api-key command
var configSetApiKeyCmd = &cobra.Command{
	Use:   "api-key [value]",
	Short: "Set the API key",
	Long:  `Saves the API key to the configuration file.`,
	Args:  cobra.ExactArgs(1), // Expect exactly one argument for the value
	RunE: func(cmd *cobra.Command, args []string) error {
		value := args[0]
		currentCfg, err := config.LoadConfig() // Load fresh from file for modification
		if err != nil && !os.IsNotExist(err) { // Ignore not exist error, means we create a new file
			return fmt.Errorf("failed to load config: %w", err)
		}

		currentCfg.APIKey = value
		if err := config.SaveConfig(currentCfg); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Println("API key updated successfully in config file.")
		return nil
	},
}

// configSetBaseUrlCmd represents the config set base-url command
var configSetBaseUrlCmd = &cobra.Command{
	Use:   "base-url [value]",
	Short: "Set the base URL",
	Long:  `Saves the base URL to the configuration file.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		value := args[0]
		currentCfg, err := config.LoadConfig() // Load fresh from file for modification
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to load config: %w", err)
		}

		currentCfg.BaseURL = value
		if err := config.SaveConfig(currentCfg); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Println("Base URL updated successfully in config file.")
		return nil
	},
}

func init() {
	// Add subcommands to the 'set' command
	configSetCmd.AddCommand(configSetApiKeyCmd)
	configSetCmd.AddCommand(configSetBaseUrlCmd)

	// Add subcommands ('set', 'view') to the 'config' command
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configViewCmd)

	// Add the 'config' command to the root command
	rootCmd.AddCommand(configCmd)
}
