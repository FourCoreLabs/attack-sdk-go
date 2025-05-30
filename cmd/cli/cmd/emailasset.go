package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	pkgAsset "github.com/fourcorelabs/attack-sdk-go/pkg/asset"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/asset"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
)

// emailAssetCmd represents the emailasset command
var emailAssetCmd = &cobra.Command{
	Use:   "emailasset",
	Short: "Email asset operations",
	Long:  `Commands for interacting with email assets in the FourCore platform.`,
}

// emailAssetListCmd represents the emailasset list command
var emailAssetListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List email assets",
	Long:    `Retrieves and displays email assets from the FourCore platform.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- Get Flags ---
		format, _ := cmd.Flags().GetString("format")

		// --- API Call ---
		assets, err := pkgAsset.GetEmailAssets(context.Background(), client)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			return fmt.Errorf("failed to retrieve email assets: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printEmailAssetsJSON(assets)
		case "table":
			fallthrough // Default to table
		default:
			printEmailAssetsTable(assets)
			return nil
		}
	},
}

// emailAssetGetCmd represents the emailasset get command
var emailAssetGetCmd = &cobra.Command{
	Use:   "get [asset_id]",
	Short: "Get email asset details",
	Long:  `Retrieves detailed information about a specific email asset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("email asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- Get Flags ---
		format, _ := cmd.Flags().GetString("format")

		// --- API Call ---
		asset, err := pkgAsset.GetEmailAsset(context.Background(), client, assetID)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("email asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to retrieve email asset: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printEmailAssetJSON(asset)
		default:
			printEmailAssetDetails(asset)
			return nil
		}
	},
}

// emailAssetCreateCmd represents the emailasset create command
var emailAssetCreateCmd = &cobra.Command{
	Use:   "create [email]",
	Short: "Create a new email asset",
	Long:  `Creates a new email asset in the FourCore platform.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		email := args[0]
		if email == "" {
			return fmt.Errorf("email address is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- Get Flags ---
		tags, _ := cmd.Flags().GetStringToString("tags")

		// --- API Call ---
		asset, err := pkgAsset.CreateEmailAsset(context.Background(), client, email, tags)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			return fmt.Errorf("failed to create email asset: %w", err)
		}

		// --- Output Success ---
		fmt.Printf("Successfully created email asset with ID: %s\n", asset.ID)
		return nil
	},
}

// emailAssetUpdateCmd represents the emailasset update command
var emailAssetUpdateCmd = &cobra.Command{
	Use:   "update [asset_id]",
	Short: "Update an email asset",
	Long:  `Updates an existing email asset in the FourCore platform.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("email asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- Get Flags ---
		email, _ := cmd.Flags().GetString("email")
		tags, _ := cmd.Flags().GetStringToString("tags")

		// --- API Call ---
		response, err := pkgAsset.UpdateEmailAsset(context.Background(), client, assetID, email, tags)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("email asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to update email asset: %w", err)
		}

		// --- Output Success ---
		if response.Success {
			fmt.Printf("Successfully updated email asset: %s\n", assetID)
		} else {
			fmt.Printf("No changes made to email asset: %s\n", assetID)
		}
		return nil
	},
}

// emailAssetDeleteCmd represents the emailasset delete command
var emailAssetDeleteCmd = &cobra.Command{
	Use:   "delete [asset_id]",
	Short: "Delete an email asset",
	Long:  `Deletes a specific email asset from the FourCore platform.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("email asset ID is required")
		}

		// Confirm deletion if confirm flag not set
		confirm, _ := cmd.Flags().GetBool("confirm")
		if !confirm {
			fmt.Printf("Are you sure you want to delete email asset %s? (y/N): ", assetID)
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
				fmt.Println("Deletion cancelled.")
				return nil
			}
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		response, err := pkgAsset.DeleteEmailAsset(context.Background(), client, assetID)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("email asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to delete email asset: %w", err)
		}

		// --- Output Success ---
		if response.Success {
			fmt.Printf("Successfully deleted email asset: %s\n", assetID)
		} else {
			fmt.Printf("No changes made to email asset: %s\n", assetID)
		}
		return nil
	},
}

// emailAssetVerifyCmd represents the emailasset verify command
var emailAssetVerifyCmd = &cobra.Command{
	Use:   "verify [asset_id]",
	Short: "Verify an email asset",
	Long:  `Sends a verification email to a specific email asset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("email asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		response, err := pkgAsset.VerifyEmailAsset(context.Background(), client, assetID)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("email asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to verify email asset: %w", err)
		}

		// --- Output Success ---
		if response.Success {
			fmt.Printf("Successfully sent verification email to: %s\n", assetID)
		} else {
			fmt.Printf("Failed to send verification email to: %s\n", assetID)
		}
		return nil
	},
}

// emailAssetAnalyticsCmd represents the emailasset analytics command
var emailAssetAnalyticsCmd = &cobra.Command{
	Use:   "analytics [asset_id]",
	Short: "Get email asset analytics",
	Long:  `Retrieves analytics data for a specific email asset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("email asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- Get Flags ---
		days, _ := cmd.Flags().GetInt("days")
		format, _ := cmd.Flags().GetString("format")

		// --- API Call ---
		analytics, err := pkgAsset.GetEmailAssetAnalytics(context.Background(), client, assetID, days)
		if err != nil {
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("email asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to retrieve email asset analytics: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			data, err := json.MarshalIndent(analytics, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to format JSON output: %w", err)
			}
			fmt.Println(string(data))
			return nil
		default:
			printEmailAssetAnalytics(analytics)
			return nil
		}
	},
}

// emailAssetGmailConfCodeCmd represents the emailasset gmail-conf-code command
var emailAssetGmailConfCodeCmd = &cobra.Command{
	Use:   "gmail-conf-code [asset_id]",
	Short: "Get Gmail confirmation code",
	Long:  `Retrieves the Gmail confirmation code for an email asset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("email asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		confCode, err := pkgAsset.GetGmailConfirmationCode(context.Background(), client, assetID)
		if err != nil {
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("email asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to retrieve Gmail confirmation code: %w", err)
		}

		// --- Output ---
		fmt.Printf("Gmail Confirmation Code: %s\n", confCode.Code)
		fmt.Printf("Verification Link: %s\n", confCode.Link)
		return nil
	},
}

func init() {
	// Add commands to the emailasset command
	emailAssetCmd.AddCommand(emailAssetListCmd)
	emailAssetCmd.AddCommand(emailAssetGetCmd)
	emailAssetCmd.AddCommand(emailAssetCreateCmd)
	emailAssetCmd.AddCommand(emailAssetUpdateCmd)
	emailAssetCmd.AddCommand(emailAssetDeleteCmd)
	emailAssetCmd.AddCommand(emailAssetVerifyCmd)
	emailAssetCmd.AddCommand(emailAssetAnalyticsCmd)
	emailAssetCmd.AddCommand(emailAssetGmailConfCodeCmd)

	// Add emailasset command to root command
	rootCmd.AddCommand(emailAssetCmd)

	// --- Common Flags ---
	// Format flag for commands that output data
	emailAssetListCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	emailAssetGetCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	emailAssetAnalyticsCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")

	// --- Command-specific Flags ---
	// Create command flags
	emailAssetCreateCmd.Flags().StringToStringP("tags", "t", nil, "Add tags (key=value)")

	// Update command flags
	emailAssetUpdateCmd.Flags().StringP("email", "e", "", "New email address")
	emailAssetUpdateCmd.Flags().StringToStringP("tags", "t", nil, "Update tags (key=value)")

	// Delete command flags
	emailAssetDeleteCmd.Flags().BoolP("confirm", "y", false, "Skip confirmation prompt")

	// Analytics command flags
	emailAssetAnalyticsCmd.Flags().IntP("days", "d", 30, "Number of days for analytics (max 60)")
}

// --- Helper Functions for Output Formatting ---

func printEmailAssetsTable(assets []asset.EmailAsset) {
	if len(assets) == 0 {
		fmt.Println("No email assets found.")
		return
	}

	// Create a new table with headers
	tbl := table.New("ID", "Email", "Available", "Disabled", "Verified")

	for _, asset := range assets {
		// Add row data
		tbl.AddRow(
			asset.ID,
			asset.Email,
			fmt.Sprintf("%t", asset.Available),
			fmt.Sprintf("%t", asset.Disabled),
			fmt.Sprintf("%t", asset.Verified),
		)
	}

	// Print the table to stdout
	tbl.Print()
}

func printEmailAssetsJSON(assets []asset.EmailAsset) error {
	jsonData, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func printEmailAssetJSON(asset asset.EmailAsset) error {
	jsonData, err := json.MarshalIndent(asset, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func printEmailAssetDetails(asset asset.EmailAsset) {
	fmt.Println("Email Asset Details:")
	fmt.Printf("ID:        %s\n", asset.ID)
	fmt.Printf("Email:     %s\n", asset.Email)
	fmt.Printf("Available: %t\n", asset.Available)
	fmt.Printf("Disabled:  %t\n", asset.Disabled)
	fmt.Printf("Verified:  %t\n", asset.Verified)

	if asset.CreatedAt != nil {
		fmt.Printf("Created At: %s\n", asset.CreatedAt.Format(time.RFC3339))
	}
	if asset.UpdatedAt != nil {
		fmt.Printf("Updated At: %s\n", asset.UpdatedAt.Format(time.RFC3339))
	}

	// Tags
	if len(asset.Tags) > 0 {
		fmt.Println("\nTags:")
		for k, v := range asset.Tags {
			fmt.Printf("  %s: %s\n", k, v)
		}
	} else {
		fmt.Println("\nTags: None")
	}
}

func printEmailAssetAnalytics(analytics asset.EmailAssetAnalytics) {
	fmt.Println("Email Asset Analytics Summary:")
	fmt.Printf("Total:    %d\n", analytics.Total)
	fmt.Printf("Successful: %d\n", analytics.Success)
	fmt.Printf("Detected: %d\n", analytics.Detected)

	if len(analytics.ActionSuccess) > 0 {
		fmt.Println("\nAction Success:")
		for action, count := range analytics.ActionSuccess {
			fmt.Printf("  %s: %d\n", action, count)
		}
	}

	if len(analytics.ExtSuccess) > 0 {
		fmt.Println("\nExtension Success:")
		for ext, count := range analytics.ExtSuccess {
			fmt.Printf("  %s: %d\n", ext, count)
		}
	}

	if len(analytics.MimeSuccess) > 0 {
		fmt.Println("\nMIME Type Success:")
		for mime, count := range analytics.MimeSuccess {
			fmt.Printf("  %s: %d\n", mime, count)
		}
	}
}
