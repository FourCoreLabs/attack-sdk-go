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
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/asset"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
)

// assetCmd represents the asset command
var assetCmd = &cobra.Command{
	Use:   "asset",
	Short: "Asset operations",
	Long:  `Commands for interacting with assets in the FourCore platform.`,
}

// assetListCmd represents the asset list command
var assetListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List assets",
	Long:    `Retrieves and displays assets from the FourCore platform.`,
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
		connected, _ := cmd.Flags().GetBool("connected")
		available, _ := cmd.Flags().GetBool("available")

		// --- API Call with filtering ---
		opts := pkgAsset.GetAssetsOpts{
			Connected: connected,
			Available: available,
		}

		assets, err := pkgAsset.GetFilteredAssets(context.Background(), client, opts)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			return fmt.Errorf("failed to retrieve assets: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printAssetsJSON(assets)
		case "table":
			fallthrough // Default to table
		default:
			printAssetsTable(assets)
			return nil
		}
	},
}

// assetGetCmd represents the asset get command
var assetGetCmd = &cobra.Command{
	Use:   "get [asset_id]",
	Short: "Get asset details",
	Long:  `Retrieves detailed information about a specific asset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- Get Flags ---
		format, _ := cmd.Flags().GetString("format")

		// --- API Call ---
		asset, err := pkgAsset.GetAsset(context.Background(), client, assetID)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to retrieve asset: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printAssetJSON(asset)
		default:
			printAssetDetails(asset)
			return nil
		}
	},
}

// assetEnableCmd represents the asset enable command
var assetEnableCmd = &cobra.Command{
	Use:   "enable [asset_id]",
	Short: "Enable an asset",
	Long:  `Enables a specific asset in the FourCore platform.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		response, err := pkgAsset.EnableAsset(context.Background(), client, assetID)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to enable asset: %w", err)
		}

		// --- Output Success ---
		if response.Success {
			fmt.Printf("Successfully enabled asset: %s\n", assetID)
		} else {
			fmt.Printf("No changes made to asset: %s\n", assetID)
		}
		return nil
	},
}

// assetDisableCmd represents the asset disable command
var assetDisableCmd = &cobra.Command{
	Use:   "disable [asset_id]",
	Short: "Disable an asset",
	Long:  `Disables a specific asset in the FourCore platform.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		response, err := pkgAsset.DisableAsset(context.Background(), client, assetID)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to disable asset: %w", err)
		}

		// --- Output Success ---
		if response.Success {
			fmt.Printf("Successfully disabled asset: %s\n", assetID)
		} else {
			fmt.Printf("No changes made to asset: %s\n", assetID)
		}
		return nil
	},
}

// assetDeleteCmd represents the asset delete command
var assetDeleteCmd = &cobra.Command{
	Use:   "delete [asset_id]",
	Short: "Delete an asset",
	Long:  `Deletes a specific asset from the FourCore platform.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("asset ID is required")
		}

		// Confirm deletion if confirm flag not set
		confirm, _ := cmd.Flags().GetBool("confirm")
		if !confirm {
			fmt.Printf("Are you sure you want to delete asset %s? (y/N): ", assetID)
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
		response, err := pkgAsset.DeleteAsset(context.Background(), client, assetID)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to delete asset: %w", err)
		}

		// --- Output Success ---
		if response.Success {
			fmt.Printf("Successfully deleted asset: %s\n", assetID)
		} else {
			fmt.Printf("No changes made to asset: %s\n", assetID)
		}
		return nil
	},
}

// assetTagsCmd represents the asset tags command
var assetTagsCmd = &cobra.Command{
	Use:   "tags [asset_id]",
	Short: "Manage asset tags",
	Long:  `View and modify tags for a specific asset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// Get asset to view current tags
		asset, err := pkgAsset.GetAsset(context.Background(), client, assetID)
		if err != nil {
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to retrieve asset: %w", err)
		}

		// Get tag operations from flags
		add, _ := cmd.Flags().GetStringToString("add")
		remove, _ := cmd.Flags().GetStringArray("remove")
		clear, _ := cmd.Flags().GetBool("clear")

		// If no operations, just display current tags
		if len(add) == 0 && len(remove) == 0 && !clear {
			fmt.Println("Current tags:")
			if len(asset.Tags) == 0 {
				fmt.Println("  No tags set")
			} else {
				for k, v := range asset.Tags {
					fmt.Printf("  %s: %s\n", k, v)
				}
			}
			return nil
		}

		// Start with the current tags or an empty map
		newTags := make(map[string]string)
		if !clear {
			for k, v := range asset.Tags {
				newTags[k] = v
			}
		}

		// Add new tags
		for k, v := range add {
			newTags[k] = v
		}

		// Remove tags
		for _, k := range remove {
			delete(newTags, k)
		}

		// Update tags
		response, err := pkgAsset.SetAssetTags(context.Background(), client, assetID, newTags)
		if err != nil {
			return fmt.Errorf("failed to update tags: %w", err)
		}

		// --- Output Success ---
		if response.Success {
			fmt.Println("Successfully updated tags.")
			fmt.Println("New tags:")
			for k, v := range response.Tags.Tags {
				fmt.Printf("  %s: %s\n", k, v)
			}
		} else {
			fmt.Println("Failed to update tags.")
		}
		return nil
	},
}

// assetAnalyticsCmd represents the asset analytics command
var assetAnalyticsCmd = &cobra.Command{
	Use:   "analytics [asset_id]",
	Short: "Get asset analytics",
	Long:  `Retrieves analytics data for a specific asset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("asset ID is required")
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
		analytics, err := pkgAsset.GetAssetAnalytics(context.Background(), client, assetID, days)
		if err != nil {
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to retrieve analytics: %w", err)
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
			printAssetAnalytics(analytics)
			return nil
		}
	},
}

// assetAttacksCmd represents the asset attacks command
var assetAttacksCmd = &cobra.Command{
	Use:   "attacks [asset_id]",
	Short: "List asset attacks",
	Long:  `Retrieves attack executions performed on a specific asset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- Get Flags ---
		size, _ := cmd.Flags().GetInt("size")
		offset, _ := cmd.Flags().GetInt("offset")
		order, _ := cmd.Flags().GetString("order")
		name, _ := cmd.Flags().GetString("name")
		format, _ := cmd.Flags().GetString("format")

		// --- API Call ---
		opts := pkgAsset.GetAssetAttacksOpts{
			Size:   size,
			Offset: offset,
			Order:  strings.ToUpper(order),
			Name:   name,
		}

		attacks, err := pkgAsset.GetAssetAttacks(context.Background(), client, assetID, opts)
		if err != nil {
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to retrieve attacks: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			data, err := json.MarshalIndent(attacks, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to format JSON output: %w", err)
			}
			fmt.Println(string(data))
			return nil
		default:
			printAssetAttacks(attacks)
			return nil
		}
	},
}

// assetExecutionsCmd represents the asset executions command
var assetExecutionsCmd = &cobra.Command{
	Use:   "executions [asset_id]",
	Short: "List asset executions",
	Long:  `Retrieves execution reports for a specific asset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- Get Flags ---
		size, _ := cmd.Flags().GetInt("size")
		offset, _ := cmd.Flags().GetInt("offset")
		order, _ := cmd.Flags().GetString("order")
		name, _ := cmd.Flags().GetString("name")
		format, _ := cmd.Flags().GetString("format")

		// --- API Call ---
		opts := pkgAsset.GetAssetExecutionsOpts{
			Size:   size,
			Offset: offset,
			Order:  strings.ToUpper(order),
			Name:   name,
		}

		executions, err := pkgAsset.GetAssetExecutions(context.Background(), client, assetID, opts)
		if err != nil {
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to retrieve executions: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			data, err := json.MarshalIndent(executions, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to format JSON output: %w", err)
			}
			fmt.Println(string(data))
			return nil
		default:
			printAssetExecutions(executions)
			return nil
		}
	},
}

// assetPacksCmd represents the asset packs command
var assetPacksCmd = &cobra.Command{
	Use:   "packs [asset_id]",
	Short: "List asset assessment reports",
	Long:  `Retrieves assessment reports for a specific asset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		assetID := args[0]
		if assetID == "" {
			return fmt.Errorf("asset ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- Get Flags ---
		size, _ := cmd.Flags().GetInt("size")
		offset, _ := cmd.Flags().GetInt("offset")
		order, _ := cmd.Flags().GetString("order")
		name, _ := cmd.Flags().GetString("name")
		format, _ := cmd.Flags().GetString("format")

		// --- API Call ---
		opts := pkgAsset.GetAssetExecutionsOpts{
			Size:   size,
			Offset: offset,
			Order:  strings.ToUpper(order),
			Name:   name,
		}

		packs, err := pkgAsset.GetAssetPacks(context.Background(), client, assetID, opts)
		if err != nil {
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("asset not found: %s", assetID)
			}
			return fmt.Errorf("failed to retrieve packs: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			data, err := json.MarshalIndent(packs, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to format JSON output: %w", err)
			}
			fmt.Println(string(data))
			return nil
		default:
			printAssetPacks(packs)
			return nil
		}
	},
}

func init() {
	// Add commands to the asset command
	assetCmd.AddCommand(assetListCmd)
	assetCmd.AddCommand(assetGetCmd)
	assetCmd.AddCommand(assetEnableCmd)
	assetCmd.AddCommand(assetDisableCmd)
	assetCmd.AddCommand(assetDeleteCmd)
	assetCmd.AddCommand(assetTagsCmd)
	assetCmd.AddCommand(assetAnalyticsCmd)
	assetCmd.AddCommand(assetAttacksCmd)
	assetCmd.AddCommand(assetExecutionsCmd)
	assetCmd.AddCommand(assetPacksCmd)

	// Add asset command to root command
	rootCmd.AddCommand(assetCmd)

	// --- Common Flags ---
	// Format flag for all commands that output data
	assetListCmd.Flags().BoolP("connected", "c", false, "Show only connected assets")
	assetListCmd.Flags().BoolP("available", "a", false, "Show only available assets")
	assetListCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	assetGetCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	assetAnalyticsCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	assetAttacksCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	assetExecutionsCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	assetPacksCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")

	// --- Command-specific Flags ---
	// Delete command flags
	assetDeleteCmd.Flags().BoolP("confirm", "y", false, "Skip confirmation prompt")

	// Tags command flags
	assetTagsCmd.Flags().StringToStringP("add", "a", nil, "Add or update tags (key=value)")
	assetTagsCmd.Flags().StringArrayP("remove", "r", nil, "Remove tags (key)")
	assetTagsCmd.Flags().BoolP("clear", "c", false, "Clear all existing tags before applying changes")

	// Analytics command flags
	assetAnalyticsCmd.Flags().IntP("days", "d", 30, "Number of days for analytics (max 30)")

	// Common pagination flags for attacks, executions, and packs commands
	for _, cmd := range []*cobra.Command{assetAttacksCmd, assetExecutionsCmd, assetPacksCmd} {
		cmd.Flags().IntP("size", "s", 10, "Number of items to retrieve")
		cmd.Flags().IntP("offset", "o", 0, "Offset for pagination")
		cmd.Flags().StringP("order", "r", "DESC", "Order of items (ASC or DESC)")
		cmd.Flags().StringP("name", "n", "", "Filter by name")
	}
}

// --- Helper Functions for Output Formatting ---

func printAssetsTable(assets []asset.Asset) {
	if len(assets) == 0 {
		fmt.Println("No assets found.")
		return
	}

	// Create a new table with headers
	tbl := table.New("ID", "Hostname", "IP Address", "OS", "Available", "Connected", "Disabled")

	for _, asset := range assets {
		hostname := "N/A"
		ipAddr := "N/A"
		os := "N/A"

		if asset.SystemInfo != nil {
			hostname = asset.SystemInfo.Hostname
			ipAddr = asset.SystemInfo.IPAddr
			os = asset.SystemInfo.OS
		}

		// Add row data
		tbl.AddRow(
			asset.ID,
			hostname,
			ipAddr,
			os,
			fmt.Sprintf("%t", asset.Available),
			fmt.Sprintf("%t", asset.Connected),
			fmt.Sprintf("%t", asset.Disabled),
		)
	}

	// Print the table to stdout
	tbl.Print()
}

func printAssetsJSON(assets []asset.Asset) error {
	jsonData, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func printAssetJSON(asset asset.Asset) error {
	jsonData, err := json.MarshalIndent(asset, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func printAssetDetails(asset asset.Asset) {
	fmt.Println("Asset Details:")
	fmt.Printf("ID:              %s\n", asset.ID)
	fmt.Printf("Available:       %t\n", asset.Available)
	fmt.Printf("Connected:       %t\n", asset.Connected)
	fmt.Printf("Disabled:        %t\n", asset.Disabled)
	fmt.Printf("Elevated:        %t\n", asset.Elevated)
	fmt.Printf("Version:         %s\n", asset.Version)

	if asset.CreatedAt != nil {
		fmt.Printf("Created At:      %s\n", asset.CreatedAt.Format(time.RFC3339))
	}
	if asset.UpdatedAt != nil {
		fmt.Printf("Updated At:      %s\n", asset.UpdatedAt.Format(time.RFC3339))
	}

	// Organization
	if asset.OrgID != nil {
		fmt.Printf("Organization ID: %d\n", *asset.OrgID)
	}
	if asset.OrgName != nil && *asset.OrgName != "" {
		fmt.Printf("Organization:    %s\n", *asset.OrgName)
	}

	// System Info
	if asset.SystemInfo != nil {
		fmt.Println("\nSystem Information:")
		fmt.Printf("  Hostname:        %s\n", asset.SystemInfo.Hostname)
		fmt.Printf("  IP Address:      %s\n", asset.SystemInfo.IPAddr)
		fmt.Printf("  OS:              %s\n", asset.SystemInfo.OS)
		fmt.Printf("  Kernel:          %s\n", asset.SystemInfo.Kernel)
		fmt.Printf("  Architecture:    %s\n", asset.SystemInfo.Arch)
		fmt.Printf("  Version:         %s\n", asset.SystemInfo.Version)
		fmt.Printf("  Machine Type:    %s\n", asset.SystemInfo.MachineType)
		fmt.Printf("  Manufacturer:    %s\n", asset.SystemInfo.Manufacturer)
		fmt.Printf("  Model:           %s\n", asset.SystemInfo.Model)
		fmt.Printf("  CPU Count:       %d\n", asset.SystemInfo.CPU)
		fmt.Printf("  Running Proc:    %d\n", asset.SystemInfo.RunningProc)
		fmt.Printf("  Memory:          %s / %s\n", asset.SystemInfo.FreeMemory, asset.SystemInfo.TotalMemory)
		fmt.Printf("  Disk Space:      %s / %s\n", asset.SystemInfo.FreeDiskSpace, asset.SystemInfo.TotalDiskSpace)

		// Domain Info
		if asset.SystemInfo.DomainInfo != nil {
			fmt.Println("\nDomain Information:")
			fmt.Printf("  Joined:          %t\n", asset.SystemInfo.DomainInfo.Joined)
			fmt.Printf("  Name:            %s\n", asset.SystemInfo.DomainInfo.Name)
			fmt.Printf("  DNS Domain:      %s\n", asset.SystemInfo.DomainInfo.DnsDomainName)
			fmt.Printf("  DNS Forest:      %s\n", asset.SystemInfo.DomainInfo.DnsForestName)
		}

		// Users
		if len(asset.SystemInfo.Users) > 0 {
			fmt.Println("\nSystem Users:")
			for i, user := range asset.SystemInfo.Users {
				if i < 5 { // Limit to first 5 users to avoid overwhelming output
					fmt.Printf("  - %s (%s)\n", user.Username, user.Name)
				}
			}
			if len(asset.SystemInfo.Users) > 5 {
				fmt.Printf("  ... and %d more users\n", len(asset.SystemInfo.Users)-5)
			}
		}
	}

	// EDR
	if len(asset.EDR) > 0 {
		fmt.Println("\nEDR Solutions:")
		for _, edr := range asset.EDR {
			fmt.Printf("  - %s\n", edr.EDRType)
		}
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

	// Users associated with asset
	if len(asset.Users) > 0 {
		fmt.Println("\nAssociated Users:")
		for _, user := range asset.Users {
			fmt.Printf("  - %s (%s)\n", user.Name, user.Type)
		}
	}
}

// Add these functions to cmd/cli/cmd/asset.go

func printAssetAnalytics(analytics asset.AssetAnalytics) {
	fmt.Println("Asset Analytics Summary:")
	fmt.Printf("Total Attacks:    %d\n", analytics.Total)
	fmt.Printf("Successful:       %d\n", analytics.Success)
	fmt.Printf("Detected:         %d\n", analytics.Detected)

	detectionRate := 0.0
	if analytics.Total > 0 {
		detectionRate = float64(analytics.Detected) / float64(analytics.Total) * 100
	}
	fmt.Printf("Detection Rate:   %.1f%%\n", detectionRate)

	fmt.Println("\nCorrelation Types:")
	fmt.Printf("  Alerts:         %d\n", analytics.CorrelationType.Alerts)
	fmt.Printf("  Queries:        %d\n", analytics.CorrelationType.Queries)

	if len(analytics.IntegrationType) > 0 {
		fmt.Println("\nIntegration Types:")
		for _, integration := range analytics.IntegrationType {
			fmt.Printf("  %s: %d\n", integration.IntegrationType, integration.Count)
		}
	}
}

func printAssetAttacks(attacks models.ListWithCount) {
	if attacks.Count == 0 || len(attacks.Data) == 0 {
		fmt.Println("No attacks found for this asset.")
		return
	}

	fmt.Printf("Total Attacks: %d\n\n", attacks.Count)

	// Create a new table with headers
	tbl := table.New("ID", "Action", "Status", "Severity", "Detected", "Success")

	for _, data := range attacks.Data {
		// We need to convert the interface{} to a map to access the fields
		attackMap, ok := data.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract values with defaults for missing fields
		id := getStringOrDefault(attackMap, "id", "N/A")
		action := getStringOrDefault(attackMap, "action_id", "N/A")
		status := getStringOrDefault(attackMap, "status", "N/A")
		severity := getStringOrDefault(attackMap, "severity", "N/A")

		// Handle boolean fields
		detected := "No"
		if val, ok := attackMap["detected"].(bool); ok && val {
			detected = "Yes"
		}

		success := "No"
		if val, ok := attackMap["success"].(bool); ok && val {
			success = "Yes"
		}

		// Add row data
		tbl.AddRow(id, action, status, severity, detected, success)
	}

	// Print the table to stdout
	tbl.Print()
}

func printAssetExecutions(executions models.ListWithCount) {
	if executions.Count == 0 || len(executions.Data) == 0 {
		fmt.Println("No executions found for this asset.")
		return
	}

	fmt.Printf("Total Executions: %d\n\n", executions.Count)

	// Create a new table with headers
	tbl := table.New("ID", "Attack Name", "Status", "Success", "Detected", "Created At")

	for _, data := range executions.Data {
		// We need to convert the interface{} to a map to access the fields
		execMap, ok := data.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract values with defaults for missing fields
		id := getStringOrDefault(execMap, "id", "N/A")
		attackName := getStringOrDefault(execMap, "attack_name", "N/A")
		status := getStringOrDefault(execMap, "status_state", "N/A")

		// Handle numeric fields
		progress := "0%"
		if val, ok := execMap["progress"].(float64); ok {
			progress = fmt.Sprintf("%.1f%%", val)
		}

		detected := "0%"
		if val, ok := execMap["detected"].(float64); ok {
			detected = fmt.Sprintf("%.1f%%", val)
		}

		createdAt := getStringOrDefault(execMap, "created_at", "N/A")

		// Add row data
		tbl.AddRow(id, attackName, status, progress, detected, createdAt)
	}

	// Print the table to stdout
	tbl.Print()
}

func printAssetPacks(packs []models.PackRun) {
	if len(packs) == 0 {
		fmt.Println("No assessment reports found for this asset.")
		return
	}

	fmt.Printf("Total Assessment Reports: %d\n\n", len(packs))

	// Create a new table with headers
	tbl := table.New("ID", "Name", "Status", "Success/Total", "Detection Rate", "Created At")

	for _, pack := range packs {
		// Calculate detection rate
		detectionRate := "N/A"
		if pack.Total > 0 {
			detectionRate = fmt.Sprintf("%.1f%%", float64(pack.Detected)/float64(pack.Total)*100)
		}

		// Format success/total
		successTotal := fmt.Sprintf("%d/%d", pack.Success, pack.Total)

		// Format created at
		createdAt := "N/A"
		if pack.CreatedAt != nil {
			createdAt = *pack.CreatedAt
		}

		// Add row data
		tbl.AddRow(pack.ID, pack.Name, pack.StatusState, successTotal, detectionRate, createdAt)
	}

	// Print the table to stdout
	tbl.Print()
}

// Helper function to safely extract string values from map
func getStringOrDefault(m map[string]interface{}, key, defaultValue string) string {
	if val, ok := m[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return defaultValue
}
