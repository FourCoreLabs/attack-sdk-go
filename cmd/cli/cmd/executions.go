package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	pkgExecutions "github.com/fourcorelabs/attack-sdk-go/pkg/executions" // Alias to avoid collision
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
)

// executionsCmd represents the executions command
var executionsCmd = &cobra.Command{
	Use:   "executions",
	Short: "Execution operations",
	Long:  `Commands for interacting with executions in the FourCore platform.`,
}

// executionsListCmd represents the executions list command
var executionsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List executions",
	Long:    `Retrieves and displays executions with options for pagination, ordering, filtering, and formatting.`,
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
		size, _ := cmd.Flags().GetInt("size")
		offset, _ := cmd.Flags().GetInt("offset")
		order, _ := cmd.Flags().GetString("order")
		format, _ := cmd.Flags().GetString("format")
		name, _ := cmd.Flags().GetString("name")
		status, _ := cmd.Flags().GetString("status")
		assetIDs, _ := cmd.Flags().GetStringArray("asset-id")
		hostnames, _ := cmd.Flags().GetStringArray("hostname")
		chainIDs, _ := cmd.Flags().GetStringArray("chain-id")
		attackIDs, _ := cmd.Flags().GetStringArray("attack-id")
		executionTypes, _ := cmd.Flags().GetStringArray("execution-type")
		dateAfterStr, _ := cmd.Flags().GetString("date-after")
		dateBeforeStr, _ := cmd.Flags().GetString("date-before")

		// Parse date-after and date-before if provided
		var dateAfter, dateBefore time.Time
		if dateAfterStr != "" {
			dateAfter, err = time.Parse(time.RFC3339, dateAfterStr)
			if err != nil {
				return fmt.Errorf("invalid date-after format, must be RFC3339 format (e.g., 2023-01-01T00:00:00Z): %w", err)
			}
		}
		if dateBeforeStr != "" {
			dateBefore, err = time.Parse(time.RFC3339, dateBeforeStr)
			if err != nil {
				return fmt.Errorf("invalid date-before format, must be RFC3339 format (e.g., 2023-01-01T00:00:00Z): %w", err)
			}
		}

		opts := pkgExecutions.ExecutionOpts{
			Size:          size,
			Offset:        offset,
			Order:         strings.ToUpper(order),
			Name:          name,
			Status:        status,
			AssetIDs:      assetIDs,
			Hostnames:     hostnames,
			ChainIDs:      chainIDs,
			AttackIDs:     attackIDs,
			ExecutionType: executionTypes,
			DateAfter:     dateAfter,
			DateBefore:    dateBefore,
		}

		// --- API Call ---
		executions, err := pkgExecutions.GetExecutions(context.Background(), client, opts)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			return fmt.Errorf("failed to retrieve executions: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printExecutionsJSON(executions)
		case "table":
			fallthrough
		default:
			printExecutionsTable(executions)
			return nil
		}
	},
}

// executionsGetCmd represents the executions get command
var executionsGetCmd = &cobra.Command{
	Use:   "get [execution_id]",
	Short: "Get execution report",
	Long:  `Retrieves detailed execution report for a specific execution.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		executionID := args[0]
		if executionID == "" {
			return fmt.Errorf("execution ID is required")
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- Get Flags ---
		format, _ := cmd.Flags().GetString("format")

		// --- API Call ---
		execution, err := pkgExecutions.GetExecutionReport(context.Background(), client, executionID)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("execution not found: %s", executionID)
			}
			return fmt.Errorf("failed to retrieve execution report: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printExecutionJSON(execution)
		default:
			printExecutionItemDetails(execution)
			return nil
		}
	},
}

// executionsDeleteCmd represents the executions delete command
var executionsDeleteCmd = &cobra.Command{
	Use:   "delete [execution_id]",
	Short: "Delete an execution",
	Long:  `Deletes a specific execution from the FourCore platform.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		executionID := args[0]
		if executionID == "" {
			return fmt.Errorf("execution ID is required")
		}

		// Confirm deletion if confirm flag not set
		confirm, _ := cmd.Flags().GetBool("confirm")
		if !confirm {
			fmt.Printf("Are you sure you want to delete execution %s? (y/N): ", executionID)
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
		response, err := pkgExecutions.DeleteExecution(context.Background(), client, executionID)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("execution not found: %s", executionID)
			}
			return fmt.Errorf("failed to delete execution: %w", err)
		}

		// --- Output Success ---
		if response.Success {
			fmt.Printf("Successfully deleted execution: %s\n", executionID)
		} else {
			fmt.Printf("No changes made to execution: %s\n", executionID)
		}
		return nil
	},
}

func init() {
	// Add commands to the executions command
	executionsCmd.AddCommand(executionsListCmd)
	executionsCmd.AddCommand(executionsGetCmd)
	executionsCmd.AddCommand(executionsDeleteCmd)

	// Add executions command to root command
	rootCmd.AddCommand(executionsCmd)

	// --- Common Flags ---
	// Format flag for commands that output data
	executionsListCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	executionsGetCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")

	// --- Command-specific Flags ---
	// List command flags
	executionsListCmd.Flags().IntP("size", "s", 10, "Number of executions to retrieve")
	executionsListCmd.Flags().IntP("offset", "o", 0, "Offset for pagination")
	executionsListCmd.Flags().StringP("order", "r", "DESC", "Order of executions (ASC or DESC)")
	executionsListCmd.Flags().StringP("name", "n", "", "Filter by name")
	executionsListCmd.Flags().StringP("status", "", "", "Filter by status (inprogress, finished, unknown)")
	executionsListCmd.Flags().StringArrayP("asset-id", "a", []string{}, "Filter by asset ID (can be specified multiple times)")
	executionsListCmd.Flags().StringArray("hostname", []string{}, "Filter by hostname (can be specified multiple times)")
	executionsListCmd.Flags().StringArray("chain-id", []string{}, "Filter by chain ID (can be specified multiple times)")
	executionsListCmd.Flags().StringArray("attack-id", []string{}, "Filter by attack ID (can be specified multiple times)")
	executionsListCmd.Flags().StringArray("execution-type", []string{}, "Filter by execution type (endpoint_security, data_exfil, firewall, email_infiltration, waf)")
	executionsListCmd.Flags().String("date-after", "", "Filter executions created after specified date (RFC3339 format)")
	executionsListCmd.Flags().String("date-before", "", "Filter executions created before specified date (RFC3339 format)")

	// Delete command flags
	executionsDeleteCmd.Flags().BoolP("confirm", "y", false, "Skip confirmation prompt")
}

// --- Helper Functions for Output Formatting ---

func printExecutionsTable(executions models.ListWithCountExecutions) {
	if executions.Count == 0 || len(executions.Data) == 0 {
		fmt.Println("No executions found matching the criteria.")
		return
	}

	fmt.Printf("Total Executions: %d\n\n", executions.Count)

	// Create a new table with headers
	tbl := table.New("ID", "Attack Name", "Status", "Success", "Detection Rate", "Assets", "Created At", "Updated At")

	for _, execution := range executions.Data {
		// Format progress as percentage
		progress := fmt.Sprintf("%.1f%%", execution.Progress)

		// Format detection rate as percentage
		detectionRate := fmt.Sprintf("%.1f%%", execution.Detected)

		// Format asset count
		assetCount := fmt.Sprintf("%d", execution.AssetCount)

		// Format created at
		createdAt := "N/A"
		if execution.CreatedAt != nil {
			createdAt = execution.CreatedAt.Format(time.RFC3339)
		}

		updatedAt := "N/A"
		if execution.UpdatedAt != nil {
			createdAt = execution.UpdatedAt.Format(time.RFC3339)
		}

		// Truncate long attack names
		attackName := execution.AttackName

		// Add row data
		tbl.AddRow(
			execution.ID,
			attackName,
			execution.StatusState,
			progress,
			detectionRate,
			assetCount,
			createdAt,
			updatedAt,
		)
	}

	// Print the table to stdout
	tbl.Print()
}

func printExecutionsJSON(executions models.ListWithCountExecutions) error {
	jsonData, err := json.MarshalIndent(executions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func printExecutionJSON(execution models.GetExecutionResponse) error {
	jsonData, err := json.MarshalIndent(execution, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func printExecutionItemDetails(execution models.GetExecutionResponse) {
	fmt.Println("Execution Details:")
	fmt.Printf("ID:               %s\n", execution.ID)
	fmt.Printf("Attack Name:      %s\n", execution.AttackName)
	fmt.Printf("Chain ID:         %s\n", execution.ChainID)
	fmt.Printf("Status:           %s\n", execution.StatusState)
	fmt.Printf("Execution Type:   %s\n", execution.ExecutionType)
	fmt.Printf("Progress:         %.1f%%\n", execution.Progress)
	fmt.Printf("Detection Rate:   %.1f%%\n", execution.Detected)
	fmt.Printf("Score:            %.1f\n", execution.Score)
	fmt.Printf("Run Elevated:     %t\n", execution.RunElevated)

	if execution.CreatedAt != nil {
		fmt.Printf("Created At:       %s\n", execution.CreatedAt.Format(time.RFC3339))
	}
	if execution.UpdatedAt != nil {
		fmt.Printf("Updated At:       %s\n", execution.UpdatedAt.Format(time.RFC3339))
	}

	// Organization and User info
	if execution.OrgName != nil && *execution.OrgName != "" {
		fmt.Printf("Organization:     %s (ID: %d)\n", *execution.OrgName, execution.OrgID)
	}
	if execution.Username != nil && *execution.Username != "" {
		fmt.Printf("User:             %s (ID: %d)\n", *execution.Username, execution.UserID)
	}

	// Statistics
	fmt.Printf("\nStatistics:\n")
	fmt.Printf("  Total Attacks:  %d\n", execution.TotalAttacks)
	fmt.Printf("  Total Finished: %d\n", execution.TotalFinished)
	fmt.Printf("  Total Success:  %d\n", execution.TotalSuccess)
	fmt.Printf("  Total Detected: %d\n", execution.TotalDetected)

	// Assets
	if len(execution.Assets) > 0 {
		fmt.Printf("\nAssets (%d):\n", len(execution.Assets))
		for i, asset := range execution.Assets {
			if i < 5 { // Limit to first 5 assets to avoid overwhelming output
				fmt.Printf("  - %s (%s) - %s\n", asset.Hostname, asset.AssetID, asset.Platform)
			}
		}
		if len(execution.Assets) > 5 {
			fmt.Printf("  ... and %d more assets\n", len(execution.Assets)-5)
		}
	}

	// Hostname info
	if len(execution.Hostname) > 0 {
		fmt.Printf("\nTarget Hosts (%d):\n", len(execution.Hostname))
		for i, host := range execution.Hostname {
			if i < 5 { // Limit to first 5 hosts
				fmt.Printf("  - %s (%s) - %s\n", host.Name, host.IPAddr, host.OS)
			}
		}
		if len(execution.Hostname) > 5 {
			fmt.Printf("  ... and %d more hosts\n", len(execution.Hostname)-5)
		}
	}

	// C2 Information
	if execution.C2Type != "" || execution.C2Profile != "" {
		fmt.Printf("\nC2 Configuration:\n")
		if execution.C2Type != "" {
			fmt.Printf("  Type:           %s\n", execution.C2Type)
		}
		if execution.C2Profile != "" {
			fmt.Printf("  Profile:        %s\n", execution.C2Profile)
		}
	}

	// Attack information
	if execution.Attack != nil {
		fmt.Printf("\nAttack Information:\n")
		fmt.Printf("  Attack ID:      %d\n", execution.Attack.ID)
		fmt.Printf("  Description:    %s\n", execution.Attack.Description)
		fmt.Printf("  Platform:       %s\n", execution.Attack.Platform)
		if len(execution.Attack.Platforms) > 0 {
			fmt.Printf("  Platforms:      %s\n", strings.Join(execution.Attack.Platforms, ", "))
		}
	}

	// Integrations
	if len(execution.Integrations) > 0 {
		fmt.Printf("\nIntegrations:     %s\n", strings.Join(execution.Integrations, ", "))
	}

	// Action IDs
	if len(execution.ActionIDs) > 0 {
		fmt.Printf("\nAction IDs (%d):  ", len(execution.ActionIDs))
		if len(execution.ActionIDs) <= 3 {
			fmt.Printf("%s\n", strings.Join(execution.ActionIDs, ", "))
		} else {
			fmt.Printf("%s, ... and %d more\n", strings.Join(execution.ActionIDs[:3], ", "), len(execution.ActionIDs)-3)
		}
	}

	// Statistics detail
	if execution.Statistics != nil {
		fmt.Printf("\nDetailed Statistics:\n")
		fmt.Printf("  Assets Attacked:     %d\n", execution.Statistics.AssetsAttacked)
		fmt.Printf("  Attack Success Rate: %.1f%%\n", execution.Statistics.AttackSuccess*100)
		fmt.Printf("  Files Exfiltrated:   %d\n", execution.Statistics.FilesExfiltrated)
		fmt.Printf("  Total Steps:         %d\n", execution.Statistics.TotalSteps)
		if len(execution.Statistics.PlatformsAttacked) > 0 {
			fmt.Printf("  Platforms Attacked:  %s\n", strings.Join(execution.Statistics.PlatformsAttacked, ", "))
		}
	}
}
