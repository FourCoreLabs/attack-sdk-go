package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	pkgAgentLog "github.com/fourcorelabs/attack-sdk-go/pkg/agentlog" // Alias to avoid collision
	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/agentlog"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
)

// agentCmd represents the agent command
var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Agent operations",
	Long:  `Commands for interacting with agent resources in the FourCore platform.`,
}

// agentLogCmd represents the agent log command
var agentLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Agent log operations",
	Long:  `Commands for interacting with agent logs in the FourCore platform.`,
}

// agentLogListCmd represents the agent log list command
var agentLogListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List agent logs",
	Long:    `Retrieves and displays agent logs with options for pagination, ordering, filtering, and formatting.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		// apiKeyVal and baseUrlVal are populated by rootCmd's PersistentPreRunE
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
		action, _ := cmd.Flags().GetString("action")
		query, _ := cmd.Flags().GetString("query")
		assetIDs, _ := cmd.Flags().GetStringArray("asset-id")
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

		opts := pkgAgentLog.AgentLogOpts{
			Size:       size,
			Offset:     offset,
			Order:      strings.ToUpper(order), // Ensure consistent case for API
			AssetIDs:   assetIDs,
			Action:     action,
			DateAfter:  dateAfter,
			DateBefore: dateBefore,
			Query:      query,
		}

		// --- API Call ---
		logs, err := pkgAgentLog.GetAgentLogs(client, opts)
		if err != nil {
			// Check for specific API errors if needed
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			// Handle other potential errors from GetAgentLogs or underlying client
			return fmt.Errorf("failed to retrieve agent logs: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printAgentLogsJSON(logs)
		case "table":
			fallthrough // Default to table
		default:
			printAgentLogsTable(logs)
			return nil
		}
	},
}

func init() {
	// --- Flags for 'agent log list' ---
	agentLogListCmd.Flags().IntP("size", "s", 10, "Number of agent logs to retrieve")
	agentLogListCmd.Flags().IntP("offset", "o", 0, "Offset for pagination")
	agentLogListCmd.Flags().StringP("order", "r", "DESC", "Order of agent logs (ASC or DESC)")
	agentLogListCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	agentLogListCmd.Flags().StringArrayP("asset-id", "a", []string{}, "Filter logs by asset ID (can be specified multiple times)")
	agentLogListCmd.Flags().StringP("action", "c", "", "Filter logs by action type")
	agentLogListCmd.Flags().String("date-after", "", "Filter logs created after specified date (RFC3339 format)")
	agentLogListCmd.Flags().String("date-before", "", "Filter logs created before specified date (RFC3339 format)")
	agentLogListCmd.Flags().StringP("query", "q", "", "Filter logs based on query language")

	// --- Add Commands ---
	agentLogCmd.AddCommand(agentLogListCmd) // Add 'list' to 'agent log'
	agentCmd.AddCommand(agentLogCmd)        // Add 'log' to 'agent'
	rootCmd.AddCommand(agentCmd)            // Add 'agent' to the root command
}

// --- Helper Functions (specific to agent log command output) ---

func printAgentLogsTable(logs models.PaginationResponse[agentlog.AgentLog]) {
	if logs.TotalRows == 0 || len(logs.Data) == 0 {
		fmt.Println("No agent logs found matching the criteria.")
		return
	}

	fmt.Printf("Total Rows: %d\n", logs.TotalRows) // Keep total rows info

	// Create a new table with headers
	tbl := table.New("Time", "Asset ID", "Hostname", "Action", "Message", "Data")

	for _, log := range logs.Data {
		timeStr := "N/A"
		if log.CreatedAt != nil {
			timeStr = log.CreatedAt.Format(time.RFC3339)
		}

		// Truncate message if it's too long for display
		message := log.Message
		if len(message) > 50 {
			message = message[:47] + "..."
		}

		var dataJsonStr string
		if log.Data != nil {
			if data, err := json.Marshal(log.Data); err == nil {
				dataJsonStr = string(data)
			}
		}

		// Add row data - arguments must match the order of headers in table.New
		tbl.AddRow(
			timeStr,
			log.AssetID,
			log.Hostname,
			log.Action,
			message,
			dataJsonStr,
		)
	}

	// Print the table to stdout
	tbl.Print()
}

func printAgentLogsJSON(logs models.PaginationResponse[agentlog.AgentLog]) error {
	jsonData, err := json.MarshalIndent(logs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}
