package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	pkgAuditLog "github.com/fourcorelabs/attack-sdk-go/pkg/auditlog" // Alias to avoid collision
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/auditlog"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
)

// auditCmd represents the audit command
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log operations",
	Long:  `Commands for interacting with audit logs in the FourCore platform.`,
}

// auditListCmd represents the audit list command
var auditListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List audit logs",
	Long:    `Retrieves and displays audit logs with options for pagination, ordering, and formatting.`,
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

		opts := pkgAuditLog.AuditLogOpts{
			Size:   size,
			Offset: offset,
			Order:  strings.ToUpper(order), // Ensure consistent case for API
		}

		// --- API Call ---
		logs, err := pkgAuditLog.GetAuditLogs(context.Background(), client, opts)
		if err != nil {
			// Check for specific API errors if needed
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			// Handle other potential errors from GetAuditLogs or underlying client
			return fmt.Errorf("failed to retrieve audit logs: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printAuditLogsJSON(logs)
		case "table":
			fallthrough // Default to table
		default:
			printAuditLogsTable(logs)
			return nil
		}
	},
}

func init() {
	// --- Flags for 'audit list' ---
	auditListCmd.Flags().IntP("size", "s", 10, "Number of audit logs to retrieve")
	auditListCmd.Flags().IntP("offset", "o", 0, "Offset for pagination")
	auditListCmd.Flags().StringP("order", "r", "DESC", "Order of audit logs (ASC or DESC)")
	auditListCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")

	// --- Add Commands ---
	auditCmd.AddCommand(auditListCmd) // Add 'list' to 'audit'
	rootCmd.AddCommand(auditCmd)      // Add 'audit' to the root command
}

// --- Helper Functions (specific to audit command output) ---

func printAuditLogsTable(logs models.PaginationResponse[auditlog.AuditLog]) {
	if logs.TotalRows == 0 || len(logs.Data) == 0 {
		fmt.Println("No audit logs found matching the criteria.")
		return
	}

	fmt.Printf("Total Rows: %d\n", logs.TotalRows) // Keep total rows info

	// Create a new table with headers
	// Note: rodaine/table automatically prints to os.Stdout by default
	tbl := table.New("Time", "Source IP", "Actor", "Action", "Endpoint", "Organization")

	// Optional: Customize table appearance (check rodaine/table docs for options)
	// Example: tbl.WithHeaderFormatter(...)
	// Example: tbl.WithPadding(...)
	// Example: table.DefaultHeaderFormatter = ... (for global changes)

	for _, log := range logs.Data {
		timeStr := "N/A"
		if log.CreatedAt != nil {
			timeStr = log.CreatedAt.Format(time.RFC3339)
		}

		actor := log.Actor.Email
		if actor == "" {
			actor = maskString(log.Actor.ApiKey)
		}
		if actor == "" {
			actor = "System/Unknown"
		}

		orgStr := log.OrgName + " (" + strconv.FormatUint(uint64(log.OrgID), 10) + ")"

		// Add row data - arguments must match the order of headers in table.New
		tbl.AddRow(
			timeStr,
			log.SourceIP,
			actor,
			log.Action,
			log.Endpoint,
			orgStr,
		)
	}

	// Print the table to stdout
	tbl.Print()
}

func printAuditLogsJSON(logs models.PaginationResponse[auditlog.AuditLog]) error {
	jsonData, err := json.MarshalIndent(logs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}
