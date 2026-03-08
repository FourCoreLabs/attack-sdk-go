package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	pkgAuditLog "github.com/fourcorelabs/attack-sdk-go/pkg/auditlog" // Alias to avoid collision
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/auditlog"
	"github.com/spf13/cobra"
)

type auditViewItem struct {
	log auditlog.AuditLog
}

func (i auditViewItem) Transform() (any, error) {
	return auditlog.AuditLogExpanded(i.log), nil
}

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

		return outputPaginatedItems(cmd, format, "", false, logs, func(item auditlog.AuditLog) auditViewItem {
			return auditViewItem{log: item}
		}, "No audit logs found matching the criteria.", "Total Rows")
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
