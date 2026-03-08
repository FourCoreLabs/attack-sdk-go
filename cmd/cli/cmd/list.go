package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	pkgActions "github.com/fourcorelabs/attack-sdk-go/pkg/actions"
	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	pkgChains "github.com/fourcorelabs/attack-sdk-go/pkg/chains" // Alias to avoid collision
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	modelActions "github.com/fourcorelabs/attack-sdk-go/pkg/models/actions"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/chains"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
)

// listCmd represents the content listing command
var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "content listing operations",
	Long:    `Commands for interacting with various content list in the FourCore platform.`,
}

// chainListCmd represents the endpoint chain list command
var chainListCmd = &cobra.Command{
	Use:   "chain",
	Short: "List endpoint chains",
	Long:  `Retrieves and displays endpoint chains with options for pagination, ordering, and filtering.`,
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
		order, _ := cmd.Flags().GetStringSlice("order")
		format, _ := cmd.Flags().GetString("format")
		startReleaseDate, _ := cmd.Flags().GetString("start_release_date")
		endReleaseDate, _ := cmd.Flags().GetString("end_release_date")
		startLastRunAt, _ := cmd.Flags().GetString("start_last_run_at")
		endLastRunAt, _ := cmd.Flags().GetString("end_last_run_at")
		platforms, _ := cmd.Flags().GetStringSlice("platform")

		orderbyMap := map[string]struct{}{}
		for _, o := range order {
			s := o
			if len(s) > 0 && (s[0] == '-' || s[0] == '+') {
				s = s[1:]
			}

			if slices.ContainsFunc(pkgChains.ValidListEndpointChainOrder, func(v pkgChains.ListEndpointChainOrderBy) bool {
				return strings.EqualFold(s, string(v))
			}) {
				orderbyMap[o] = struct{}{}
			}
		}

		opts := pkgChains.ListEndpointChainOpts{
			Size:   size,
			Offset: offset,
			Order:  slices.Collect(maps.Keys(orderbyMap)),
		}

		if t, err := time.Parse(time.RFC3339, startReleaseDate); err == nil {
			opts.StartReleaseDate = t
		}
		if t, err := time.Parse(time.RFC3339, endReleaseDate); err == nil {
			opts.EndReleaseDate = t
		}
		if t, err := time.Parse(time.RFC3339, startLastRunAt); err == nil {
			opts.StartLastRunAt = t
		}
		if t, err := time.Parse(time.RFC3339, endLastRunAt); err == nil {
			opts.EndLastRunAt = t
		}
		if len(platforms) > 0 {
			opts.Platform = platforms
		}
		if cmd.Flags().Changed("id") {
			id, _ := cmd.Flags().GetString("id")
			opts.ID = id
		}
		if cmd.Flags().Changed("search_name") {
			name, _ := cmd.Flags().GetString("search_name")
			opts.Name = name
		}
		if cmd.Flags().Changed("elevated") {
			elevated, _ := cmd.Flags().GetBool("elevated")
			opts.Elevated = &elevated
		}
		if cmd.Flags().Changed("show_deprecated") {
			dep, _ := cmd.Flags().GetBool("show_deprecated")
			opts.ShowDeprecated = &dep
		}

		// --- API Call ---
		chains, err := pkgChains.ListEndpointChains(context.Background(), client, opts)
		if err != nil {
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}

			return fmt.Errorf("failed to retrieve chains: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printEndpointChainsJSON(chains)
		case "table":
			fallthrough
		default:
			printEndpointChainsTable(chains)
			return nil
		}
	},
}

// actionListCmd represents the endpoint action list command
var actionListCmd = &cobra.Command{
	Use:   "actions",
	Short: "List endpoint actions",
	Long:  `Retrieves and displays endpoint actions with options for pagination and filtering.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		size, _ := cmd.Flags().GetInt("size")
		offset, _ := cmd.Flags().GetInt("offset")
		format, _ := cmd.Flags().GetString("format")
		startReleaseDate, _ := cmd.Flags().GetString("start_release_date")
		endReleaseDate, _ := cmd.Flags().GetString("end_release_date")
		platforms, _ := cmd.Flags().GetStringSlice("platform")

		opts := pkgActions.ListEndpointActionOpts{
			Size:   size,
			Offset: offset,
		}

		if t, err := time.Parse(time.RFC3339, startReleaseDate); err == nil {
			opts.StartReleaseDate = t
		}
		if t, err := time.Parse(time.RFC3339, endReleaseDate); err == nil {
			opts.EndReleaseDate = t
		}

		if len(platforms) > 0 {
			for _, p := range platforms {
				if slices.ContainsFunc(models.ValidPlatforms, func(v models.Platform) bool {
					return strings.EqualFold(p, string(v))
				}) {
					opts.Platforms = append(opts.Platforms, models.Platform(strings.ToLower(p)))
				}
			}
		}

		if cmd.Flags().Changed("id") {
			id, _ := cmd.Flags().GetString("id")
			opts.ID = id
		}
		if cmd.Flags().Changed("search_name") {
			name, _ := cmd.Flags().GetString("search_name")
			opts.Name = name
		}
		if cmd.Flags().Changed("type") {
			actionType, _ := cmd.Flags().GetString("type")
			opts.Type = actionType
		}
		if cmd.Flags().Changed("severity") {
			severity, _ := cmd.Flags().GetString("severity")
			if slices.ContainsFunc(models.ValidSeverities, func(v models.Severity) bool {
				return strings.EqualFold(severity, string(v))
			}) {
				opts.Severity = models.Severity(strings.ToLower(severity))
			}
		}

		actions, err := pkgActions.ListEndpointActions(context.Background(), client, opts)
		if err != nil {
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}

			return fmt.Errorf("failed to retrieve actions: %w", err)
		}

		switch strings.ToLower(format) {
		case "json":
			return printEndpointActionsJSON(actions)
		case "table":
			fallthrough
		default:
			printEndpointActionsTable(actions)
			return nil
		}
	},
}

func init() {
	validOrders := []string{}
	for _, v := range pkgChains.ValidListEndpointChainOrder {
		validOrders = append(validOrders, string(v))
	}

	chainListCmd.Flags().IntP("size", "s", 10, "Number of audit logs to retrieve")
	chainListCmd.Flags().IntP("offset", "o", 0, "Offset for pagination")
	chainListCmd.Flags().StringSliceP("order", "r", []string{"-" + string(pkgChains.ListEndpointChainOrderbyReleaseDate)}, fmt.Sprintf("Order of chains (%s)", strings.Join(validOrders, ", ")))
	chainListCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	chainListCmd.Flags().String("start_release_date", "", "Set filter on starting of release date")
	chainListCmd.Flags().String("end_release_date", "", "Set filter on ending of release date")
	chainListCmd.Flags().String("start_last_run_at", "", "Set filter on starting of last running date")
	chainListCmd.Flags().String("end_last_run_at", "", "Set filter on ending of last running date")
	chainListCmd.Flags().StringSlice("platform", nil, "Set filter on type of platforms")
	chainListCmd.Flags().String("id", "", "Search chain based on ID")
	chainListCmd.Flags().String("search_name", "", "Search chain based on name")
	chainListCmd.Flags().Bool("elevated", false, "Set filter on elevation of chain")
	chainListCmd.Flags().Bool("show_deprecated", false, "show deprecated chains")

	actionListCmd.Flags().IntP("size", "s", 10, "Number of actions to retrieve")
	actionListCmd.Flags().IntP("offset", "o", 0, "Offset for pagination")
	actionListCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	actionListCmd.Flags().String("start_release_date", "", "Set filter on starting of release date")
	actionListCmd.Flags().String("end_release_date", "", "Set filter on ending of release date")
	actionListCmd.Flags().StringSlice("platform", nil, "Set filter on type of platforms")
	actionListCmd.Flags().String("id", "", "Search action based on ID")
	actionListCmd.Flags().String("search_name", "", "Search action based on name")
	actionListCmd.Flags().String("severity", "", "Set filter on severity (critical, high, medium, low)")
	actionListCmd.Flags().String("type", "", "Set filter on action type")

	listCmd.AddCommand(chainListCmd)
	listCmd.AddCommand(actionListCmd)
	rootCmd.AddCommand(listCmd)
}

func printEndpointChainsJSON(chains models.PaginationResponse[chains.ChainForUserState]) error {
	jsonData, err := json.MarshalIndent(chains, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func printEndpointChainsTable(chains models.PaginationResponse[chains.ChainForUserState]) {
	if len(chains.Data) == 0 {
		fmt.Println("No chains found matching the criteria.")
		return
	}

	fmt.Printf("Total Chains: %d\n\n", chains.TotalRows)

	// Create a new table with headers
	tbl := table.New("ID", "Name", "Platforms", "Blocked Rate", "Success Rate", "Detection Rate", "Released At", "Last Executed At")

	for _, chain := range chains.Data {
		var (
			blockedRate   = "0%"
			successRate   = "0%"
			detectionRate = "0%"
		)

		if chain.Total > 0 {
			// Format detection rate as percentage
			detectionRate = fmt.Sprintf("%.1f%%", float64(chain.Detected*100)/float64(chain.Total))
			successRate = fmt.Sprintf("%.1f%%", float64(chain.Success*100)/float64(chain.Total))
			blockedRate = fmt.Sprintf("%.1f%%", float64((chain.Total-chain.Success)*100)/float64(chain.Total))
		}

		// Format created at
		releasedAt := "N/A"
		if !chain.ReleaseDate.IsZero() {
			releasedAt = chain.ReleaseDate.Format(time.RFC3339)
		}

		lastExecutedAt := "N/A"
		if chain.LastRunAt != nil && !chain.LastRunAt.IsZero() {
			lastExecutedAt = chain.LastRunAt.Format(time.RFC3339)
		}

		// Add row data
		tbl.AddRow(
			chain.ID,
			chain.Name,
			strings.Join(chain.Platforms, ", "),
			blockedRate,
			successRate,
			detectionRate,
			releasedAt,
			lastExecutedAt,
		)
	}

	// Print the table to stdout
	tbl.Print()
}

func printEndpointActionsJSON(actions models.PaginationResponse[modelActions.ActionForUserState]) error {
	jsonData, err := json.MarshalIndent(actions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func printEndpointActionsTable(actions models.PaginationResponse[modelActions.ActionForUserState]) {
	if len(actions.Data) == 0 {
		fmt.Println("No actions found matching the criteria.")
		return
	}

	fmt.Printf("Total Actions: %d\n\n", actions.TotalRows)

	tbl := table.New("ID", "Name", "Type", "Severity", "Platforms", "Released At")

	for _, action := range actions.Data {
		releasedAt := "N/A"
		if !action.ReleaseDate.IsZero() {
			releasedAt = action.ReleaseDate.Format(time.RFC3339)
		}

		platforms := make([]string, 0, len(action.Platforms))
		for _, platform := range action.Platforms {
			platforms = append(platforms, platform)
		}

		tbl.AddRow(
			action.ID,
			action.Name,
			action.Type,
			action.Severity,
			strings.Join(platforms, ", "),
			releasedAt,
		)
	}

	tbl.Print()
}
