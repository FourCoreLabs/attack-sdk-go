package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	pkgMitre "github.com/fourcorelabs/attack-sdk-go/pkg/mitre"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/mitre"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
)

// mitreCmd represents the mitre command
var mitreCmd = &cobra.Command{
	Use:   "mitre",
	Short: "MITRE ATT&CK operations",
	Long:  `Commands for interacting with MITRE ATT&CK framework data in the FourCore platform.`,
}

// mitreCoverageCmd represents the mitre coverage command
var mitreCoverageCmd = &cobra.Command{
	Use:   "coverage",
	Short: "Get MITRE ATT&CK coverage",
	Long:  `Retrieves complete MITRE ATT&CK coverage information showing techniques, tactics, and associated actions/stagers.`,
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
		days, _ := cmd.Flags().GetInt("days")
		format, _ := cmd.Flags().GetString("format")

		// --- API Call ---
		coverage, err := pkgMitre.GetAllMitreCoverage(context.Background(), client, days)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			return fmt.Errorf("failed to retrieve MITRE ATT&CK coverage: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printMitreCoverageJSON(coverage)
		case "table":
			fallthrough
		default:
			printMitreCoverageTable(coverage)
			return nil
		}
	},
}

// mitreTechniqueCmd represents the mitre technique command
var mitreTechniqueCmd = &cobra.Command{
	Use:   "technique [technique_id]",
	Short: "Get MITRE ATT&CK technique details",
	Long:  `Retrieves detailed information about a specific MITRE ATT&CK technique including associated actions, stagers, and execution statistics.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		techniqueID := args[0]
		if techniqueID == "" {
			return fmt.Errorf("technique ID is required")
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
		technique, err := pkgMitre.GetMitreTechnique(context.Background(), client, techniqueID, days)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("MITRE technique not found: %s", techniqueID)
			}
			return fmt.Errorf("failed to retrieve MITRE technique: %w", err)
		}

		// --- Output ---
		switch strings.ToLower(format) {
		case "json":
			return printMitreTechniqueJSON(technique)
		default:
			printMitreTechniqueDetails(technique)
			return nil
		}
	},
}

func init() {
	// Add commands to the mitre command
	mitreCmd.AddCommand(mitreCoverageCmd)
	mitreCmd.AddCommand(mitreTechniqueCmd)

	// Add mitre command to root command
	rootCmd.AddCommand(mitreCmd)

	// --- Common Flags ---
	// Format flag for commands that output data
	mitreCoverageCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	mitreTechniqueCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")

	// --- Command-specific Flags ---
	// Days flag for both commands (limit days for analytics)
	mitreCoverageCmd.Flags().IntP("days", "d", 30, "Number of days for analytics (max 60)")
	mitreTechniqueCmd.Flags().IntP("days", "d", 30, "Number of days for analytics (max 60)")
}

// --- Helper Functions for Output Formatting ---

func printMitreCoverageTable(coverage []mitre.MitreTacticTechniqueWithActionAndStagers) {
	if len(coverage) == 0 {
		fmt.Println("No MITRE ATT&CK coverage data found.")
		return
	}

	fmt.Printf("MITRE ATT&CK Coverage (%d techniques)\n\n", len(coverage))

	// Create a new table with headers
	tbl := table.New("Technique ID", "Tactic ID", "Sub-Technique", "Total", "Success", "Detected", "Actions", "Stagers")

	for _, item := range coverage {
		// Calculate success and detection rates
		successRate := "0%"
		detectionRate := "0%"
		if item.Total > 0 {
			successRate = fmt.Sprintf("%.1f%%", float64(item.Success)/float64(item.Total)*100)
			detectionRate = fmt.Sprintf("%.1f%%", float64(item.Detected)/float64(item.Total)*100)
		}

		// Format technique ID with sub-technique if present
		techniqueDisplay := item.TechniqueID
		if item.SubTechniqueID != "" {
			techniqueDisplay = fmt.Sprintf("%s.%s", item.TechniqueID, item.SubTechniqueID)
		}

		// Count actions and stagers
		actionCount := fmt.Sprintf("%d", len(item.Actions))
		stagerCount := fmt.Sprintf("%d", len(item.Stagers))

		// Add row data
		tbl.AddRow(
			techniqueDisplay,
			item.TacticID,
			item.SubTechniqueID,
			fmt.Sprintf("%d", item.Total),
			successRate,
			detectionRate,
			actionCount,
			stagerCount,
		)
	}

	// Print the table to stdout
	tbl.Print()

	// Print summary statistics
	var totalExecutions, totalSuccess, totalDetected int64
	uniqueTechniques := make(map[string]bool)
	uniqueTactics := make(map[string]bool)

	for _, item := range coverage {
		totalExecutions += item.Total
		totalSuccess += item.Success
		totalDetected += item.Detected
		uniqueTechniques[item.TechniqueID] = true
		uniqueTactics[item.TacticID] = true
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("Unique Techniques: %d\n", len(uniqueTechniques))
	fmt.Printf("Unique Tactics:    %d\n", len(uniqueTactics))
	fmt.Printf("Total Executions:  %d\n", totalExecutions)
	if totalExecutions > 0 {
		fmt.Printf("Success Rate:      %.1f%%\n", float64(totalSuccess)/float64(totalExecutions)*100)
		fmt.Printf("Detection Rate:    %.1f%%\n", float64(totalDetected)/float64(totalExecutions)*100)
	}
}

func printMitreCoverageJSON(coverage []mitre.MitreTacticTechniqueWithActionAndStagers) error {
	jsonData, err := json.MarshalIndent(coverage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func printMitreTechniqueJSON(technique mitre.MitreTacticTechniqueWithActionAndStagers) error {
	jsonData, err := json.MarshalIndent(technique, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func printMitreTechniqueDetails(technique mitre.MitreTacticTechniqueWithActionAndStagers) {
	fmt.Println("MITRE ATT&CK Technique Details:")
	fmt.Printf("Technique ID:      %s\n", technique.TechniqueID)
	fmt.Printf("Absolute ID:       %s\n", technique.AbsoluteID)
	fmt.Printf("Tactic ID:         %s\n", technique.TacticID)

	if technique.SubTechniqueID != "" {
		fmt.Printf("Sub-Technique ID:  %s\n", technique.SubTechniqueID)
	}

	fmt.Printf("Step ID:           %d\n", technique.StepID)

	// Statistics
	fmt.Printf("\nExecution Statistics:\n")
	fmt.Printf("Total Executions:  %d\n", technique.Total)
	fmt.Printf("Successful:        %d", technique.Success)
	if technique.Total > 0 {
		fmt.Printf(" (%.1f%%)", float64(technique.Success)/float64(technique.Total)*100)
	}
	fmt.Printf("\n")

	fmt.Printf("Detected:          %d", technique.Detected)
	if technique.Total > 0 {
		fmt.Printf(" (%.1f%%)", float64(technique.Detected)/float64(technique.Total)*100)
	}
	fmt.Printf("\n")

	// Tactics
	if len(technique.Tactics) > 0 {
		fmt.Printf("\nTactics (%d):\n", len(technique.Tactics))
		for _, tactic := range technique.Tactics {
			fmt.Printf("  - %s\n", tactic)
		}
	}

	// Actions
	if len(technique.Actions) > 0 {
		fmt.Printf("\nAssociated Actions (%d):\n", len(technique.Actions))
		for i, action := range technique.Actions {
			if i < 10 { // Limit to first 10 to avoid overwhelming output
				fmt.Printf("  - %s\n", action)
			}
		}
		if len(technique.Actions) > 10 {
			fmt.Printf("  ... and %d more actions\n", len(technique.Actions)-10)
		}
	}

	// Stagers
	if len(technique.Stagers) > 0 {
		fmt.Printf("\nAssociated Stagers (%d):\n", len(technique.Stagers))
		for i, stager := range technique.Stagers {
			if i < 10 { // Limit to first 10
				fmt.Printf("  - %s\n", stager)
			}
		}
		if len(technique.Stagers) > 10 {
			fmt.Printf("  ... and %d more stagers\n", len(technique.Stagers)-10)
		}
	}

	// Unique executions
	if len(technique.UniqueActionsRun) > 0 {
		fmt.Printf("\nUnique Actions Executed (%d):\n", len(technique.UniqueActionsRun))
		for i, action := range technique.UniqueActionsRun {
			if i < 5 { // Limit to first 5
				fmt.Printf("  - %s\n", action)
			}
		}
		if len(technique.UniqueActionsRun) > 5 {
			fmt.Printf("  ... and %d more unique actions\n", len(technique.UniqueActionsRun)-5)
		}
	}

	if len(technique.UniqueStageRuns) > 0 {
		fmt.Printf("\nUnique Stagers Executed (%d):\n", len(technique.UniqueStageRuns))
		for i, stager := range technique.UniqueStageRuns {
			if i < 5 { // Limit to first 5
				fmt.Printf("  - %s\n", stager)
			}
		}
		if len(technique.UniqueStageRuns) > 5 {
			fmt.Printf("  ... and %d more unique stagers\n", len(technique.UniqueStageRuns)-5)
		}
	}
}
