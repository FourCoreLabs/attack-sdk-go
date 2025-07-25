package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/fourcorelabs/attack-sdk-go/pkg/actions"
	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/chains"
	"github.com/fourcorelabs/attack-sdk-go/pkg/emailchains"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/fourcorelabs/attack-sdk-go/pkg/wafchains"
)

var (
	// Flags for endpoint chain execution
	endpointAssetIDs       []string
	endpointDisableCleanup bool
	endpointRunElevated    bool

	// Flags for email chain execution
	emailAssetIDs       []string
	emailDisableCleanup bool

	// Flags for WAF chain execution
	wafAssetIDs       []string
	wafDisableCleanup bool

	// New flags for endpoint action execution
	endpointStagersRaw []string // To populate AttackRunActionsStagers.Stagers (e.g., "id:mode" strings)
)

// actionCmd represents the action command
var actionCmd = &cobra.Command{
	Use:   "action",
	Short: "Execute attack actions",
	Long:  `Execute different types of attack actions and stagers including endpoint, email, and WAF.`,
	// No RunE needed for the parent command if it only groups subcommands
}

var endpointActionCmd = &cobra.Command{
	Use:   "endpoint <action_id...>", // Allow multiple action IDs as positional arguments
	Short: "Execute an endpoint attack actions and stagers",
	Args:  cobra.MinimumNArgs(1), // Require at least one action ID
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}
		if len(endpointAssetIDs) == 0 {
			return fmt.Errorf("at least one asset ID is required for endpoint actions")
		}

		// Parse stagersRaw into models.AttackStager
		var stagers []models.AttackStager
		for _, s := range endpointStagersRaw {
			id, mode, ok := strings.Cut(s, ":")
			if !ok {
				return fmt.Errorf("invalid stager format: %s. Expected 'stager_id:stager_mode'", s)
			}
			stagers = append(stagers, models.AttackStager{
				StagerID:   id,
				StagerMode: mode,
			})
		}

		attackRun := models.AttackRunActionsStagers{
			AttackRun: models.AttackRun{
				Assets:         endpointAssetIDs,
				DisableCleanup: &endpointDisableCleanup,
				RunElevated:    &endpointRunElevated,
			},
			Actions: args,    // Populate Actions from args
			Stagers: stagers, // Populate Stagers from parsed flag
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		// Pass the collected positional arguments as actionID to the ExecuteEndpointAction function [1]
		execution, err := actions.ExecuteEndpointAction(context.Background(), client, attackRun)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				// Error message updated since it's now multiple action IDs
				return fmt.Errorf("endpoint action(s) not found or API error: %w", err)
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			// Handle other potential errors
			return fmt.Errorf("failed to execute endpoint action: %w", err)
		}

		// --- Output ---
		printExecutionDetails(execution)
		return nil
	},
}

// chainCmd represents the chain command
var chainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Execute attack chains",
	Long:  `Execute different types of attack chains including endpoint, email, and WAF.`,
	// No RunE needed for the parent command if it only groups subcommands
}

var endpointChainCmd = &cobra.Command{
	Use:   "endpoint <chain_id>",
	Short: "Execute an endpoint attack chain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}
		if len(endpointAssetIDs) == 0 {
			return fmt.Errorf("at least one asset ID is required for endpoint chains")
		}

		chainID := args[0]
		attackRun := models.AttackRun{
			Assets:         endpointAssetIDs,
			DisableCleanup: &endpointDisableCleanup,
			RunElevated:    &endpointRunElevated,
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		execution, err := chains.ExecuteEndpointChain(context.Background(), client, chainID, attackRun)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("endpoint chain not found: %s", chainID)
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			// Handle other potential errors
			return fmt.Errorf("failed to execute endpoint chain: %w", err)
		}

		// --- Output ---
		printExecutionDetails(execution)
		return nil
	},
}

var emailChainCmd = &cobra.Command{
	Use:   "email <chain_id>",
	Short: "Execute an email attack chain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}
		if len(emailAssetIDs) == 0 {
			return fmt.Errorf("at least one email asset ID is required for email chains")
		}

		chainID := args[0]
		attackRun := models.AttackRun{
			EmailAssets:    emailAssetIDs,
			DisableCleanup: &emailDisableCleanup,
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		execution, err := emailchains.ExecuteEmailChain(context.Background(), client, chainID, attackRun)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("email chain not found: %s", chainID)
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			// Handle other potential errors
			return fmt.Errorf("failed to execute email chain: %w", err)
		}

		// --- Output ---
		printAttackExecutionDetails(execution)
		return nil
	},
}

var wafChainCmd = &cobra.Command{
	Use:   "waf <chain_id>",
	Short: "Execute a WAF attack chain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}
		if len(wafAssetIDs) == 0 {
			return fmt.Errorf("at least one WAF asset ID is required for WAF chains")
		}

		chainID := args[0]
		attackRun := models.AttackRun{
			WafAssets:      wafAssetIDs,
			DisableCleanup: &wafDisableCleanup,
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		execution, err := wafchains.ExecuteWAFChain(context.Background(), client, chainID, attackRun)
		if err != nil {
			// Check for specific API errors
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("WAF chain not found: %s", chainID)
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			// Handle other potential errors
			return fmt.Errorf("failed to execute WAF chain: %w", err)
		}

		// --- Output ---
		printExecutionDetails(execution)
		return nil
	},
}

func init() {
	// Add chain command to root command
	rootCmd.AddCommand(chainCmd)
	rootCmd.AddCommand(actionCmd)

	// Add subcommands to the action command
	actionCmd.AddCommand(endpointActionCmd)

	// Add subcommands to the chain command
	chainCmd.AddCommand(endpointChainCmd)
	chainCmd.AddCommand(emailChainCmd)
	chainCmd.AddCommand(wafChainCmd)

	// Define flags for endpoint action command (re-using some existing ones)
	endpointActionCmd.Flags().StringSliceVarP(&endpointAssetIDs, "assets", "a", []string{}, "Comma-separated list of asset IDs")
	endpointActionCmd.Flags().BoolVar(&endpointDisableCleanup, "disable-cleanup", false, "Disable cleanup after execution")
	endpointActionCmd.Flags().BoolVar(&endpointRunElevated, "run-elevated", false, "Run with elevated privileges")
	// New flags for multiple stagers
	endpointActionCmd.Flags().StringSliceVar(&endpointStagersRaw, "stagers", []string{}, "Comma-separated list of stagers in 'stager_id:stager_mode' format")
	// Mark "assets" flag as required for endpoint actions
	endpointActionCmd.MarkFlagRequired("assets")

	// Define flags for endpoint chain command
	endpointChainCmd.Flags().StringSliceVarP(&endpointAssetIDs, "assets", "a", []string{}, "Comma-separated list of asset IDs")
	endpointChainCmd.Flags().BoolVar(&endpointDisableCleanup, "disable-cleanup", false, "Disable cleanup after execution")
	endpointChainCmd.Flags().BoolVar(&endpointRunElevated, "run-elevated", false, "Run with elevated privileges")
	// Mark "assets" flag as required for endpoint chains
	endpointChainCmd.MarkFlagRequired("assets")

	// Define flags for email chain command
	emailChainCmd.Flags().StringSliceVarP(&emailAssetIDs, "email-assets", "e", []string{}, "Comma-separated list of email asset IDs")
	emailChainCmd.Flags().BoolVar(&emailDisableCleanup, "disable-cleanup", false, "Disable cleanup after execution")
	// Mark "email-assets" flag as required for email chains
	emailChainCmd.MarkFlagRequired("email-assets")

	// Define flags for WAF chain command
	wafChainCmd.Flags().StringSliceVarP(&wafAssetIDs, "waf-assets", "w", []string{}, "Comma-separated list of WAF asset IDs")
	wafChainCmd.Flags().BoolVar(&wafDisableCleanup, "disable-cleanup", false, "Disable cleanup after execution")
	// Mark "waf-assets" flag as required for WAF chains
	wafChainCmd.MarkFlagRequired("waf-assets")
}

// printExecutionDetails prints the details of a GetExecutionResponse in JSON format.
func printExecutionDetails(execution models.GetExecutionResponse) {
	details, err := json.MarshalIndent(execution, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling execution details: %v\n", err)
		return
	}
	fmt.Println(string(details))
}

// printAttackExecutionDetails prints the details of an AttackExecution in JSON format.
func printAttackExecutionDetails(execution models.AttackExecution) {
	details, err := json.MarshalIndent(execution, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling execution details: %v\n", err)
		return
	}
	fmt.Println(string(details))
}
