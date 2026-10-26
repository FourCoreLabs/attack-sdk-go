package cmd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	pkgAttacks "github.com/fourcorelabs/attack-sdk-go/pkg/attacks"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/spf13/cobra"
)

// attackCmd represents the attack command
var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Custom attack operations",
	Long:  `Commands for creating, updating, running, and deleting custom attacks in the FourCore platform.`,
}

// attackCreateCmd represents the attack create command
var attackCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a custom attack",
	Long:  `Creates a custom attack from the given actions and stagers.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		wizard, err := buildAttackWizard(cmd)
		if err != nil {
			return err
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		attack, err := pkgAttacks.CreateAttack(context.Background(), client, wizard)
		if err != nil {
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			return fmt.Errorf("failed to create attack: %w", err)
		}

		// --- Output ---
		return printJSON(cmd.OutOrStdout(), attack)
	},
}

// attackUpdateCmd represents the attack update command
var attackUpdateCmd = &cobra.Command{
	Use:   "update <attack_id>",
	Short: "Update a custom attack",
	Long:  `Updates a custom attack by ID with the given actions and stagers.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		attackID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid attack id: %s", args[0])
		}

		wizard, err := buildAttackWizard(cmd)
		if err != nil {
			return err
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		response, err := pkgAttacks.UpdateAttack(context.Background(), client, attackID, wizard)
		if err != nil {
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("attack not found: %d", attackID)
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			return fmt.Errorf("failed to update attack: %w", err)
		}

		// --- Output Success ---
		if response.Success {
			fmt.Printf("Successfully updated attack: %d\n", attackID)
		} else {
			fmt.Printf("No changes made to attack: %d\n", attackID)
		}
		return nil
	},
}

// attackDeleteCmd represents the attack delete command
var attackDeleteCmd = &cobra.Command{
	Use:   "delete <attack_id>",
	Short: "Delete a custom attack",
	Long:  `Deletes a custom attack by ID from the FourCore platform.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		attackID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid attack id: %s", args[0])
		}

		// Confirm deletion if confirm flag not set
		confirm, _ := cmd.Flags().GetBool("confirm")
		if !confirm {
			fmt.Printf("Are you sure you want to delete attack %d? (y/N): ", attackID)
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
		response, err := pkgAttacks.DeleteAttack(context.Background(), client, attackID)
		if err != nil {
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("attack not found: %d", attackID)
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			return fmt.Errorf("failed to delete attack: %w", err)
		}

		// --- Output Success ---
		if response.Success {
			fmt.Printf("Successfully deleted attack: %d\n", attackID)
		} else {
			fmt.Printf("No changes made to attack: %d\n", attackID)
		}
		return nil
	},
}

// attackRunCmd represents the attack run command
var attackRunCmd = &cobra.Command{
	Use:   "run <attack_id>",
	Short: "Run a custom attack",
	Long:  `Runs a custom attack by ID on the specified assets.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// --- Validation ---
		if apiKeyVal == "" {
			return fmt.Errorf("API key is required. Set it using --api-key flag, FOURCORE_API_KEY environment variable, or 'config set api-key' command")
		}

		attackID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid attack id: %s", args[0])
		}

		assets, _ := cmd.Flags().GetStringSlice("assets")
		if len(assets) == 0 {
			return fmt.Errorf("at least one asset ID is required to run an attack")
		}

		disableCleanup, _ := cmd.Flags().GetBool("disable-cleanup")
		runElevated, _ := cmd.Flags().GetBool("run-elevated")

		attackRun := models.AttackRun{
			Assets:         assets,
			DisableCleanup: &disableCleanup,
			RunElevated:    &runElevated,
		}

		// --- API Client ---
		client, err := api.NewHTTPAPI(baseUrlVal, apiKeyVal)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		// --- API Call ---
		execution, err := pkgAttacks.RunAttack(context.Background(), client, attackID, attackRun)
		if err != nil {
			if errors.Is(err, api.ErrApiKeyInvalid) {
				return fmt.Errorf("API request failed: Invalid API Key")
			}
			if errors.Is(err, api.ErrNotFound) {
				return fmt.Errorf("attack not found: %d", attackID)
			}
			if errors.Is(err, api.ErrRateLimited) {
				return fmt.Errorf("API request failed: Rate limit exceeded (%w)", err)
			}
			return fmt.Errorf("failed to run attack: %w", err)
		}

		// --- Output ---
		printExecutionDetails(execution)
		return nil
	},
}

func init() {
	// Add subcommands to the attack command
	attackCmd.AddCommand(attackCreateCmd)
	attackCmd.AddCommand(attackUpdateCmd)
	attackCmd.AddCommand(attackDeleteCmd)
	attackCmd.AddCommand(attackRunCmd)

	// Add attack command to root command
	rootCmd.AddCommand(attackCmd)

	// Wizard flags, shared by create and update
	for _, c := range []*cobra.Command{attackCreateCmd, attackUpdateCmd} {
		c.Flags().StringP("name", "n", "", "Attack name")
		c.Flags().StringP("platform", "p", "", "Attack platform (windows, linux)")
		c.Flags().StringP("description", "d", "", "Attack description")
		c.Flags().StringSlice("actions", nil, "Comma-separated list of action IDs")
		c.Flags().StringSlice("malwares", nil, "Comma-separated list of malware IDs")
		c.Flags().StringSlice("stagers", nil, "Comma-separated list of stagers in 'stager_id:stager_mode' format")
		c.Flags().Bool("run-elevated", false, "Run with elevated privileges")
		c.Flags().Bool("disable-cleanup", false, "Disable cleanup after execution")
		c.MarkFlagRequired("name")
		c.MarkFlagRequired("platform")
	}

	// Delete command flags
	attackDeleteCmd.Flags().BoolP("confirm", "y", false, "Skip confirmation prompt")

	// Run command flags
	attackRunCmd.Flags().StringSliceP("assets", "a", nil, "Comma-separated list of asset IDs")
	attackRunCmd.Flags().Bool("disable-cleanup", false, "Disable cleanup after execution")
	attackRunCmd.Flags().Bool("run-elevated", false, "Run with elevated privileges")
	attackRunCmd.MarkFlagRequired("assets")
}

// buildAttackWizard assembles a CreateAttackWizard from the shared create/update flags.
func buildAttackWizard(cmd *cobra.Command) (models.CreateAttackWizard, error) {
	name, _ := cmd.Flags().GetString("name")
	platform, _ := cmd.Flags().GetString("platform")
	description, _ := cmd.Flags().GetString("description")
	actions, _ := cmd.Flags().GetStringSlice("actions")
	malwares, _ := cmd.Flags().GetStringSlice("malwares")
	stagersRaw, _ := cmd.Flags().GetStringSlice("stagers")
	runElevated, _ := cmd.Flags().GetBool("run-elevated")
	disableCleanup, _ := cmd.Flags().GetBool("disable-cleanup")

	var stagers []models.StagerInAttackWizard
	for _, s := range stagersRaw {
		id, mode, ok := strings.Cut(s, ":")
		if !ok {
			return models.CreateAttackWizard{}, fmt.Errorf("invalid stager format: %s. Expected 'stager_id:stager_mode'", s)
		}
		stagers = append(stagers, models.StagerInAttackWizard{StagerID: id, Mode: mode})
	}

	return models.CreateAttackWizard{
		Name:                name,
		Platform:            platform,
		Description:         description,
		Stager:              stagers,
		MaliciousBehaviours: models.MaliciousBehaviourInAttackWizard{MaliciousBehaviours: actions},
		Malware:             models.MalwareInAttackWizard{Malwares: malwares},
		Opts:                models.AttackOpts{RunElevated: runElevated, DisableCleanup: disableCleanup},
	}, nil
}
