package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the CLI configuration.
type Config struct {
	APIKey  string `json:"api_key"`
	BaseURL string `json:"base_url"`
}

// DefaultConfig returns the default configuration values *stored in the file*.
// The effective default (like base URL) might be applied elsewhere if the file value is empty.
func DefaultConfig() Config {
	return Config{
		// BaseURL: "https://prod.fourcore.io", // Can keep or remove, root.go handles effective default
	}
}

// LoadConfig loads the configuration from the config file.
func LoadConfig() (Config, error) {
	cfg := DefaultConfig() // Start with file defaults (which might be empty strings)

	configPath, err := getConfigPath()
	if err != nil {
		return cfg, err // Return default struct + error getting path
	}

	// If config file doesn't exist, return the default struct without error
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return cfg, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return cfg, fmt.Errorf("failed to read config file '%s': %w", configPath, err)
	}

	// If the file is empty, return the default struct without error
	if len(data) == 0 {
		return cfg, nil
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		// Provide more context on parse error
		return cfg, fmt.Errorf("failed to parse config file '%s': %w. Content: %s", configPath, err, string(data))
	}

	return cfg, nil
}

// SaveConfig saves the configuration to the config file.
func SaveConfig(cfg Config) error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0750); err != nil { // Use 0750 for permissions
		return fmt.Errorf("failed to create config directory '%s': %w", configDir, err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write with 0600 permissions (read/write for user only)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file '%s': %w", configPath, err)
	}

	return nil
}

// getConfigPath returns the path to the config file.
func getConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	// Use .fourcore directory directly under home for simplicity, or keep .config/fourcore
	// configDir := filepath.Join(homeDir, ".config", "fourcore")
	configDir := filepath.Join(homeDir, ".fourcore") // Example alternative
	return filepath.Join(configDir, "config.json"), nil
}
