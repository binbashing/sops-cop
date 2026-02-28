package main

import (
	"fmt"
	"path/filepath"
	"strings"

	sopsconfig "github.com/getsops/sops/v3/config"
)

// SopsConfig holds resolved SOPS config file location details.
type SopsConfig struct {
	ConfigPath string
	ConfigDir  string
}

// loadSopsConfig resolves .sops.yaml using SOPS native lookup behavior.
func loadSopsConfig(startDir string) (*SopsConfig, string, error) {
	absStartDir, err := filepath.Abs(startDir)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve directory: %w", err)
	}

	// SOPS lookup expects a file path and starts from its parent directory.
	lookupStart := filepath.Join(absStartDir, "__sops_cop_lookup_start__")

	configPath, err := sopsconfig.FindConfigFile(lookupStart)
	if err != nil {
		return nil, "", fmt.Errorf("no .sops.yaml file found in directory hierarchy")
	}

	configDir := filepath.Dir(configPath)
	return &SopsConfig{ConfigPath: configPath, ConfigDir: configDir}, configDir, nil
}

// loadCreationRuleForFile resolves the matching creation rule using SOPS native matching.
// The bool return indicates whether a rule matched.
func loadCreationRuleForFile(config *SopsConfig, filePath string) (*sopsconfig.Config, bool, error) {
	if config == nil {
		return nil, false, fmt.Errorf("missing sops config context")
	}

	rule, err := sopsconfig.LoadCreationRuleForFile(config.ConfigPath, filePath, nil)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "no matching creation rules found") {
			return nil, false, nil
		}
		return nil, false, err
	}

	if rule == nil {
		return nil, false, nil
	}

	return rule, true, nil
}
