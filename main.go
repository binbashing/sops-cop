package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sops "github.com/getsops/sops/v3"
	sopsformats "github.com/getsops/sops/v3/cmd/sops/formats"
	sopsconfig "github.com/getsops/sops/v3/config"
	sopsstores "github.com/getsops/sops/v3/stores"
	sopsyaml "github.com/getsops/sops/v3/stores/yaml"
	"gopkg.in/yaml.v3"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const (
	encryptedPrefix = "ENC["
	dryRunMarker    = "__SOPS_COP_SELECTED__"

	exitSuccess          = 0
	exitInvalidArguments = 2
	exitFileReadError    = 3
	exitInvalidYAML      = 4
	exitUnencryptedValue = 5
	exitConfigError      = 6
)

// main configures CLI behavior and exits with process-level status codes.
func main() {
	target := flag.String("target", ".", "Path inside a SOPS project (optional). Used to locate .sops.yaml")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Fprintf(os.Stdout, "sops-cop %s\n", version)
		os.Exit(exitSuccess)
	}

	os.Exit(run(*target, os.Stderr))
}

// usage prints CLI help text and available flags.
func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "sops-cop %s\n\n", version)
	fmt.Fprintln(out, "Validates that YAML values are encrypted according to .sops.yaml rules.")
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  sops-cop [-target <path-inside-project>]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "The enforcer locates .sops.yaml from the provided path (or current directory),")
	fmt.Fprintln(out, "then scans the SOPS project and validates files matched by path_regex rules.")
	fmt.Fprintln(out)
	flag.PrintDefaults()
}

// run executes validation and returns an exit code.
func run(target string, stderr io.Writer) int {
	if strings.TrimSpace(target) == "" {
		target = "."
	}

	// Resolve absolute path
	absTarget, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(stderr, "error: failed to resolve path: %v\n", err)
		return exitInvalidArguments
	}

	// Check if target exists
	info, err := os.Stat(absTarget)
	if err != nil {
		fmt.Fprintf(stderr, "error: target not found: %v\n", err)
		return exitFileReadError
	}

	// Load .sops.yaml
	startDir := absTarget
	if !info.IsDir() {
		startDir = filepath.Dir(absTarget)
	}

	config, configDir, err := loadSopsConfig(startDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitConfigError
	}

	// Validate all files matched by creation_rules from the SOPS project root.
	return validateProject(config, configDir, stderr)
}

// validateProject validates all files in configDir that match creation_rules.path_regex.
func validateProject(config *SopsConfig, configDir string, stderr io.Writer) int {
	exitCode := exitSuccess
	totalViolations := 0

	err := filepath.Walk(configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if filepath.Base(path) == ".sops.yaml" {
			return nil
		}

		rule, matched, err := loadCreationRuleForFile(config, path)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			exitCode = exitConfigError
			return nil
		}
		if !matched {
			return nil
		}

		if !sopsformats.IsYAMLFile(path) {
			fmt.Fprintf(stderr, "warning: skipping non-YAML file matched by path_regex: %s\n", path)
			return nil
		}

		code, violations := validateFileWithRule(path, rule, stderr)
		totalViolations += violations
		if code != exitSuccess && exitCode == exitSuccess {
			exitCode = code
		}

		return nil
	})

	if err != nil {
		fmt.Fprintf(stderr, "error: failed to walk project directory: %v\n", err)
		return exitFileReadError
	}

	// Summary report to stderr so it doesn't interfere with piping.
	if totalViolations > 0 {
		fmt.Fprintf(stderr, "\n🚨 SOPS-COP found %d violations! Fix these before committing.\n", totalViolations)
	} else if exitCode == exitSuccess {
		fmt.Fprintf(stderr, "\n✅ All files compliant with .sops.yaml rules.\n")
	}

	return exitCode
}

// validateFileWithRule validates a single file using a specific creation rule.
// Returns (exitCode, violationCount).
func validateFileWithRule(filePath string, rule *sopsconfig.Config, stderr io.Writer) (int, int) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(stderr, "error: failed to read file: %v\n", err)
		return exitFileReadError, 0
	}

	failures, err := validateYAMLContent(data, rule)
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid YAML: %v\n", err)
		return exitInvalidYAML, 0
	}

	if len(failures) > 0 {
		for _, msg := range failures {
			fmt.Fprintf(stderr, "%s:%s\n", filePath, msg)
		}
		return exitUnencryptedValue, len(failures)
	}

	return exitSuccess, 0
}

// validateYAMLContent parses YAML bytes and returns locations of unencrypted values that should be encrypted.
func validateYAMLContent(data []byte, rule *sopsconfig.Config) ([]string, error) {
	// Parse YAML first to detect empty or comment-only files before
	// handing data to the SOPS store, which rejects empty input.
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return []string{}, err
	}

	// Empty file or comment-only: nothing to validate.
	if len(root.Content) == 0 {
		return []string{}, nil
	}

	doc := root.Content[0]
	// Document node with no data (e.g., bare "---").
	if len(doc.Content) == 0 {
		return []string{}, nil
	}

	// Determine which paths SOPS would encrypt. tree.Encrypt with our
	// dryRunCipher respects EncryptedRegex, UnencryptedRegex, EncryptedSuffix,
	// UnencryptedSuffix, and comment-based regex selectors — mirroring SOPS's
	// own selection logic exactly.
	encryptedPaths, err := computeSOPSSelectedPaths(data, rule)
	if err != nil {
		return []string{}, err
	}

	var failures []string
	walkNode(doc, nil, &failures, encryptedPaths)

	// Ensure we return a proper empty slice, not nil.
	if failures == nil {
		failures = []string{}
	}
	return failures, nil
}

// walkNode recursively traverses YAML nodes and checks encryption based on SOPS-selected paths.
func walkNode(node *yaml.Node, path []string, failures *[]string, encryptedPaths map[string]struct{}) {
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			walkNode(child, path, failures, encryptedPaths)
		}

	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			// Always skip the sops metadata
			if keyNode.Value == sopsstores.SopsMetadataKey {
				continue
			}

			nextPath := appendPath(path, keyNode.Value)
			walkNode(valueNode, nextPath, failures, encryptedPaths)
		}

	case yaml.SequenceNode:
		for i, child := range node.Content {
			nextPath := appendPath(path, strconv.Itoa(i))
			walkNode(child, nextPath, failures, encryptedPaths)
		}

	case yaml.ScalarNode:
		// Flag this value only when both conditions are met:
		// 1. The path is in encryptedPaths (SOPS selected it for encryption).
		// 2. The value is not already encrypted (missing "ENC[" prefix or not a string).
		if _, shouldEncrypt := encryptedPaths[joinPath(path)]; shouldEncrypt && (node.Tag != "!!str" || !strings.HasPrefix(node.Value, encryptedPrefix)) {
			msg := fmt.Sprintf("%d:%d: unencrypted value found at '%s'",
				node.Line, node.Column, joinPath(path))
			*failures = append(*failures, msg)
		}

	case yaml.AliasNode:
		if node.Alias != nil {
			walkNode(node.Alias, path, failures, encryptedPaths)
		}
	}
}

// dryRunCipher is a no-op cipher that marks values as selected for encryption.
// When passed to tree.Encrypt, SOPS applies its full regex/suffix selection logic
// and calls Encrypt only for values it considers encryptable — letting us discover
// the exact set of paths SOPS would encrypt without performing real cryptography.
type dryRunCipher struct{}

func (c dryRunCipher) Encrypt(plaintext interface{}, key []byte, additionalData string) (string, error) {
	return dryRunMarker, nil
}

func (c dryRunCipher) Decrypt(ciphertext string, key []byte, additionalData string) (interface{}, error) {
	return ciphertext, nil
}

func computeSOPSSelectedPaths(data []byte, rule *sopsconfig.Config) (map[string]struct{}, error) {
	store := sopsyaml.NewStore(&sopsconfig.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(data)
	if err != nil {
		return nil, err
	}

	// Apply the SOPS default: when no selector is specified, keys ending in
	// "_unencrypted" are left as plaintext.
	unencryptedSuffix := rule.UnencryptedSuffix
	if rule.UnencryptedSuffix == "" && rule.EncryptedSuffix == "" &&
		rule.UnencryptedRegex == "" && rule.EncryptedRegex == "" &&
		rule.UnencryptedCommentRegex == "" && rule.EncryptedCommentRegex == "" {
		unencryptedSuffix = sops.DefaultUnencryptedSuffix
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			UnencryptedSuffix:       unencryptedSuffix,
			EncryptedSuffix:         rule.EncryptedSuffix,
			UnencryptedRegex:        rule.UnencryptedRegex,
			EncryptedRegex:          rule.EncryptedRegex,
			UnencryptedCommentRegex: rule.UnencryptedCommentRegex,
			EncryptedCommentRegex:   rule.EncryptedCommentRegex,
			MACOnlyEncrypted:        rule.MACOnlyEncrypted,
		},
	}

	if _, err := tree.Encrypt([]byte("sops-cop-dry-run-key"), dryRunCipher{}); err != nil {
		return nil, err
	}

	selected := make(map[string]struct{})
	for _, branch := range tree.Branches {
		collectSelectedPaths(branch, nil, selected)
	}

	return selected, nil
}

func collectSelectedPaths(value interface{}, path []string, selected map[string]struct{}) {
	switch typed := value.(type) {
	case sops.TreeBranch:
		for _, item := range typed {
			key := fmt.Sprint(item.Key)
			if key == sopsstores.SopsMetadataKey {
				continue
			}
			nextPath := appendPath(path, key)
			collectSelectedPaths(item.Value, nextPath, selected)
		}

	case []interface{}:
		for i, item := range typed {
			nextPath := appendPath(path, strconv.Itoa(i))
			collectSelectedPaths(item, nextPath, selected)
		}

	case string:
		if typed == dryRunMarker {
			selected[joinPath(path)] = struct{}{}
		}
	}
}

// appendPath creates a new path with one additional segment.
func appendPath(path []string, part string) []string {
	next := make([]string, len(path), len(path)+1)
	copy(next, path)
	return append(next, part)
}

// joinPath formats a breadcrumb path for error reporting.
func joinPath(path []string) string {
	if len(path) == 0 {
		return "<root>"
	}
	return strings.Join(path, ".")
}
