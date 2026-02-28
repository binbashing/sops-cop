package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	sopsconfig "github.com/getsops/sops/v3/config"
)

func TestValidateYAMLContent(t *testing.T) {
	// Create a rule that requires all keys to be encrypted
	ruleAllEncrypted := &sopsconfig.Config{
		EncryptedRegex: "", // Empty means all keys should be encrypted
	}

	// Create a rule that only encrypts keys matching password|secret|token|key
	rulePartialEncryption := &sopsconfig.Config{
		EncryptedRegex: "^(password|secret|token|key|pass|token|credentials)$",
	}

	// Create a rule that allows some keys to remain plaintext.
	ruleWithUnencryptedRegex := &sopsconfig.Config{
		UnencryptedRegex: "^(host|port|username)$",
	}

	// Create a rule that encrypts only keys ending in _enc.
	ruleWithEncryptedSuffix := &sopsconfig.Config{
		EncryptedSuffix: "_enc",
	}

	// Create a rule that leaves keys ending in _plain unencrypted.
	ruleWithUnencryptedSuffix := &sopsconfig.Config{
		UnencryptedSuffix: "_plain",
	}

	// Rule with no selectors — SOPS defaults to UnencryptedSuffix: "_unencrypted"
	ruleDefault := &sopsconfig.Config{}

	tests := []struct {
		name     string
		yaml     string
		rule     *sopsconfig.Config
		wantFail []string
		wantErr  bool
	}{
		{
			name:     "all encrypted scalars pass",
			yaml:     "apiVersion: ENC[AES256_GCM,data:abc]\nkind: ENC[AES256_GCM,data:def]\nspec:\n  credentials:\n    user: ENC[AES256_GCM,data:ghi]\n    pass: ENC[AES256_GCM,data:jkl]\n  replicas:\n    - ENC[AES256_GCM,data:mno]\n",
			rule:     ruleAllEncrypted,
			wantFail: []string{},
		},
		{
			name:     "sops metadata is ignored",
			yaml:     "secret: ENC[AES256_GCM,data:abc]\nsops:\n  version: 3.9.0\n  kms:\n    - arn:aws:kms:us-east-1:123456789012:key/abcd\n",
			rule:     ruleAllEncrypted,
			wantFail: []string{},
		},
		{
			name:     "null and empty string must be encrypted when selected",
			yaml:     "service:\n  token: null\n  note: \"\"\n  password: ENC[AES256_GCM,data:abc]\n",
			rule:     ruleAllEncrypted,
			wantFail: []string{"3:9: unencrypted value found at 'service.note'"},
		},
		{
			name:     "reports nested map and array paths",
			yaml:     "services:\n  db:\n    password: plaintext\n  api:\n    keys:\n      - ENC[AES256_GCM,data:abc]\n      - not_encrypted\n",
			rule:     ruleAllEncrypted,
			wantFail: []string{"3:15: unencrypted value found at 'services.db.password'", "7:9: unencrypted value found at 'services.api.keys.1'"},
		},
		{
			name:     "non-string scalar is unencrypted",
			yaml:     "count: 3\n",
			rule:     ruleAllEncrypted,
			wantFail: []string{"1:8: unencrypted value found at 'count'"},
		},
		{
			name:     "invalid yaml returns error",
			yaml:     "key: [unclosed\n",
			rule:     ruleAllEncrypted,
			wantErr:  true,
			wantFail: nil,
		},
		{
			name:     "partial encryption: only password/secret/token/key must be encrypted",
			yaml:     "host: localhost\nport: 5432\nusername: admin\npassword: plaintext\ntoken: ENC[AES256_GCM,data:abc]\n",
			rule:     rulePartialEncryption,
			wantFail: []string{"4:11: unencrypted value found at 'password'"},
		},
		{
			name:     "unencrypted_regex: matching keys may remain plaintext",
			yaml:     "host: localhost\nport: 5432\nusername: admin\npassword: plaintext\n",
			rule:     ruleWithUnencryptedRegex,
			wantFail: []string{"4:11: unencrypted value found at 'password'"},
		},
		{
			name:     "unencrypted_regex: empty values allowed only for excluded keys",
			yaml:     "host: \"\"\nport: null\npassword: null\n",
			rule:     ruleWithUnencryptedRegex,
			wantFail: []string{},
		},
		{
			name:     "encrypted_suffix: only matching suffix keys must be encrypted",
			yaml:     "host: localhost\npassword_enc: plaintext\napi_key_enc: ENC[AES256_GCM,data:abc]\n",
			rule:     ruleWithEncryptedSuffix,
			wantFail: []string{"2:15: unencrypted value found at 'password_enc'"},
		},
		{
			name:     "unencrypted_suffix: matching suffix keys may remain plaintext",
			yaml:     "host_plain: localhost\npassword: plaintext\n",
			rule:     ruleWithUnencryptedSuffix,
			wantFail: []string{"2:11: unencrypted value found at 'password'"},
		},
		{
			name:     "default rule: keys ending in _unencrypted are excluded",
			yaml:     "password: plaintext\ndebug_unencrypted: true\n",
			rule:     ruleDefault,
			wantFail: []string{"1:11: unencrypted value found at 'password'"},
		},
		{
			name:     "default rule: all _unencrypted keys pass without encryption",
			yaml:     "token: ENC[AES256_GCM,data:abc]\nlog_level_unencrypted: info\n",
			rule:     ruleDefault,
			wantFail: []string{},
		},
		{
			name:     "empty file returns no failures",
			yaml:     "",
			rule:     ruleAllEncrypted,
			wantFail: []string{},
		},
		{
			name:     "comment-only file returns no failures",
			yaml:     "# This is a comment\n# Another comment\n",
			rule:     ruleAllEncrypted,
			wantFail: []string{},
		},
		{
			name:     "bare document separator returns no failures",
			yaml:     "---\n",
			rule:     ruleAllEncrypted,
			wantFail: []string{},
		},
		{
			name:     "unencrypted_regex excludes matching keys from encryption",
			yaml:     "runtime: prod\ntags: web\nsecret: plaintext\n",
			rule:     &sopsconfig.Config{UnencryptedRegex: "^(runtime|tags)$"},
			wantFail: []string{"3:9: unencrypted value found at 'secret'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFail, err := validateYAMLContent([]byte(tt.yaml), tt.rule)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateYAMLContent() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}

			sort.Strings(gotFail)
			sort.Strings(tt.wantFail)
			if !reflect.DeepEqual(gotFail, tt.wantFail) {
				t.Fatalf("validateYAMLContent() failures = %v, want %v", gotFail, tt.wantFail)
			}
		})
	}
}

func TestRunExitCodes(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(t *testing.T) string
		wantExitCode  int
		wantErrSubstr string
	}{
		{
			name: "file not found",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				return filepath.Join(tempDir, "nonexistent.yaml")
			},
			wantExitCode:  exitFileReadError,
			wantErrSubstr: "target not found",
		},
		{
			name: "invalid yaml in matched file",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: ".*\\.yaml$"
    encrypted_regex: ""
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "invalid.yaml"), []byte("key: [unclosed\n"), 0o600); err != nil {
					t.Fatalf("write invalid yaml: %v", err)
				}
				return tempDir
			},
			wantExitCode:  exitInvalidYAML,
			wantErrSubstr: "invalid YAML",
		},
		{
			name: "unencrypted value in matched file",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: ".*\\.yaml$"
    encrypted_regex: ""
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "unencrypted.yaml"), []byte("spec:\n  db:\n    password: plaintext\n"), 0o600); err != nil {
					t.Fatalf("write unencrypted yaml: %v", err)
				}
				return tempDir
			},
			wantExitCode:  exitUnencryptedValue,
			wantErrSubstr: "unencrypted value found",
		},
		{
			name: "valid project",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: ".*\\.yaml$"
    encrypted_regex: ""
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "valid.yaml"), []byte("key: ENC[AES256_GCM,data:abc]\n"), 0o600); err != nil {
					t.Fatalf("write valid yaml: %v", err)
				}
				return tempDir
			},
			wantExitCode:  exitSuccess,
			wantErrSubstr: "All files compliant",
		},
		{
			name: "valid project prints success summary",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: ".*\\.yaml$"
    encrypted_regex: ""
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "valid.yaml"), []byte("key: ENC[AES256_GCM,data:abc]\n"), 0o600); err != nil {
					t.Fatalf("write valid yaml: %v", err)
				}
				return tempDir
			},
			wantExitCode:  exitSuccess,
			wantErrSubstr: "All files compliant",
		},
		{
			name: "unencrypted value prints violation summary",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: ".*\\.yaml$"
    encrypted_regex: ""
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "bad.yaml"), []byte("a: plain1\nb: plain2\n"), 0o600); err != nil {
					t.Fatalf("write bad yaml: %v", err)
				}
				return tempDir
			},
			wantExitCode:  exitUnencryptedValue,
			wantErrSubstr: "SOPS-COP found 2 violations",
		},
		{
			name: "empty yaml file passes",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: ".*\\.yaml$"
    encrypted_regex: ""
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "empty.yaml"), []byte(""), 0o600); err != nil {
					t.Fatalf("write empty yaml: %v", err)
				}
				return tempDir
			},
			wantExitCode:  exitSuccess,
			wantErrSubstr: "All files compliant",
		},
		{
			name: "comment-only yaml file passes",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: ".*\\.yaml$"
    encrypted_regex: ""
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "comments.yaml"), []byte("# only comments here\n"), 0o600); err != nil {
					t.Fatalf("write comments yaml: %v", err)
				}
				return tempDir
			},
			wantExitCode:  exitSuccess,
			wantErrSubstr: "All files compliant",
		},
		{
			name: "only files matching path_regex are validated",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: "^secrets/.*\\.yaml$"
    encrypted_regex: ""
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}

				if err := os.MkdirAll(filepath.Join(tempDir, "secrets"), 0o755); err != nil {
					t.Fatalf("mkdir secrets: %v", err)
				}
				if err := os.MkdirAll(filepath.Join(tempDir, "configs"), 0o755); err != nil {
					t.Fatalf("mkdir configs: %v", err)
				}

				if err := os.WriteFile(filepath.Join(tempDir, "secrets", "bad.yaml"), []byte("password: plaintext\n"), 0o600); err != nil {
					t.Fatalf("write secrets bad yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "configs", "ignored.yaml"), []byte("password: plaintext\n"), 0o600); err != nil {
					t.Fatalf("write ignored yaml: %v", err)
				}

				return tempDir
			},
			wantExitCode:  exitUnencryptedValue,
			wantErrSubstr: "secrets/bad.yaml",
		},
		{
			name: "multiple creation rules apply different encryption to different paths",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				// Rule 1: secrets/ files must encrypt everything
				// Rule 2: configs/ files only encrypt keys matching "password"
				sopsConfig := `creation_rules:
  - path_regex: "^secrets/.*\\.yaml$"
    encrypted_regex: ""
  - path_regex: "^configs/.*\\.yaml$"
    encrypted_regex: "^password$"
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}

				if err := os.MkdirAll(filepath.Join(tempDir, "secrets"), 0o755); err != nil {
					t.Fatalf("mkdir secrets: %v", err)
				}
				if err := os.MkdirAll(filepath.Join(tempDir, "configs"), 0o755); err != nil {
					t.Fatalf("mkdir configs: %v", err)
				}

				// secrets/creds.yaml: fully encrypted — should pass
				if err := os.WriteFile(filepath.Join(tempDir, "secrets", "creds.yaml"),
					[]byte("token: ENC[AES256_GCM,data:abc]\n"), 0o600); err != nil {
					t.Fatalf("write secrets creds.yaml: %v", err)
				}

				// configs/db.yaml: host is plaintext (allowed), password is plaintext (violation)
				if err := os.WriteFile(filepath.Join(tempDir, "configs", "db.yaml"),
					[]byte("host: localhost\npassword: plaintext\n"), 0o600); err != nil {
					t.Fatalf("write configs db.yaml: %v", err)
				}

				return tempDir
			},
			wantExitCode:  exitUnencryptedValue,
			wantErrSubstr: "configs/db.yaml",
		},
		{
			name: "multiple creation rules all passing",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: "^secrets/.*\\.yaml$"
    encrypted_regex: ""
  - path_regex: "^configs/.*\\.yaml$"
    encrypted_regex: "^password$"
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}

				if err := os.MkdirAll(filepath.Join(tempDir, "secrets"), 0o755); err != nil {
					t.Fatalf("mkdir secrets: %v", err)
				}
				if err := os.MkdirAll(filepath.Join(tempDir, "configs"), 0o755); err != nil {
					t.Fatalf("mkdir configs: %v", err)
				}

				if err := os.WriteFile(filepath.Join(tempDir, "secrets", "creds.yaml"),
					[]byte("token: ENC[AES256_GCM,data:abc]\n"), 0o600); err != nil {
					t.Fatalf("write secrets creds.yaml: %v", err)
				}

				if err := os.WriteFile(filepath.Join(tempDir, "configs", "db.yaml"),
					[]byte("host: localhost\npassword: ENC[AES256_GCM,data:xyz]\n"), 0o600); err != nil {
					t.Fatalf("write configs db.yaml: %v", err)
				}

				return tempDir
			},
			wantExitCode:  exitSuccess,
			wantErrSubstr: "All files compliant",
		},
		{
			name: "invalid rule when both encrypted_regex and unencrypted_regex are set",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: ".*\\.yaml$"
    encrypted_regex: "^password$"
    unencrypted_regex: "^host$"
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "bad.yaml"), []byte("host: localhost\n"), 0o600); err != nil {
					t.Fatalf("write bad yaml: %v", err)
				}
				return tempDir
			},
			wantExitCode:  exitConfigError,
			wantErrSubstr: "cannot use more than one of encrypted_suffix",
		},
		{
			name: "invalid rule when both encrypted_suffix and unencrypted_suffix are set",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: ".*\\.yaml$"
    encrypted_suffix: "_enc"
    unencrypted_suffix: "_plain"
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "bad.yaml"), []byte("password_enc: plaintext\n"), 0o600); err != nil {
					t.Fatalf("write bad yaml: %v", err)
				}
				return tempDir
			},
			wantExitCode:  exitConfigError,
			wantErrSubstr: "cannot use more than one of encrypted_suffix",
		},
		{
			name: "invalid rule when regex and suffix selectors are mixed",
			setup: func(t *testing.T) string {
				tempDir := t.TempDir()
				sopsConfig := `creation_rules:
  - path_regex: ".*\\.yaml$"
    encrypted_regex: "^password$"
    encrypted_suffix: "_enc"
`
				if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), []byte(sopsConfig), 0o600); err != nil {
					t.Fatalf("write .sops.yaml: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tempDir, "bad.yaml"), []byte("password: plaintext\n"), 0o600); err != nil {
					t.Fatalf("write bad yaml: %v", err)
				}
				return tempDir
			},
			wantExitCode:  exitConfigError,
			wantErrSubstr: "cannot use more than one of encrypted_suffix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.setup(t)

			var stderr bytes.Buffer
			gotExitCode := run(target, &stderr)

			if gotExitCode != tt.wantExitCode {
				t.Fatalf("run() exit code = %d, want %d", gotExitCode, tt.wantExitCode)
			}

			if tt.wantErrSubstr != "" && !strings.Contains(stderr.String(), tt.wantErrSubstr) {
				t.Fatalf("run() stderr = %q, want substring %q", stderr.String(), tt.wantErrSubstr)
			}
		})
	}
}

func TestExampleSecretFixtureWithSopsConfig(t *testing.T) {
	// Use the real .sops.yaml and secrets.example.yaml from the repo.
	repoRoot, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("failed to resolve repo root: %v", err)
	}

	sopsConfigBytes, err := os.ReadFile(filepath.Join(repoRoot, ".sops.yaml"))
	if err != nil {
		t.Fatalf("read .sops.yaml: %v", err)
	}

	encryptedSecretBytes, err := os.ReadFile(filepath.Join(repoRoot, "secrets.example.yaml"))
	if err != nil {
		t.Fatalf("read secrets.example.yaml: %v", err)
	}

	t.Run("encrypted fixture passes", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), sopsConfigBytes, 0o600); err != nil {
			t.Fatalf("write .sops.yaml: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tempDir, "secrets.example.yaml"), encryptedSecretBytes, 0o600); err != nil {
			t.Fatalf("write secrets.example.yaml: %v", err)
		}

		var stderr bytes.Buffer
		gotExitCode := run(tempDir, &stderr)
		if gotExitCode != exitSuccess {
			t.Fatalf("run() exit code = %d, want %d; stderr=%q", gotExitCode, exitSuccess, stderr.String())
		}
	})

	t.Run("plaintext secret value fails", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tempDir, ".sops.yaml"), sopsConfigBytes, 0o600); err != nil {
			t.Fatalf("write .sops.yaml: %v", err)
		}

		plaintextSecretYAML := strings.Replace(string(encryptedSecretBytes),
			"DB_PASSWORD: ENC[AES256_GCM,data:c3VwZXItc2VjcmV0LXBhc3M=]",
			"DB_PASSWORD: plaintext-password", 1)

		if err := os.WriteFile(filepath.Join(tempDir, "secrets.example.yaml"), []byte(plaintextSecretYAML), 0o600); err != nil {
			t.Fatalf("write secrets.example.yaml: %v", err)
		}

		var stderr bytes.Buffer
		gotExitCode := run(tempDir, &stderr)
		if gotExitCode != exitUnencryptedValue {
			t.Fatalf("run() exit code = %d, want %d; stderr=%q", gotExitCode, exitUnencryptedValue, stderr.String())
		}

		errOut := stderr.String()
		if !strings.Contains(errOut, "secrets.example.yaml") || !strings.Contains(errOut, "stringData.DB_PASSWORD") {
			t.Fatalf("run() stderr = %q, want references to secrets.example.yaml and stringData.DB_PASSWORD", errOut)
		}
	})
}
