# SOPS-Cop

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go)](https://go.dev/)
[![CI](https://github.com/binbashing/sops-cop/actions/workflows/ci.yml/badge.svg)](https://github.com/binbashing/sops-cop/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-go%20test%20.%2F...-brightgreen)](https://github.com/binbashing/sops-cop/actions/workflows/ci.yml)

SOPS-Cop is a CLI tool to enforce SOPS encryption rules without requiring the SOPS binary or encryption keys; designed for commit hooks and CI jobs.


## How it works

- Discovers your existing SOPS configuration and verifies encryption rules are followed.
- Supports YAML, JSON, ENV, and INI files when matched by `.sops.yaml` creation rules.
- Reports each unencrypted key path to `stderr` with file path and location details (line:column for YAML; path-only fallback for other formats).

## Exit codes

- `0`: all checked values are encrypted
- `2`: invalid arguments (for example, unresolvable target path)
- `3`: file read error (for example, file missing or permission denied)
- `4`: invalid input for the matched file format (YAML/JSON/ENV/INI)
- `5`: one or more unencrypted values were found
- `6`: `.sops.yaml` config error (for example, invalid regex)

## Requirements

- Go 1.23+

If you install from release binaries, Go is not required.

## Install

### Option 1: `go install`

```bash
go install github.com/binbashing/sops-cop@latest
```

### Option 2: prebuilt release binary (no Go required)

Download the correct binary from the GitHub Releases page for your OS/arch and place `sops-cop` on your `PATH`.

## Build

```bash
go build -o sops-cop .
```

## Usage

```bash
./sops-cop
```

Or start from any path inside the project:

```bash
./sops-cop -target path/to/any/subdir
```

Print version:

```bash
./sops-cop -version
```

Help:

```bash
./sops-cop -h
```

## Examples

Encrypted YAML (`ok.yaml`):

```yaml
apiVersion: ENC[AES256_GCM,data:abc]
kind: ENC[AES256_GCM,data:def]
spec:
  db:
    password: ENC[AES256_GCM,data:ghi]
sops:
  version: 3.9.0
```

Run from anywhere in that repo:

```bash
./sops-cop -target ./secrets
# exit code: 0
```

Unencrypted YAML (`bad.yaml`):

```yaml
spec:
  db:
    password: plaintext
```

Run:

```bash
./sops-cop -target .
# stderr:
# /path/to/repo/secrets/bad.yaml:3:15: unencrypted value found at 'spec.db.password'
# exit code: 5
```

## Test

```bash
go test ./...
go vet ./...
```

## CI

GitHub Actions runs tests on push and pull request via:

- `.github/workflows/ci.yml`

## Project structure

- `main.go`: CLI entrypoint and YAML validation logic
- `config.go`: `.sops.yaml` loading and rule matching
- `main_test.go`: table-driven unit tests
- `.sops.yaml`: example SOPS config for the included fixture
- `secrets.example.yaml`: example encrypted Kubernetes Secret
- `go.mod` / `go.sum`: module and dependency locks

## Design notes

- Uses the SOPS library (`github.com/getsops/sops/v3`) for config parsing, rule matching, and encryption path selection — ensuring exact behavioral parity with SOPS.
- Uses `gopkg.in/yaml.v3` node traversal for line:column error reporting.
- Keeps implementation in a single executable package for simplicity and portability.
- Follows fail-fast CLI behavior with deterministic exit codes for CI/pipeline integration.
