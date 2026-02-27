# sops-enforcer

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go)](https://go.dev/)
[![CI](https://github.com/binbashing/sops-enforcer/actions/workflows/ci.yml/badge.svg)](https://github.com/binbashing/sops-enforcer/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-go%20test%20.%2F...-brightgreen)](https://github.com/binbashing/sops-enforcer/actions/workflows/ci.yml)

A small, fast Go CLI that enforces SOPS encryption rules without requiring the SOPS binary or encryption keys; designed for commit hooks and CI jobs.

## How it works

- Locates `.sops.yaml` by walking up from the provided path (or current directory).
- Scans files matched by `creation_rules` and checks that selected values are encrypted.
- Reports each unencrypted key path to `stderr` with file path and line:column location.

## Exit codes

- `0`: all checked values are encrypted
- `3`: file read error (for example, file missing or permission denied)
- `4`: invalid YAML input
- `5`: one or more unencrypted values were found
- `6`: `.sops.yaml` config error (for example, invalid regex)

## Requirements

- Go 1.23+

If you install from release binaries, Go is not required.

## Install

### Option 1: `go install`

```bash
go install github.com/binbashing/sops-enforcer@latest
```

### Option 2: prebuilt release binary (no Go required)

Download the correct archive from the GitHub Releases page for your OS/arch, extract it, and place `sops-enforcer` on your `PATH`.

## Build

```bash
go build -o sops-enforcer .
```

## Usage

```bash
./sops-enforcer
```

Or start from any path inside the project:

```bash
./sops-enforcer -target path/to/any/subdir
```

Help:

```bash
./sops-enforcer -h
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
./sops-enforcer -target ./secrets
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
./sops-enforcer -target .
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
