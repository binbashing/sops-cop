# Next Steps

## Goal
Extend `sops-cop` beyond YAML to support JSON, ENV, and INI using a single generic SOPS-tree validation path, with best-effort (or absent) positional output for non-YAML formats.

## Principles
- Keep SOPS behavior authoritative for rule matching and "should encrypt" logic.
- Reuse `LoadCreationRuleForFile` and dry-run `tree.Encrypt` path selection.
- Use one generic tree walker for all formats (`TreeBranch` / arrays / scalar values).
- Minimize custom parsing logic; only add what is needed for reporting.
- Preserve existing CLI behavior and exit codes.

## Phase 1 — Core Refactor (format-aware validation)
1. Add format detection for matched files using SOPS format helpers.
2. Replace YAML-only gate in `validateProject` with a supported-format gate:
   - Supported: YAML, JSON, ENV, INI.
   - Unsupported: keep warning and skip.
3. Replace `validateYAMLContent` call path with a new dispatcher:
   - `validateContentByFormat(filePath, data, rule)`
   - routes to format-specific SOPS store loading, then a shared validator.
4. Refactor `computeSOPSSelectedPaths` to accept format and use matching SOPS store:
   - YAML: `stores/yaml`
   - JSON: `stores/json`
   - ENV: `stores/dotenv`
   - INI: `stores/ini`
5. Build one shared validator that:
   - runs dry-run `tree.Encrypt` to mark selected paths,
   - walks the tree generically,
   - flags selected scalar values that are not `ENC[...]`.

## Phase 2 — Shared validation engine
1. Keep YAML-specific path for positional output (`line:column`) as the high-fidelity implementation.
2. Add generic tree traversal for all formats loaded via SOPS stores:
   - traverse map-like branches (`TreeBranch`), arrays (`[]interface{}`), and scalars.
   - skip `sops` metadata key.
   - use joined path (`a.b.0.c`) consistently across formats.
3. For each selected scalar path, fail if value is not a string with `ENC[` prefix.
4. Use the same failure text format for all formats, with/without positions based on availability.

## Phase 3 — Output contract
1. Keep linter-style format when line/column exist:
   - `file:line:col: unencrypted value found at '<path>'`
2. For formats without positions, keep clean deterministic fallback:
   - `file: unencrypted value found at '<path>'`
3. Keep summary banner and exit codes unchanged.

## Phase 4 — Tests
1. Add unit tests for format dispatcher.
2. Add unit tests for shared generic walker behavior (map/array/scalar across formats).
3. Add fixtures and tests for JSON/ENV/INI success/failure via store-loaded trees.
4. Add integration-style `run()` tests covering:
   - mixed-format repos
   - rule matching across multiple creation rules
   - empty/near-empty content handling per format where applicable
5. Keep existing YAML tests unchanged as regression suite.

## Phase 5 — Docs and release notes
1. Update `README.md` format support section to list YAML/JSON/ENV/INI.
2. Clarify positional output behavior by format (exact for YAML, best-effort/path-only elsewhere).
3. Add short examples for each format.

## Effort Estimate
- Core refactor + dispatcher: ~2–3 hours
- Shared generic walker + tests: ~2–3 hours
- JSON/ENV/INI format wiring + tests: ~2–3 hours
- Docs + cleanup: ~1 hour
- Total: ~1 focused day

## Risks / Unknowns
- Mapping SOPS store structures cleanly back to user-facing paths for every format.
- Edge-case parsing differences between raw file parser and SOPS store normalization.
- Ensuring no regressions to current YAML positional reporting.

## Suggested Execution Order
1. Format dispatcher + store-based `computeSOPSSelectedPaths` refactor.
2. Shared generic walker implementation.
3. Output fallback standardization.
4. JSON/ENV/INI test coverage.
5. README updates.
