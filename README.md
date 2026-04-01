# depguard

`depguard` is a Go CLI focused on AI-consumable dependency metadata for PHP Composer projects.

## Design goals

- Stable, predictable JSON as primary output.
- Structured results always on stdout.
- Internal errors/logs only on stderr.
- Small commands that are easy to compose.
- Architecture prepared to expand `audit scan` with external sources later.

## MVP scope

Current ecosystem support:

- PHP Composer (`composer.json`, `composer.lock`)

Not included yet:

- OSV or external vulnerability APIs
- Reputation scoring
- SARIF output
- Additional ecosystems (npm, pip, go)

Included now:

- Local offline heuristic scan (`audit scan`) for suspicious risk signals

## Installation

```bash
go mod tidy
go build -o depguard .
```

## Usage

Global flags available on all commands:

- `--path` (default: `.`)
- `--format` (default: `json`, currently only supported value)

### Detect Composer project

```bash
./depguard detect --path . --format json
```

Example JSON output:

```json
{
  "ok": true,
  "data": {
    "project_path": ".",
    "ecosystem": "php-composer",
    "manifests": {
      "composer.json": true,
      "composer.lock": true
    }
  },
  "error": null
}
```

### List direct dependencies

```bash
./depguard deps direct --path . --format json
```

Include dev dependencies:

```bash
./depguard deps direct --path . --format json --include-dev
```

Example JSON output:

```json
{
  "ok": true,
  "data": {
    "project_path": ".",
    "ecosystem": "php-composer",
    "dependencies": [
      {
        "name": "monolog/monolog",
        "version_constraint": "^3.0",
        "scope": "require"
      },
      {
        "name": "phpunit/phpunit",
        "version_constraint": "^11.0",
        "scope": "require-dev"
      }
    ]
  },
  "error": null
}
```

### List locked dependencies

```bash
./depguard deps locked --path . --format json
```

Example JSON output:

```json
{
  "ok": true,
  "data": {
    "project_path": ".",
    "ecosystem": "php-composer",
    "dependencies": [
      {
        "name": "monolog/monolog",
        "version": "3.5.0",
        "scope": "packages",
        "license": [
          "MIT"
        ]
      }
    ]
  },
  "error": null
}
```

If `composer.lock` is missing:

```json
{
  "ok": false,
  "data": null,
  "error": {
    "code": "LOCKFILE_NOT_FOUND",
    "message": "composer.lock file was not found"
  }
}
```

### Run local risk scan (offline)

```bash
./depguard audit scan --path . --format json
```

What this command checks in the current MVP:

- Missing `composer.lock`
- Unsafe version constraints (`*`, `@dev`, `dev-master`)
- Development branch constraints
- Risky Composer script command patterns
- Missing lock metadata (`license`, `source/dist reference`)

Example JSON output:

```json
{
  "ok": true,
  "data": {
    "project_path": ".",
    "ecosystem": "php-composer",
    "summary": {
      "total": 2,
      "critical": 0,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 0
    },
    "findings": [
      {
        "id": "DEV_BRANCH_CONSTRAINT",
        "title": "Dependency tracks a development branch",
        "severity": "high",
        "category": "supply-chain",
        "package": "vendor/package",
        "scope": "require",
        "message": "Constraint \"dev-master\" references development builds.",
        "confidence": "high"
      },
      {
        "id": "MISSING_LOCKFILE",
        "title": "composer.lock is missing",
        "severity": "medium",
        "category": "supply-chain",
        "message": "The project does not include composer.lock, which reduces dependency reproducibility.",
        "confidence": "high"
      }
    ]
  },
  "error": null
}
```

Note: this is an offline heuristic scan. It does not query CVE databases yet.

## Exit codes

- `0`: success
- `1`: input or technical error

## Project structure

```text
cmd/
  root.go
  audit.go
  audit_scan.go
  detect.go
  deps.go
  deps_direct.go
  deps_locked.go
  version.go
internal/
  domain/
    audit.go
    project.go
    dependency.go
    result.go
    errors.go
  usecase/
    audit_scan.go
    detect_project.go
    list_direct_dependencies.go
    list_locked_dependencies.go
  ecosystem/
    scanner.go         ← Scanner interface + Registry
    registry.go
    composer/
      scanner.go       ← PHP Composer implementation
    # npm/             ← future
    # gomod/           ← future
  parser/
    composer_json_parser.go
    composer_lock_parser.go
  infra/
    filesystem/
      reader.go
  output/
    json_writer.go
main.go
```
