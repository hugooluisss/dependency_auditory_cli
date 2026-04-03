# depguard

`depguard` is a Go CLI focused on AI-consumable dependency metadata for dependency ecosystems such as Composer, npm, Go Modules and Python.

## Design goals

- Stable, predictable JSON as primary output.
- Structured results always on stdout.
- Internal errors/logs only on stderr.
- Small commands that are easy to compose.
- `audit scan` combines local heuristics with remote vulnerability sources when available.

## MVP scope

Current ecosystem support:

- PHP Composer (`composer.json`, `composer.lock`)
- npm / Node.js (`package.json`, `package-lock.json`, `npm-shrinkwrap.json`)
- Go Modules (`go.mod`, `go.sum`)
- Python (`requirements.txt`, `requirements-dev.txt`, `poetry.lock`, `Pipfile.lock`, `requirements.lock`)

Not included yet:

- Reputation scoring
- SARIF output
- Additional ecosystems (Java/.NET/Ruby and others)

Included now:

- Local heuristic scan (`audit scan`) for suspicious risk signals
- Remote OSV vulnerability lookup for locked dependencies in Composer, npm, Go Modules, and Python

## Installation

```bash
go mod tidy
go build -o depguard .
```

## Usage

Global flags available on all commands:

- `--path` (default: `.`)
- `--format` (default: `json`, currently only supported value)
- `--offline` (default: `false`, disables remote vulnerability lookup)

### Detect project ecosystem

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

Example for npm:

```json
{
  "ok": true,
  "data": {
    "project_path": ".",
    "ecosystem": "npm",
    "manifests": {
      "package.json": true,
      "package-lock.json": true,
      "npm-shrinkwrap.json": false
    }
  },
  "error": null
}
```

Example for Go Modules:

```json
{
  "ok": true,
  "data": {
    "project_path": ".",
    "ecosystem": "go-mod",
    "manifests": {
      "go.mod": true,
      "go.sum": true
    }
  },
  "error": null
}
```

Example for Python:

```json
{
  "ok": true,
  "data": {
    "project_path": ".",
    "ecosystem": "python",
    "manifests": {
      "requirements.txt": true,
      "requirements-dev.txt": true,
      "poetry.lock": false,
      "Pipfile.lock": false,
      "requirements.lock": true
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

If a lockfile is missing:

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

npm lockfile error example:

```json
{
  "ok": false,
  "data": null,
  "error": {
    "code": "LOCKFILE_NOT_FOUND",
    "message": "package-lock.json or npm-shrinkwrap.json file was not found"
  }
}
```

Go Modules lockfile error example:

```json
{
  "ok": false,
  "data": null,
  "error": {
    "code": "LOCKFILE_NOT_FOUND",
    "message": "go.sum file was not found"
  }
}
```

Python lockfile error example:

```json
{
  "ok": false,
  "data": null,
  "error": {
    "code": "LOCKFILE_NOT_FOUND",
    "message": "poetry.lock, Pipfile.lock, or requirements.lock file was not found"
  }
}
```

### Run dependency risk scan

```bash
./depguard audit scan --path . --format json
```

What this command checks in the current MVP:

- Missing lockfile (`composer.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `go.sum`, `poetry.lock`, `Pipfile.lock`, or `requirements.lock` depending on ecosystem)
- Unsafe version constraints (`*`, `latest`, `@dev`, `dev-master`)
- Development branch or non-registry constraints
- Risky script command patterns
- Missing lock metadata (`license`, `source/dist reference` or `resolved/integrity`)
- Known vulnerabilities via OSV for locked dependencies (`composer.lock`, npm lockfiles, `go.sum`, `poetry.lock`, `Pipfile.lock`, `requirements.lock`)
- Go `replace` directives to local/remote non-registry targets
- Python requirements without constraints or referencing remote direct sources

Example JSON output:

```json
{
  "ok": true,
  "data": {
    "project_path": ".",
    "ecosystem": "php-composer",
    "summary": {
      "total": 1,
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 0
    },
    "findings": [
      {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "title": "Known vulnerability affects installed package",
        "severity": "high",
        "category": "known-vulnerability",
        "package": "vendor/package",
        "scope": "packages",
        "installed_version": "1.2.3",
        "message": "Installed package \"vendor/package\" at version \"1.2.3\" is affected by GHSA-xxxx-yyyy-zzzz.",
        "confidence": "high",
        "aliases": ["CVE-2026-0001"],
        "references": ["https://example.com/advisories/GHSA-xxxx-yyyy-zzzz"],
        "published_at": "2026-04-01T00:00:00Z"
      }
    ]
  },
  "error": null
}
```

Note: OSV lookup runs only when a lockfile/source with pinned versions is present. Use `--offline` to run heuristics only.

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
    npm/
      scanner.go       ← npm implementation (Angular/React/Node)
    gomod/
      scanner.go       ← Go Modules implementation
    python/
      scanner.go       ← Python implementation (requirements/poetry/pipfile)
  parser/
    composer_json_parser.go
    composer_lock_parser.go
    package_json_parser.go
    package_lock_parser.go
    go_mod_parser.go
    go_sum_parser.go
    requirements_parser.go
    python_lock_parser.go
  infra/
    filesystem/
      reader.go
  output/
    json_writer.go
main.go
```
