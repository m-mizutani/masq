# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`masq` is a Go library for redacting sensitive data in structured logging with slog. It provides flexible options to identify and conceal sensitive values like API tokens, passwords, and PII (Personal Identifiable Information) in log outputs.

## Development Commands

### Testing
- **Run tests**: `go test .` (runs tests in current directory only, avoiding tmp/ directory issues)
- **Run tests with verbose output**: `go test . -v`
- **Run specific test**: `go test . -run TestFunctionName`

### Linting
- **Lint code**: The project uses golangci-lint via GitHub Actions. To run locally: `golangci-lint run`

### Dependencies
- **Update dependencies**: `go mod tidy` (Note: may fail due to tmp/ directory imports - this is expected)

## Architecture Overview

### Core Components

1. **masq.go**: Main entry point providing the `New()` function that returns a slog ReplaceAttr function
   - Contains the `masq` struct with filtering configuration
   - Orchestrates the redaction process through `redact()` method

2. **clone.go**: Deep cloning functionality to create copies of values before redaction
   - Implements recursive value cloning with cycle detection (max depth: 32)
   - Handles special types that cannot be copied (like reflect.rtype)
   - Preserves unexported fields during cloning

3. **options.go**: Configuration options for identifying values to redact
   - `WithType[T]()`: Redact by custom type
   - `WithContain()`: Redact strings containing specific text
   - `WithRegex()`: Redact by regex pattern
   - `WithTag()`: Redact struct fields with specific tags
   - `WithFieldName()`: Redact by exact field name
   - `WithFieldPrefix()`: Redact fields with specific prefix

4. **censor.go**: Implements various censoring strategies
   - Type-based censoring
   - String content censoring
   - Regex pattern matching
   - Struct tag checking
   - Field name matching

5. **redactor.go**: Handles the actual value replacement
   - Defines the `Redactor` interface
   - Provides default redaction behavior (replaces with "[REDACTED]")
   - Supports custom redaction logic

### Key Design Patterns

- **Functional Options Pattern**: Used for flexible configuration via `Option` functions
- **Filter Chain**: Multiple filters can be applied, each with its own censor and redactors
- **Reflection-based Processing**: Extensively uses Go's reflect package to handle arbitrary types
- **Context-based Depth Tracking**: Prevents infinite recursion during deep cloning

### Integration with slog

The library integrates with slog through the `ReplaceAttr` handler option:

```go
logger := slog.New(
    slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        ReplaceAttr: masq.New(options...),
    }),
)
```

This intercepts all log attributes and applies redaction before output.

 Rules

### Directory

- When you are mentioned about `tmp` directory, you SHOULD NOT see `/tmp`. You need to check `./tmp` directory from root of the repository.

### Exposure policy

In principle, do not trust developers who use this library from outside

- Do not export unnecessary methods, structs, and variables
- Assume that exposed items will be changed. Never expose fields that would be problematic if changed
- Use `export_test.go` for items that need to be exposed for testing purposes

### Check

When making changes, before finishing the task, always:
- Run `go vet ./...`, `go fmt ./...` to format the code
- Run `golangci-lint run ./...` to check lint error
- Run `gosec -quiet ./...` to check security issue
- Run tests to ensure no impact on other code

### Language

All comment and character literal in source code must be in English

### Testing

- Test files should have `package {name}_test`. Do not use same package name
- **🚨 CRITICAL RULE: Test MUST be included in same name test file. (e.g. test for `abc.go` must be in `abc_test.go`) 🚨**
  - **NEVER create test files like:**
    - ❌ `e2e_test.go`
    - ❌ `integration_test.go`
    - ❌ `feature_xyz_test.go`
    - ❌ `log_test.go` (unless there's a `log.go`)
  - **ALWAYS match the source file name:**
    - ✅ `server.go` → `server_test.go`
    - ✅ `middleware.go` → `middleware_test.go`
    - ✅ `alert.go` → `alert_test.go`
  - **Before creating ANY test, ask: "Which source file does this test belong to?"**
  - **If testing multiple files' interaction, put the test in the primary file's test**
- Do not build binary. If you need to run, use `go run` command instead
- Extend timeout duration if the test fails with time out
- DO NOT use `-short`

### Test File Checklist (Use this EVERY time)
Before creating or modifying tests:
1. ✓ Is there a corresponding source file for this test file?
2. ✓ Does the test file name match exactly? (`xyz.go` → `xyz_test.go`)
3. ✓ Are all tests for a source file in ONE test file?
4. ✓ No standalone feature/e2e/integration test files?
