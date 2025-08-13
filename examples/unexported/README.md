# Embedded Unexported Struct Example

This example demonstrates how masq handles embedded unexported structs from external packages.

Ref: https://github.com/m-mizutani/masq/issues/28

## Problem

When dealing with structs that embed unexported types from external packages, Go's reflection system faces limitations. The embedded fields may not be properly accessible, leading to incomplete cloning and missing data in logs.

## Solution

Masq handles this by making values addressable before cloning, which allows proper access to embedded unexported struct fields through unsafe operations.

## Example Structure

```go
// External package defines:
type Request struct {
    input  // embedded unexported struct
}

type input struct {
    Trigger    *trigger  `json:"trigger"`
    UseSecrets *bool     `json:"use_secrets"`
    Secrets    *[]secret `json:"individual_secrets"`
}
```

## Running the Example

```bash
# Run the demonstration
go run .

# Run the test
go test -v
```

## Expected Output

Without masq's fix, the embedded fields would appear as `<nil>` values. With the fix, you should see:

```json
{
  "time": "2025-08-06T...",
  "level": "INFO",
  "msg": "Embedded unexported struct example",
  "request": {
    "trigger": {"id": "example-trigger-id"},
    "use_secrets": true,
    "individual_secrets": [{"key": "example-key"}]
  }
}
```

## Key Technical Details

1. **Addressable Values**: The masq library makes values addressable before cloning
2. **Unsafe Operations**: Uses unsafe pointer operations to access unexported fields
3. **Field Promotion**: Embedded struct fields are properly promoted to JSON output
4. **Selective Redaction**: Can still apply field-based redaction to embedded fields