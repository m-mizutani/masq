# masq: redacting sensitive data in slog [![Go Reference](https://pkg.go.dev/badge/github.com/m-mizutani/masq.svg)](https://pkg.go.dev/github.com/m-mizutani/masq) [![test](https://github.com/m-mizutani/masq/actions/workflows/test.yml/badge.svg)](https://github.com/m-mizutani/masq/actions/workflows/test.yml) [![gosec](https://github.com/m-mizutani/masq/actions/workflows/gosec.yml/badge.svg)](https://github.com/m-mizutani/masq/actions/workflows/gosec.yml) [![trivy](https://github.com/m-mizutani/masq/actions/workflows/trivy.yml/badge.svg)](https://github.com/m-mizutani/masq/actions/workflows/trivy.yml)

`masq` is a redacting utility to conceal sensitive data for [slog](https://pkg.go.dev/golang.org/x/exp/slog) that is official Go structured logging library. The concealing feature reduce risk to store secret values (API token, password and such things) and sensitive data like PII (Personal Identifiable Information) such as address, phone number, email address and etc into logging storage.


```go
u := struct {
    ID    string
    Email EmailAddr
}{
    ID:    "u123",
    Email: "mizutani@hey.com",
}

logger := slog.New(
    slog.NewJSONHandler(
        os.Stdout,
        &slog.HandlerOptions{
            ReplaceAttr: masq.New(masq.WithType[EmailAddr]()),
        },
    ),
)

logger.Info("hello", slog.Any("user", u))
```

Then, output is following (jq formatted).

```json
{
  "time": "2022-12-25T09:00:00.123456789",
  "level": "INFO",
  "msg": "hello",
  "user": {
    "ID": "u123",
    "Email": "[FILTERED]" // <- Concealed
  }
}
```

## Usage

`masq.New()` provides a function for `ReplaceAttr` of `slog.HandlerOptions`. `masq.New` can specify one or multiple `masq.Option` to identify value and field to be concealed.

```go
logger := slog.New(
    slog.NewJSONHandler(
        os.Stdout,
		&slog.HandlerOptions{
            ReplaceAttr: masq.New(
                // By user defined custom type
                masq.WithType[AccessToken](),

                // By regex of phone number as e164 format
                masq.WithRegex(regexp.MustCompile(`^\+[1-9]\d{1,14}$`)),

                // By field tag such as masq:"secret"
                masq.WithTag("secret"),

                // By by field name prefix. Concealing SecureXxx field
                masq.WithFieldPrefix("Secure"),
            ),
        },
    ),
)
```

### With custom type

```go
type password string
type myRecord struct {
    ID       string
    Password password
}
record := myRecord{
    ID:       "m-mizutani",
    Password: "abcd1234",
}

logger := slog.New(
    slog.NewJSONHandler(
        os.Stdout,
		&slog.HandlerOptions{
            ReplaceAttr: masq.New(masq.WithType[password]()),
        },
    ),
)

logger.With("record", record).Info("Got record")
out.Flush()
// Output:
// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Password":"[FILTERED]"},"time":"2022-12-25T09:00:00.123456789"}
```

### With fixed string

```go
const issuedToken = "abcd1234"
authHeader := "Authorization: Bearer " + issuedToken

logger := slog.New(
    slog.NewJSONHandler(
        os.Stdout,
        &slog.HandlerOptions{
            ReplaceAttr: masq.New(masq.WithContain("abcd1234")),
        },
    ),
)

logger.With("auth", authHeader).Info("send header")
out.Flush()
// Output:
// {"auth":"[REDACTED]","level":"INFO","msg":"send header","time":"2022-12-25T09:00:00.123456789"}
```

## With regex

```go
type myRecord struct {
    ID    string
    Phone string
}
record := myRecord{
    ID:    "m-mizutani",
    Phone: "090-0000-0000",
}

logger := slog.New(
    slog.NewJSONHandler(
        os.Stdout,
        &slog.HandlerOptions{
            ReplaceAttr: masq.New(masq.WithRegex(regexp.MustCompile(`^\d{3}-\d{4}-\d{4}$`)),
        },
    ),
)

logger.With("record", record).Info("Got record")
out.Flush()
// Output:
// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Phone":"[FILTERED]"},"time":"2022-12-25T09:00:00.123456789"}
```

### With struct field tag

```go
type myRecord struct {
    ID    string
    EMail string `masq:"secret"`
}
record := myRecord{
    ID:    "m-mizutani",
    EMail: "mizutani@hey.com",
}

logger := slog.New(
    slog.NewJSONHandler(
        os.Stdout,
        &slog.HandlerOptions{
            ReplaceAttr: masq.New(masq.WithTag("secret")),
        },
    ),
)

logger.With("record", record).Info("Got record")
out.Flush()
// Output:
// {"level":"INFO","msg":"Got record","record":{"EMail":"[FILTERED]","ID":"m-mizutani"},"time":"2022-12-25T09:00:00.123456789"}
```

You can change the tag key by `masq.WithCustomTagKey` option.

```go
type myRecord struct {
    ID    string
    EMail string `custom:"secret"`
}

record := myRecord{
    ID:    "m-mizutani",
    EMail: "mizutani@hey.com",
}

logger := newLogger(out, masq.New(
    masq.WithCustomTagKey("custom"),
    masq.WithTag("secret"),
))

logger.With("record", record).Info("Got record")
out.Flush()
// Output:
// {"level":"INFO","msg":"Got record","record":{"EMail":"[REDACTED]","ID":"m-mizutani"},"time":"2022-12-25T09:00:00.123456789"}
```

### With struct field name

```go
type myRecord struct {
    ID    string
    Phone string
}
record := myRecord{
    ID:    "m-mizutani",
    Phone: "090-0000-0000",
}

logger := slog.New(
    slog.NewJSONHandler(
        os.Stdout,
        &slog.HandlerOptions{
            ReplaceAttr: masq.New(masq.WithFieldName("Phone")),
        },
    ),
)

logger.With("record", record).Info("Got record")
out.Flush()
// Output:
// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Phone":"[FILTERED]"},"time":"2022-12-25T09:00:00.123456789"}
```

### With struct field prefix

```go
type myRecord struct {
    ID          string
    SecurePhone string
}
record := myRecord{
    ID:          "m-mizutani",
    SecurePhone: "090-0000-0000",
}

logger := slog.New(
    slog.NewJSONHandler(
        os.Stdout,
        &slog.HandlerOptions{
            ReplaceAttr: masq.New(masq.WithFieldPrefix("Secure")),
        },
    ),
)

logger.With("record", record).Info("Got record")
out.Flush()
// Output:
// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","SecurePhone":"[FILTERED]"},"time":"2022-12-25T09:00:00.123456789"}
```

## Limitations

`masq` uses reflection to traverse and process values. The behavior is easiest to understand from two perspectives: Redaction (what gets masked) and Cloning (what gets copied vs kept as-is).

### Redaction
Example-first summary (what gets masked vs not):

```go
type RedactionCase struct {
    // Fields
    Password string `masq:"secret"` // ✅ Redacted (exported; tag/type/content apply)
    password string `masq:"secret"` // ✅ Redacted (unexported; tag/name/prefix only)
    apiKey   string                  // ✅ Redacted by name/prefix; ❌ not by content/type

    // Maps
    Users   map[string]*privateUser  // ✅ Elements redacted when filters match
    Data    map[string]privateData   // ❌ Values not inspected (unexported non-pointer value type)
    secrets map[string]string        // ❌ Not inspected (map in unexported field)

    // Interface
    anyValue interface{}             // ❌ Not inspected by type/content; name/tag/prefix on the field applies
}
```

Notes:
- Exported fields: all filters work (tag, name, prefix, type, content). Unexported: only tag/name/prefix.
- Map values are redacted only when the map is cloneable (see Cloning) and filters match.
- Unexported interface fields are safe (no panic) but not inspectable by type/content.

### Cloning
Example-first summary (what is copied vs returned as zero value):

```go
type unexportedMapType map[string]string
type exportedMapType map[string]string

type CloneCase struct {
    // Arrays / Slices
    Items []privateData            // ✅ Cloned recursively (unexported element types OK)

    // Maps
    A map[string]*privateData      // ✅ Map cloned; elements are reallocated as new pointers
    B map[string]privateData       // 🔒 Returns nil (unexported non-pointer value type - security measure)
    C map[unexportedKey]string     // 🔒 Returns nil (unexported key type - security measure)
    d map[string]string            // 🔒 Returns nil (map in unexported field - security measure)

    // Embedded Types
    unexportedMapType              // 🔒 Returns nil (embedded unexported map type - security measure)
    ExportedMapType                // ✅ Map cloned (embedded exported map type)
    hiddenCredentials              // ❌ Embedded unexported struct: fields not redacted
    PublicCredentials              // ✅ Embedded exported struct: fields processed normally

    // Pointers
    Cred *cred                     // ✅ New allocation; pointed-to values processed recursively
}
```

Notes:
- Arrays/slices are cloned and processed recursively, even with unexported element types.
- Maps are cloned when key and value types are exported, or when the value type is a pointer (`*T`). Pointer types are considered exported even if `T` is unexported.
- **Security measure**: Maps with unexported key or value types, or maps in unexported fields, return `nil` instead of the original reference to prevent potential information leakage through reflection bypass.
- **Embedded types**: Unexported embedded types (both struct and map) return zero values for security. Exported embedded types are processed normally.
- Pointers are cloned with new allocation; pointed-to values are processed recursively.

### Recommendations
- For unexported fields, prefer tag, field name, or prefix filters.
- If a map must contain unexported types, use pointer values (e.g., `map[string]*T`) to enable cloning.
- **Avoid unexported embedded types** (both struct and map) for sensitive data; use exported embedded types or regular struct fields instead.
- Prefer storing sensitive data in structs or slices rather than maps when possible.

## License

Apache License v2.0
