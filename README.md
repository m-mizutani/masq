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

`masq` works by first cloning values and then applying redaction filters. Understanding what can be cloned determines what can be redacted.

### Processing behavior summary

```go
// Type definitions
type unexportedMapType map[string]string
type hiddenCredentials struct { Password string }  // unexported struct type
type PublicCredentials struct { Password string }  // exported struct type

type Example struct {
    // ✅ Fully processed (cloned & redacted)
    Password     string                   // Exported field - all filters work
    Users        map[string]*User          // Map with exported/pointer types
    Items        []privateData             // Slices always work
    PublicCredentials                      // Embedded exported struct

    // ⚠️ Partially processed (cloned but limited redaction)
    password     string                   // Unexported field - tag/name/prefix: ✅, type/content: ❌
    hiddenCredentials                     // Embedded unexported struct - special: all filters work on exported fields
    creds        credentials              // Regular unexported field - tag/name/prefix: ✅ on all fields, type/content: ❌

    // 🔒 Not processed (returns nil/zero value - cannot be redacted)
    private      interface{}              // Unexported interface field → nil
    Data         map[string]privateData   // Map with unexported value type → nil
    secrets      map[string]string        // Map in unexported field → nil
    unexportedMapType                     // Embedded unexported map → nil
}
```

### Detailed behavior

#### Fully processed types
These are cloned properly and all redaction filters work:
- **Exported fields**: Support all filters (tag, name, prefix, type, content)
- **Maps with exported types**: `map[string]string`, `map[K]*V` (pointer values always work)
- **Slices and arrays**: Always cloned recursively, even with unexported element types
- **Embedded exported types**: Processed like regular fields

#### Partially processed types
These are cloned but have limitations:
- **Unexported fields**: Only tag, name, and prefix filters work (not type or content)
- **Embedded unexported structs**: Special case - both exported and unexported fields are cloned and accessible; exported fields support ALL filters (treated as if directly in parent)
- **Regular unexported struct fields**: Tag/name/prefix filters work on all inner fields, but type/content filters don't work

#### Not processed types (security measure)
These return `nil` or zero values to prevent information leakage:
- **Unexported interface fields**: Always become `nil` (limitation)
- **Maps with unexported key/value types**: `map[unexportedType]V` or `map[K]unexportedType` (includes pointer types like `map[string]*unexportedType`)
- **Maps in unexported fields**: Even if the map type is exported
- **Embedded unexported map types**: Return `nil` instead of original reference

### Notes
- The security measure of returning `nil` for certain map types prevents potential bypass of access controls through reflection
- Exported interface fields work normally with all filters; only unexported interface fields become `nil`
- Pointers are always cloned with new allocation, and pointed-to values are processed recursively

### Recommendations
- For unexported fields, prefer tag, field name, or prefix filters.
- Maps with unexported types cannot be cloned, even with pointer values - consider using slices or structs instead.
- **Avoid embedding unexported structs** if their fields contain sensitive data that needs redaction - use regular struct fields instead.
- **Never embed unexported map types** as they will return `nil` for security.
- Prefer storing sensitive data in structs or slices rather than maps when possible.

## License

Apache License v2.0
