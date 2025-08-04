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

### ❌ Maps with unexported value types

Due to Go's reflection API limitations, `masq` cannot properly clone maps that have unexported types as values. This includes both direct unexported types and pointers to unexported types. For example:

```go
type privateData struct {
    id string
}

type Container struct {
    // Neither of these maps can be fully cloned due to unexported types
    dataMap    map[string]privateData  // Direct unexported type
    pointerMap map[string]*privateData // Pointer to unexported type
}
```

In such cases, the original map is returned as-is without cloning. This is a fundamental limitation of Go's reflection system, where `reflect.Value.SetMapIndex` cannot be used with values obtained from unexported types.

### ❌ Unexported interface fields

Unexported fields with interface{} type can cause runtime errors when accessed through reflection. This is a fundamental limitation of Go's type system and reflection API. For example:

```go
type MyStruct struct {
    data interface{} // unexported interface field - may cause runtime errors
}
```

**Workaround:** Use exported interface fields or concrete types instead of unexported interface fields.

### ❌ Content-based filters on unexported fields

Content-based filters like `WithContain()` and `WithRegex()` do not work on unexported fields because the field values cannot be accessed through reflection. These filters only work on exported fields.

**Note:** Field name and tag-based filters (`WithFieldName()`, `WithFieldPrefix()`, `WithTag()`) work correctly on unexported fields.

### Working collection types

The following collection types work correctly with unexported types:
- Slices of unexported types (e.g., `[]privateData`) - ✅ Properly cloned
- Arrays of unexported types (e.g., `[3]privateData`) - ✅ Properly cloned (including redaction)
- Slices of pointers to unexported types (e.g., `[]*privateData`) - ✅ Properly cloned
- Maps with unexported types (e.g., `map[string]privateData`) - ❌ Not cloned (limitation)

**Workarounds:**
- Use exported types for map values
- Keep sensitive data in regular struct fields or slices (not in maps) where masq can properly handle unexported types
- Use wrapper types that are exported

## License

Apache License v2.0
