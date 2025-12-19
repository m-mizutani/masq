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

### What cannot be cloned

Some data cannot be cloned and will become `nil` or zero values:

```go
type privateMapType map[string]string

type Example struct {
    // ❌ Cannot be cloned - these become nil/zero values

    // Embedded private map types
    privateMapType
}
```

**Result**: These fields become `nil` or zero values in the output for security reasons. Note that:
- Maps with unexported key or value types can now be cloned, provided the types themselves are composed of fields that can be redacted
- Private interface fields (including `error` types) are now properly preserved and can be redacted (fixed in v0.2.1+)

### Recommendations

- Use struct fields instead of maps when storing sensitive data
- Keep maps in public fields with public key/value types
- Use struct tags (`masq:"secret"`) for reliable redaction

## License

Apache License v2.0
