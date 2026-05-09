package masq_test

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"

	"log/slog"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

type EmailAddr string

func Example() {
	u := struct {
		ID    string
		Email EmailAddr
	}{
		ID:    "u123",
		Email: "mizutani@hey.com",
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: masq.New(masq.WithType[EmailAddr]()),
	}))

	logger.Info("hello", slog.Any("user", u))
}

// TestNewSmokeOptions runs each WithXxx option through the slog ReplaceAttr
// pipeline to confirm end-to-end wiring. Detailed semantics for each option
// live in options_test.go (Examples + dedicated tests).
func TestNewSmokeOptions(t *testing.T) {
	type secretStr string

	type record struct {
		ID        string
		Email     string `masq:"secret"`
		Password  secretStr
		Phone     string
		SecureKey string
		Note      string
	}
	rec := record{
		ID:        "u1",
		Email:     "user@example.com",
		Password:  "p@ss",
		Phone:     "090-1234-5678",
		SecureKey: "abc",
		Note:      "contains a token here",
	}

	cases := []struct {
		name     string
		opts     []masq.Option
		mustHave []string
		mustMiss []string
	}{
		{
			name:     "WithTag",
			opts:     []masq.Option{masq.WithTag("secret")},
			mustHave: []string{`"Email":"[REDACTED]"`, `"Password":"p@ss"`},
		},
		{
			name:     "WithType",
			opts:     []masq.Option{masq.WithType[secretStr]()},
			mustHave: []string{`"Password":"[REDACTED]"`, `"Email":"user@example.com"`},
		},
		{
			name:     "WithContain",
			opts:     []masq.Option{masq.WithContain("token")},
			mustHave: []string{`"Note":"[REDACTED]"`, `"ID":"u1"`},
		},
		{
			name:     "WithRegex",
			opts:     []masq.Option{masq.WithRegex(regexp.MustCompile(`^\d{3}-\d{4}-\d{4}$`))},
			mustHave: []string{`"Phone":"[REDACTED]"`, `"ID":"u1"`},
		},
		{
			name:     "WithFieldName",
			opts:     []masq.Option{masq.WithFieldName("Phone")},
			mustHave: []string{`"Phone":"[REDACTED]"`, `"ID":"u1"`},
		},
		{
			name:     "WithFieldPrefix",
			opts:     []masq.Option{masq.WithFieldPrefix("Secure")},
			mustHave: []string{`"SecureKey":"[REDACTED]"`, `"ID":"u1"`},
		},
		{
			name: "WithRedactMessage",
			opts: []masq.Option{
				masq.WithFieldName("Phone"),
				masq.WithRedactMessage("****"),
			},
			mustHave: []string{`"Phone":"****"`},
			mustMiss: []string{`[REDACTED]`},
		},
		{
			name: "WithCustomTagKey",
			opts: []masq.Option{
				masq.WithCustomTagKey("custom"),
				masq.WithTag("hide"),
			},
			// no field uses `custom:"hide"` tag in record, so nothing redacted
			mustHave: []string{`"Email":"user@example.com"`},
			mustMiss: []string{`[REDACTED]`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := newLogger(&buf, masq.New(tc.opts...))
			logger.Info("msg", slog.Any("rec", rec))
			out := buf.String()
			for _, want := range tc.mustHave {
				if !strings.Contains(out, want) {
					t.Errorf("expected %q in output:\n%s", want, out)
				}
			}
			for _, miss := range tc.mustMiss {
				if strings.Contains(out, miss) {
					t.Errorf("did not expect %q in output:\n%s", miss, out)
				}
			}
		})
	}
}

func TestNewWithNilValue(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogger(&buf, masq.New(masq.WithFieldName("X")))
	logger.Info("msg", slog.Any("nilv", nil))
	gt.S(t, buf.String()).Contains(`"nilv":null`)
}

type logValuer struct{}

func (logValuer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("color", "blue"),
		slog.Any("number", "five"),
	)
}

func TestLogValuer(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogger(&buf, masq.New())
	logger.Info("test", slog.Any("group", logValuer{}))
	out := buf.String()
	gt.S(t, out).Contains(`"color":"blue"`).Contains(`"number":"five"`)
}

func TestArray(t *testing.T) {
	v := struct {
		Values [2]string
	}{Values: [2]string{"blue", "five"}}

	var buf bytes.Buffer
	logger := newLogger(&buf, masq.New())
	logger.Info("hello", slog.Any("values", v))
	out := buf.String()
	gt.S(t, out).Contains(`"blue"`).Contains(`"five"`)
}

func TestNewWithCustomCensor(t *testing.T) {
	// WithCensor allows callers to wire arbitrary censor logic.
	// Redact whenever the field name starts with "S".
	type rec struct {
		Name   string
		Secret string
		Sensor string
	}
	censor := masq.Censor(func(fieldName string, value any, tag string) bool {
		return strings.HasPrefix(fieldName, "S")
	})

	var buf bytes.Buffer
	logger := newLogger(&buf, masq.New(masq.WithCensor(censor)))
	logger.Info("msg", slog.Any("rec", rec{Name: "a", Secret: "b", Sensor: "c"}))
	out := buf.String()
	gt.S(t, out).
		Contains(`"Name":"a"`).
		Contains(`"Secret":"[REDACTED]"`).
		Contains(`"Sensor":"[REDACTED]"`)
}
