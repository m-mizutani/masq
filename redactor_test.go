package masq_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

func ExampleMaskWithSymbol() {
	out := &fixedTimeWriter{}

	type myRecord struct {
		ID    string
		Phone string
		Email string
	}
	record := myRecord{
		ID:    "m-mizutani",
		Phone: "090-0000-0000",
		// too long email address
		Email: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@example.com",
	}

	logger := newLogger(out, masq.New(
		masq.WithFieldName("Phone", masq.MaskWithSymbol('*', 32)),
		masq.WithFieldName("Email", masq.MaskWithSymbol('*', 12)),
	))
	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"Email":"************ (remained 36 chars)","ID":"m-mizutani","Phone":"*************"},"time":"2022-12-25T09:00:00.123456789"}
}

func TestMapAny(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(
			masq.WithFieldName("Secret", masq.RedactString(func(s string) string {
				return "REDACTED"
			})),
		),
	}))
	logger.Info("hello", slog.Any("target", map[string]any{"Secret": "xxx"}))
	gt.S(t, buf.String()).Contains("REDACTED")
}
