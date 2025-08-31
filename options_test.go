package masq_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"log/slog"

	"github.com/m-mizutani/masq"
)

func newLogger(w io.Writer, f func(groups []string, a slog.Attr) slog.Attr) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: f,
	}))
}

type fixedTimeWriter struct {
	buf []byte
}

func (x *fixedTimeWriter) Write(p []byte) (n int, err error) {
	x.buf = append(x.buf, p...)
	return len(p), nil
}

func (x *fixedTimeWriter) Flush() {
	var m map[string]any
	if err := json.Unmarshal(x.buf, &m); err != nil {
		panic("failed to unmarshal")
	}
	m["time"] = "2022-12-25T09:00:00.123456789"

	raw, err := json.Marshal(m)
	if err != nil {
		panic("failed to marshal")
	}

	if _, err := os.Stdout.Write(raw); err != nil {
		panic("can not output")
	}
}

func ExampleWithType() {
	out := &fixedTimeWriter{}

	type password string
	type myRecord struct {
		ID       string
		Password password
	}
	record := myRecord{
		ID:       "m-mizutani",
		Password: "abcd1234",
	}

	logger := newLogger(out, masq.New(masq.WithType[password]()))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Password":"[REDACTED]"},"time":"2022-12-25T09:00:00.123456789"}
}

func ExampleWithContain() {
	out := &fixedTimeWriter{}

	const issuedToken = "abcd1234"
	authHeader := "Authorization: Bearer " + issuedToken

	logger := newLogger(out, masq.New(masq.WithContain("abcd1234")))

	logger.With("auth", authHeader).Info("send header")
	out.Flush()
	// Output:
	// {"auth":"[REDACTED]","level":"INFO","msg":"send header","time":"2022-12-25T09:00:00.123456789"}
}

func ExampleWithRegex() {
	out := &fixedTimeWriter{}

	type myRecord struct {
		ID    string
		Phone string
	}
	record := myRecord{
		ID:    "m-mizutani",
		Phone: "090-0000-0000",
	}

	logger := newLogger(out, masq.New(
		masq.WithRegex(regexp.MustCompile(`^\d{3}-\d{4}-\d{4}$`)),
	))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Phone":"[REDACTED]"},"time":"2022-12-25T09:00:00.123456789"}
}

func ExampleWithTag() {
	out := &fixedTimeWriter{}

	type myRecord struct {
		ID    string
		EMail string `masq:"secret"`
	}
	record := myRecord{
		ID:    "m-mizutani",
		EMail: "mizutani@hey.com",
	}

	logger := newLogger(out, masq.New(masq.WithTag("secret")))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"EMail":"[REDACTED]","ID":"m-mizutani"},"time":"2022-12-25T09:00:00.123456789"}
}

func ExampleWithCustomTagKey() {
	out := &fixedTimeWriter{}

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
}

func TestCustomTagKeyPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Errorf("Failed to panic")
		}
	}()

	masq.New(masq.WithCustomTagKey(""))
}

func ExampleWithFieldName() {
	out := &fixedTimeWriter{}

	type myRecord struct {
		ID    string
		Phone string
	}
	record := myRecord{
		ID:    "m-mizutani",
		Phone: "090-0000-0000",
	}
	logger := newLogger(out, masq.New(masq.WithFieldName("Phone")))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Phone":"[REDACTED]"},"time":"2022-12-25T09:00:00.123456789"}
}

func ExampleWithFieldPrefix() {
	out := &fixedTimeWriter{}

	type myRecord struct {
		ID          string
		SecurePhone string
	}
	record := myRecord{
		ID:          "m-mizutani",
		SecurePhone: "090-0000-0000",
	}

	logger := newLogger(out, masq.New(masq.WithFieldPrefix("Secure")))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","SecurePhone":"[REDACTED]"},"time":"2022-12-25T09:00:00.123456789"}
}

func ExampleWithRedactMessage() {
	out := &fixedTimeWriter{}

	type myRecord struct {
		ID    string
		Phone string
	}
	record := myRecord{
		ID:    "m-mizutani",
		Phone: "090-0000-0000",
	}

	logger := newLogger(out, masq.New(
		masq.WithFieldName("Phone"),
		masq.WithRedactMessage("****"),
	))
	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Phone":"****"},"time":"2022-12-25T09:00:00.123456789"}
}

func ExampleRedactString() {
	out := &fixedTimeWriter{}

	type myRecord struct {
		ID    string
		Phone string
		Email string
	}
	record := myRecord{
		ID:    "m-mizutani",
		Phone: "090-0000-1234",
		Email: "mizutani@hey.com",
	}

	logger := newLogger(out, masq.New(
		// custom redactor
		masq.WithFieldName("Phone",
			masq.RedactString(func(s string) string {
				return "****-" + s[len(s)-4:]
			}),
		),
		// default redactor
		masq.WithFieldName("Email"),
	))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"Email":"[REDACTED]","ID":"m-mizutani","Phone":"****-1234"},"time":"2022-12-25T09:00:00.123456789"}
}

type logValuer struct {
}

func (x logValuer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("color", "blue"),
		slog.Any("number", "five"),
	)
}

func TestLogValuer(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogger(&buf, masq.New())

	var v logValuer
	logger.Info("test", slog.Any("group", v))
	t.Log(buf.String())
	if !strings.Contains(buf.String(), `"color":"blue"`) {
		t.Errorf("Failed to filter: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"number":"five"`) {
		t.Errorf("Failed to filter: %s", buf.String())
	}
}

func TestArray(t *testing.T) {
	v := struct {
		Values [2]string
	}{
		Values: [2]string{"blue", "five"},
	}

	var buf bytes.Buffer
	logger := newLogger(&buf, masq.New())
	logger.Info("hello", slog.Any("values", v))

	if !strings.Contains(buf.String(), `"blue"`) {
		t.Errorf("Failed to filter: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"five"`) {
		t.Errorf("Failed to filter: %s", buf.String())
	}

}
