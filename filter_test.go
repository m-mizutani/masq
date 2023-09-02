package masq_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

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

func ExampleWithString() {
	out := &fixedTimeWriter{}

	const issuedToken = "abcd1234"
	authHeader := "Authorization: Bearer " + issuedToken

	logger := newLogger(out, masq.New(masq.WithString("abcd1234")))

	logger.With("auth", authHeader).Info("send header")
	out.Flush()
	// Output:
	// {"auth":"Authorization: Bearer [REDACTED]","level":"INFO","msg":"send header","time":"2022-12-25T09:00:00.123456789"}
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

func TestFilterWithPrefixForMap(t *testing.T) {
	type myRecord struct {
		Data map[string]string
	}
	record := myRecord{
		Data: map[string]string{
			"secure_phone": "090-0000-0000",
		},
	}

	var buf bytes.Buffer
	logger := newLogger(&buf, masq.New(masq.WithFieldPrefix("secure_")))

	logger.With("record", record).Info("Got record")
	if !strings.Contains(buf.String(), "[REDACTED]") {
		t.Errorf("Failed to filter: %s", buf.String())
	}
	if strings.Contains(buf.String(), "090-0000-0000") {
		t.Errorf("Failed to filter: %s", buf.String())
	}
}

func TestFilterWithTagForCustomType(t *testing.T) {
	type myRecord struct {
		Data map[string]string `masq:"secret"`
	}
	record := myRecord{
		Data: map[string]string{
			"phone": "090-0000-0000",
		},
	}

	var buf bytes.Buffer
	logger := newLogger(&buf, masq.New(masq.WithTag("secret")))

	logger.With("record", record).Info("Got record")
	if strings.Contains(buf.String(), "090-0000-0000") {
		t.Errorf("Failed to filter: %s", buf.String())
	}

}

func TestAllowedType(t *testing.T) {
	type myRecord struct {
		Time time.Time
	}
	now := time.Now().Add(-time.Hour * 24)
	record := myRecord{
		Time: now,
	}

	var buf bytes.Buffer
	logger := newLogger(&buf, masq.New(masq.WithAllowedType(reflect.TypeOf(time.Time{}))))

	logger.With("record", record).Info("Got record")
	if !strings.Contains(buf.String(), now.Format(time.RFC3339Nano)) {
		t.Errorf("Failed to filter: %s", buf.String())
	}
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
