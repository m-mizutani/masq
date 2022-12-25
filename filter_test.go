package masq_test

import (
	"encoding/json"
	"os"
	"regexp"

	"github.com/m-mizutani/masq"
	"golang.org/x/exp/slog"
)

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

	logger := slog.New(slog.HandlerOptions{
		ReplaceAttr: masq.New(masq.WithType[password]()),
	}.NewJSONHandler(out))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Password":"[FILTERED]"},"time":"2022-12-25T09:00:00.123456789"}
}

func ExampleWithString() {
	out := &fixedTimeWriter{}

	const issuedToken = "abcd1234"
	authHeader := "Authorization: Bearer " + issuedToken

	logger := slog.New(slog.HandlerOptions{
		ReplaceAttr: masq.New(masq.WithString("abcd1234")),
	}.NewJSONHandler(out))

	logger.With("auth", authHeader).Info("send header")
	out.Flush()
	// Output:
	// {"auth":"Authorization: Bearer [FILTERED]","level":"INFO","msg":"send header","time":"2022-12-25T09:00:00.123456789"}
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

	logger := slog.New(slog.HandlerOptions{
		ReplaceAttr: masq.New(
			masq.WithRegex(regexp.MustCompile(`^\d{3}-\d{4}-\d{4}$`)),
		),
	}.NewJSONHandler(out))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Phone":"[FILTERED]"},"time":"2022-12-25T09:00:00.123456789"}
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

	logger := slog.New(slog.HandlerOptions{
		ReplaceAttr: masq.New(masq.WithTag("secret")),
	}.NewJSONHandler(out))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"EMail":"[FILTERED]","ID":"m-mizutani"},"time":"2022-12-25T09:00:00.123456789"}
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

	logger := slog.New(slog.HandlerOptions{
		ReplaceAttr: masq.New(
			masq.WithFieldName("Phone"),
		),
	}.NewJSONHandler(out))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Phone":"[FILTERED]"},"time":"2022-12-25T09:00:00.123456789"}
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

	logger := slog.New(slog.HandlerOptions{
		ReplaceAttr: masq.New(
			masq.WithFieldPrefix("Secure"),
		),
	}.NewJSONHandler(out))

	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","SecurePhone":"[FILTERED]"},"time":"2022-12-25T09:00:00.123456789"}
}
