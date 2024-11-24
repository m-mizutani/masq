package masq_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"log/slog"

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

func TestJsonUnmarshalTypeError(t *testing.T) {
	// It should not panic
	logger := slog.New(
		slog.NewJSONHandler(
			os.Stdout,
			&slog.HandlerOptions{
				ReplaceAttr: masq.New(masq.WithAllowedType(reflect.TypeOf(json.UnmarshalTypeError{}))),
			},
		),
	)
	var s string
	err := json.Unmarshal([]byte(`["foo"]`), &s)
	slog.Info("error", "err", err)
	logger.Info("error", "err", err)
}
