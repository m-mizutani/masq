package masq_test

import (
	"os"

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
