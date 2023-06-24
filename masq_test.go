package masq_test

import (
	"os"

	"github.com/m-mizutani/masq"
	"golang.org/x/exp/slog"
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
