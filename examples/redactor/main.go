package main

import (
	"log/slog"
	"os"
	"regexp"

	"github.com/m-mizutani/masq"
)

func main() {
	type myRecord struct {
		Name  string
		Phone string
		Email string
	}
	record := myRecord{
		Name:  "m-mizutani",
		Phone: "090-1234-5678",
		Email: "mizutani@hey.com",
	}

	filter := masq.New(
		masq.WithFieldName("Phone",
			masq.RedactString(func(s string) string {
				return "****-" + s[len(s)-4:]
			}),
		),
		masq.WithFieldName("Email",
			masq.RedactString(func(s string) string {
				return regexp.MustCompile(`^.*@`).ReplaceAllString(s, "***@")
			}),
		),
	)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: filter,
	}))
	logger.With("record", record).Info("Hello")
}
