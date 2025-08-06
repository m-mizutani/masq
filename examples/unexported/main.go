package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/m-mizutani/masq"
	"github.com/m-mizutani/masq/examples/unexported/schema"
)

func main() {
	// Create a request with embedded unexported struct
	req := schema.CreateRequest()

	fmt.Println("=== Demonstrating embedded unexported struct handling ===")
	fmt.Printf("Original struct: %+v\n", req)

	// Set up logger with masq (no filters)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))

	fmt.Println("\n=== JSON log output (no redaction) ===")
	logger.Info("Embedded unexported struct example", "request", req)

	fmt.Println("\n=== With field-based redaction ===")
	loggerWithRedaction := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: masq.New(
			masq.WithFieldName("Id"),   // Redact Id field
			masq.WithFieldName("Key"),  // Redact Key field
		),
	}))

	loggerWithRedaction.Info("Embedded unexported struct with redaction", "request", req)
}