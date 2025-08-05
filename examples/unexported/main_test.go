package main

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/m-mizutani/masq"
	"github.com/m-mizutani/masq/examples/unexported/schema"
)

func TestUnexported(t *testing.T) {
	req := schema.CreateRequest()

	// Test through slog to ensure the complete integration works
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))

	logger.Info("testing unexported struct", "request", req)

	output := buf.String()
	if output == "" {
		t.Fatal("Expected log output but got empty string")
	}

	// Debug: print the actual output to understand what's happening
	t.Logf("Actual JSON output: %s", output)

	// Verify that the original values are present in the output (no redaction applied)
	if !bytes.Contains(buf.Bytes(), []byte("example-trigger-id")) {
		t.Error("Expected trigger Id to be included but not found in output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("example-key")) {
		t.Error("Expected secret Key to be included but not found in output")
	}

	// The test demonstrates that unexported struct fields can be successfully processed
	// and cloned properly when accessed through reflection
	t.Logf("Successfully processed unexported struct: %+v", req)
}