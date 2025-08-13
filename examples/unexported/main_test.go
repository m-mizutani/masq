package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/m-mizutani/gt"
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
	gt.V(t, output).NotEqual("")

	// Debug: print the actual output to understand what's happening
	t.Logf("Actual JSON output: %s", output)

	// Parse JSON and verify structure and values
	var out map[string]any
	gt.NoError(t, json.Unmarshal(buf.Bytes(), &out))

	// Verify the request field exists
	reqData, ok := out["request"].(map[string]any)
	gt.B(t, ok).True()
	gt.V(t, reqData).NotNil()

	// Verify trigger field and its ID
	trigger, ok := reqData["trigger"].(map[string]any)
	gt.B(t, ok).True()
	gt.V(t, trigger["id"]).Equal("example-trigger-id")

	// Verify use_secrets field
	useSecrets, ok := reqData["use_secrets"].(bool)
	gt.B(t, ok).True()
	gt.B(t, useSecrets).True()

	// Verify individual_secrets field and its key
	secrets, ok := reqData["individual_secrets"].([]any)
	gt.B(t, ok).True()
	gt.V(t, len(secrets)).Equal(1)

	secret, ok := secrets[0].(map[string]any)
	gt.B(t, ok).True()
	gt.V(t, secret["key"]).Equal("example-key")

	// The test demonstrates that unexported struct fields can be successfully processed
	// and cloned properly when accessed through reflection
	t.Logf("Successfully processed unexported struct: %+v", req)
}
