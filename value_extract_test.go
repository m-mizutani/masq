package masq_test

import (
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

// Test struct with private fields for redaction testing
type PrivateFieldTestStruct struct {
	ExportedString    string `masq:"secret"`
	privateString     string `masq:"secret"`
	privateSensitive  string // contains "secret" text
	privateWithToken  string // contains "token" text
	privateInt        int    `masq:"secret"`
	privateBool       bool   `masq:"secret"`
	privateFloat64    float64
	privateCustomType privateCustomType
	privatePointer    *string
	privateSlice      []string
	privateMap        map[string]string
	privateStruct     struct {
		innerField string
	}
}

type privateCustomType string

func TestPrivateFieldRedaction(t *testing.T) {
	testStr := "test_pointer"
	testData := PrivateFieldTestStruct{
		ExportedString:    "exported_string",
		privateString:     "private_string",
		privateSensitive:  "contains secret information",
		privateWithToken:  "has token value",
		privateInt:        42,
		privateBool:       true,
		privateFloat64:    3.14,
		privateCustomType: "custom_value",
		privatePointer:    &testStr,
		privateSlice:      []string{"item1", "item2"},
		privateMap:        map[string]string{"key": "value"},
		privateStruct:     struct{ innerField string }{innerField: "inner_value"},
	}

	t.Run("WithTag redacts private fields with matching tags", func(t *testing.T) {
		m := masq.NewMasq(masq.WithTag("secret"))
		result := gt.Cast[PrivateFieldTestStruct](t, m.Redact(testData))

		// Exported field with "secret" tag should be redacted
		gt.V(t, result.ExportedString).Equal("[REDACTED]")
		// Private field with "secret" tag should be redacted
		gt.V(t, result.privateString).Equal("[REDACTED]")
		gt.V(t, result.privateInt).Equal(0)
		gt.V(t, result.privateBool).Equal(false)
		// Fields without "secret" tag should remain unchanged
		gt.V(t, result.privateSensitive).Equal("contains secret information")
		gt.V(t, result.privateFloat64).Equal(3.14)
	})

	t.Run("WithContain redacts private fields with matching content", func(t *testing.T) {
		m := masq.NewMasq(masq.WithContain("secret"))
		result := gt.Cast[PrivateFieldTestStruct](t, m.Redact(testData))

		// Field containing "secret" should be redacted
		gt.V(t, result.privateSensitive).Equal("[REDACTED]")
		// Fields not containing "secret" should remain unchanged
		gt.V(t, result.ExportedString).Equal("exported_string")
		gt.V(t, result.privateString).Equal("private_string")
		gt.V(t, result.privateWithToken).Equal("has token value")
		gt.V(t, result.privateInt).Equal(42)
	})

	t.Run("WithContain works with token in private fields", func(t *testing.T) {
		m := masq.NewMasq(masq.WithContain("token"))
		result := gt.Cast[PrivateFieldTestStruct](t, m.Redact(testData))

		// Field containing "token" should be redacted
		gt.V(t, result.privateWithToken).Equal("[REDACTED]")
		// Fields not containing "token" should remain unchanged
		gt.V(t, result.ExportedString).Equal("exported_string")
		gt.V(t, result.privateString).Equal("private_string")
		gt.V(t, result.privateSensitive).Equal("contains secret information")
		gt.V(t, result.privateInt).Equal(42)
	})

	t.Run("WithType redacts private fields of specific type", func(t *testing.T) {
		m := masq.NewMasq(masq.WithType[privateCustomType]())
		result := gt.Cast[PrivateFieldTestStruct](t, m.Redact(testData))

		// Private field of privateCustomType should be redacted
		gt.V(t, result.privateCustomType).Equal(privateCustomType("[REDACTED]"))
		// Other fields should remain unchanged
		gt.V(t, result.ExportedString).Equal("exported_string")
		gt.V(t, result.privateString).Equal("private_string")
		gt.V(t, result.privateInt).Equal(42)
		gt.V(t, result.privateBool).Equal(true)
	})

	t.Run("WithFieldName redacts private fields by name", func(t *testing.T) {
		m := masq.NewMasq(masq.WithFieldName("privateString"))
		result := gt.Cast[PrivateFieldTestStruct](t, m.Redact(testData))

		// Specific private field should be redacted
		gt.V(t, result.privateString).Equal("[REDACTED]")
		// Other fields should remain unchanged
		gt.V(t, result.ExportedString).Equal("exported_string")
		gt.V(t, result.privateSensitive).Equal("contains secret information")
		gt.V(t, result.privateWithToken).Equal("has token value")
		gt.V(t, result.privateInt).Equal(42)
	})

	t.Run("WithFieldPrefix redacts private fields by prefix", func(t *testing.T) {
		m := masq.NewMasq(masq.WithFieldPrefix("private"))
		result := gt.Cast[PrivateFieldTestStruct](t, m.Redact(testData))

		// All private fields starting with "private" should be redacted
		gt.V(t, result.privateString).Equal("[REDACTED]")
		gt.V(t, result.privateSensitive).Equal("[REDACTED]")
		gt.V(t, result.privateWithToken).Equal("[REDACTED]")
		gt.V(t, result.privateInt).Equal(0)
		gt.V(t, result.privateBool).Equal(false)
		gt.V(t, result.privateFloat64).Equal(0.0)
		gt.V(t, result.privateCustomType).Equal(privateCustomType("[REDACTED]"))
		// Exported field should remain unchanged
		gt.V(t, result.ExportedString).Equal("exported_string")
	})

	t.Run("Multiple filters work together", func(t *testing.T) {
		m := masq.NewMasq(
			masq.WithTag("secret"),
			masq.WithContain("secret"),
			masq.WithContain("token"),
		)
		result := gt.Cast[PrivateFieldTestStruct](t, m.Redact(testData))

		// Fields matching any filter should be redacted
		gt.V(t, result.ExportedString).Equal("[REDACTED]")   // tag:secret
		gt.V(t, result.privateString).Equal("[REDACTED]")    // tag:secret
		gt.V(t, result.privateSensitive).Equal("[REDACTED]") // contains:secret
		gt.V(t, result.privateWithToken).Equal("[REDACTED]") // contains:token
		gt.V(t, result.privateInt).Equal(0)                  // tag:secret
		gt.V(t, result.privateBool).Equal(false)             // tag:secret
		// Fields not matching any filter should remain unchanged
		gt.V(t, result.privateFloat64).Equal(3.14)
	})

	t.Run("Complex struct with nested private fields", func(t *testing.T) {
		type ComplexStruct struct {
			Exported   string
			privateKey string // should be redacted by content
			nested     struct {
				secretValue string // contains "secret"
				token       string `masq:"confidential"`
			}
		}

		complex := ComplexStruct{
			Exported:   "exported_value",
			privateKey: "my secret key",
			nested: struct {
				secretValue string
				token       string `masq:"confidential"`
			}{
				secretValue: "secret data",
				token:       "auth_token",
			},
		}

		m := masq.NewMasq(
			masq.WithContain("secret"),
			masq.WithTag("confidential"),
		)
		result := gt.Cast[ComplexStruct](t, m.Redact(complex))

		// Field containing "secret" should be redacted
		gt.V(t, result.privateKey).Equal("[REDACTED]")
		// Nested field containing "secret" should be redacted
		gt.V(t, result.nested.secretValue).Equal("[REDACTED]")
		// Nested field with confidential tag should be redacted
		gt.V(t, result.nested.token).Equal("[REDACTED]")
		// Exported field without matching criteria should remain unchanged
		gt.V(t, result.Exported).Equal("exported_value")
	})

	t.Run("Verify private field access works correctly", func(t *testing.T) {
		// Test that shows private fields can actually be accessed and redacted
		// This would fail without our unsafe value extraction implementation

		m := masq.NewMasq(masq.WithFieldPrefix("private"))
		original := testData
		result := gt.Cast[PrivateFieldTestStruct](t, m.Redact(original))

		// Verify that private fields were actually accessed and modified
		// If unsafe extraction didn't work, these would remain unchanged
		gt.V(t, result.privateString).NotEqual(original.privateString)
		gt.V(t, result.privateInt).NotEqual(original.privateInt)
		gt.V(t, result.privateBool).NotEqual(original.privateBool)
		gt.V(t, result.privateFloat64).NotEqual(original.privateFloat64)

		// Verify specific redacted values
		gt.V(t, result.privateString).Equal("[REDACTED]")
		gt.V(t, result.privateInt).Equal(0)
		gt.V(t, result.privateBool).Equal(false)
		gt.V(t, result.privateFloat64).Equal(0.0)
	})
}
