package masq_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

// =========================
// Helpers
// =========================

// createTestLogger creates a slog logger with masq options and returns a buffer to inspect outputs.
func createTestLogger(opts ...masq.Option) (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(opts...),
	})
	logger := slog.New(handler)
	return logger, buf
}

func assertContainsRedacted(t *testing.T, output string) {
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("Expected redaction but found none in: %s", output)
	}
}

func assertNotRedacted(t *testing.T, output string, _ any) {
	if strings.Contains(output, "[REDACTED]") {
		t.Errorf("Unexpected redaction found in: %s", output)
	}
}

// =========================
// Patterns
// =========================

// Basic supporting types used by patterns
type redactUserId string

type RedactProfile struct {
	Bio   string `masq:"secret"`
	Theme string `masq:"secret"`
}

type redactProfile struct {
	bio   string `masq:"secret"`
	theme string `masq:"secret"`
}

type RedactSettings struct {
	Mode string `masq:"secret"`
	Size int    `masq:"secret"`
}

type EmbeddedPointer struct {
	Data string `masq:"secret"`
}

// PrivateOnlyPattern tests redaction limitations with private fields
type PrivateOnlyPattern struct {
	name string `masq:"secret"`
}

// PrivateTaggedPattern tests redaction limitations with private tagged fields
type PrivateTaggedPattern struct {
	secret string `masq:"secret"`
}

// createDefaultPattern creates a comprehensive pattern that covers most scenarios
func createDefaultPattern() any {
	embedded := &EmbeddedPointer{Data: "embedded-pointer-data"}

	profile := &RedactProfile{Bio: "pointer-bio", Theme: "pointer-theme"}
	privateProfile := &redactProfile{bio: "private-pointer-bio", theme: "private-pointer-theme"}
	doublePtr := &profile

	profile1 := &RedactProfile{Bio: "collection-bio-1", Theme: "collection-theme-1"}
	profile2 := &RedactProfile{Bio: "collection-bio-2", Theme: "collection-theme-2"}

	return struct {
		Name          string       `masq:"secret"`
		PublicField   string       `masq:"secret"`
		privateField  string       `masq:"secret"`
		PublicInt     int          `masq:"secret"`
		privateInt    int          `masq:"secret"`
		UserId        redactUserId `masq:"secret"`
		NormalField   string
		normalPrivate string

		RedactProfile
		redactProfile
		RedactSettings
		*EmbeddedPointer
		NamedPublic  RedactProfile `masq:"secret"`
		namedPrivate redactProfile `masq:"secret"`

		PublicPtr  *RedactProfile  `masq:"secret"`
		privatePtr *redactProfile  `masq:"secret"`
		DoublePtr  **RedactProfile `masq:"secret"`
		NilPtr     *RedactProfile  `masq:"secret"`

		PublicArray  [3]RedactProfile               `masq:"secret"`
		privateArray [3]redactProfile               `masq:"secret"`
		PublicSlice  []RedactProfile                `masq:"secret"`
		privateSlice []redactProfile                `masq:"secret"`
		PointerSlice []*RedactProfile               `masq:"secret"`
		StringMap    map[string]RedactProfile       `masq:"secret"`
		privateMap   map[string]redactProfile       `masq:"secret"`
		CustomKeyMap map[redactUserId]RedactProfile `masq:"secret"`
		PointerMap   map[string]*RedactProfile      `masq:"secret"`
		NilSlice     []string                       `masq:"secret"`
		EmptyMap     map[string]string              `masq:"secret"`

		EmptyInterface any       `masq:"secret"`
		NilWriter      io.Writer `masq:"secret"`

		Secret         string `masq:"secret"`
		PublicSecret   string `masq:"secret"`
		privateSecret  string `masq:"secret"`
		MultipleTagged string `masq:"secret" json:"data"`
		MethodData     string `masq:"secret"`

		PublicAnonymous struct {
			Name  string `masq:"secret"`
			Value int    `masq:"secret"`
		} `masq:"secret"`
		privateAnonymous struct {
			name  string `masq:"secret"`
			value int    `masq:"secret"`
		} `masq:"secret"`
		UintPtr      uintptr       `masq:"secret"`
		ReflectType  reflect.Type  `masq:"secret"`
		ReflectValue reflect.Value `masq:"secret"`

		Mutex     *sync.Mutex     `masq:"secret"`
		RWMutex   *sync.RWMutex   `masq:"secret"`
		WaitGroup *sync.WaitGroup `masq:"secret"`
		Once      *sync.Once      `masq:"secret"`
		Context   context.Context `masq:"secret"`
		CreatedAt time.Time       `masq:"secret"`
		Timeout   time.Duration   `masq:"secret"`
		Location  *time.Location  `masq:"secret"`

		EmptyStruct  struct{}       `masq:"secret"`
		privateOnly1 string         `masq:"secret"`
		privateOnly2 int            `masq:"secret"`
		NilPointer   *RedactProfile `masq:"secret"`
		NilInterface io.Writer      `masq:"secret"`

		GenericValue    string `masq:"secret"`
		NumericValue    int    `masq:"secret"`
		privateGeneric  string `masq:"secret"`
		StringerName    string `masq:"secret"`
		MarshalerSecret string `masq:"secret"`
		LogValuerToken  string `masq:"secret"`

		PaddedA      byte    `masq:"secret"`
		PaddedLarge  int64   `masq:"secret"`
		PaddedB      byte    `masq:"secret"`
		PackedA      byte    `masq:"secret"`
		PackedB      byte    `masq:"secret"`
		PackedC      byte    `masq:"secret"`
		AlignedA     int64   `masq:"secret"`
		AlignedB     int64   `masq:"secret"`
		MixedByte    byte    `masq:"secret"`
		MixedInt32   int32   `masq:"secret"`
		MixedFloat64 float64 `masq:"secret"`
	}{
		Name:          "test-name-field",
		PublicField:   "test-public-field",
		privateField:  "test-private-field",
		PublicInt:     42,
		privateInt:    24,
		UserId:        redactUserId("test-user-id"),
		NormalField:   "normal-public",
		normalPrivate: "normal-private",

		RedactProfile:   RedactProfile{Bio: "public-embedded-bio", Theme: "public-theme"},
		redactProfile:   redactProfile{bio: "private-embedded-bio", theme: "private-theme"},
		RedactSettings:  RedactSettings{Mode: "embedded-mode", Size: 100},
		EmbeddedPointer: embedded,
		NamedPublic:     RedactProfile{Bio: "named-public-bio", Theme: "named-public-theme"},
		namedPrivate:    redactProfile{bio: "named-private-bio", theme: "named-private-theme"},

		PublicPtr:  profile,
		privatePtr: privateProfile,
		DoublePtr:  doublePtr,
		NilPtr:     nil,

		PublicArray:  [3]RedactProfile{{Bio: "array-bio-1"}, {Bio: "array-bio-2"}, {}},
		privateArray: [3]redactProfile{{bio: "private-array-bio-1"}, {bio: "private-array-bio-2"}, {}},
		PublicSlice:  []RedactProfile{{Bio: "slice-bio-1"}, {Bio: "slice-bio-2"}},
		privateSlice: []redactProfile{{bio: "private-slice-bio-1"}, {bio: "private-slice-bio-2"}},
		PointerSlice: []*RedactProfile{profile1, profile2},
		StringMap:    map[string]RedactProfile{"key1": {Bio: "map-bio-1"}, "key2": {Bio: "map-bio-2"}},
		privateMap:   map[string]redactProfile{"key1": {bio: "private-map-bio-1"}, "key2": {bio: "private-map-bio-2"}},
		CustomKeyMap: map[redactUserId]RedactProfile{redactUserId("custom-key-1"): {Bio: "custom-map-bio"}},
		PointerMap:   map[string]*RedactProfile{"ptr1": profile1, "ptr2": profile2},
		NilSlice:     nil,
		EmptyMap:     map[string]string{},

		EmptyInterface: "interface-test-data",
		NilWriter:      nil,

		Secret:         "field-name-secret",
		PublicSecret:   "tagged-public-secret",
		privateSecret:  "tagged-private-secret",
		MultipleTagged: "multiple-tagged-data",
		MethodData:     "method-test-data",

		PublicAnonymous: struct {
			Name  string `masq:"secret"`
			Value int    `masq:"secret"`
		}{
			Name:  "public-anon-name",
			Value: 100,
		},
		privateAnonymous: struct {
			name  string `masq:"secret"`
			value int    `masq:"secret"`
		}{
			name:  "private-anon-name",
			value: 200,
		},
		UintPtr:      uintptr(123456),
		ReflectType:  nil,
		ReflectValue: reflect.Value{},

		Mutex:     nil,
		RWMutex:   nil,
		WaitGroup: nil,
		Once:      nil,
		Context:   context.Background(),
		CreatedAt: time.Now(),
		Timeout:   time.Minute,
		Location:  time.UTC,

		EmptyStruct:  struct{}{},
		privateOnly1: "edge-private-1",
		privateOnly2: 42,
		NilPointer:   nil,
		NilInterface: nil,

		GenericValue:    "generic-test-value",
		NumericValue:    987,
		privateGeneric:  "private-generic-value",
		StringerName:    "stringer-test-name",
		MarshalerSecret: "marshaler-test-secret",
		LogValuerToken:  "logvaluer-test-token",

		PaddedA:      byte(1),
		PaddedLarge:  int64(9999999999),
		PaddedB:      byte(2),
		PackedA:      byte(10),
		PackedB:      byte(20),
		PackedC:      byte(30),
		AlignedA:     int64(1000000),
		AlignedB:     int64(2000000),
		MixedByte:    byte(5),
		MixedInt32:   int32(12345),
		MixedFloat64: float64(3.14159),
	}
}

func createPrivateOnlyPattern() PrivateOnlyPattern {
	return PrivateOnlyPattern{name: "private-field-name"}
}

func createPrivateTaggedPattern() PrivateTaggedPattern {
	return PrivateTaggedPattern{secret: "private-tagged-secret"}
}

func createContentBasedPattern() any {
	return struct {
		GenericValue    string `masq:"secret"`
		NumericValue    int    `masq:"secret"`
		privateGeneric  string `masq:"secret"`
		StringerName    string `masq:"secret"`
		MarshalerSecret string `masq:"secret"`
		LogValuerToken  string `masq:"secret"`
	}{
		GenericValue:    "generic-test-value",
		NumericValue:    987,
		privateGeneric:  "private-generic-value",
		StringerName:    "stringer-test-name",
		MarshalerSecret: "marshal-secret-data",
		LogValuerToken:  "logvaluer-test-token",
	}
}

// Logical pattern types
type TestPatternType int

const (
	PatternDefault TestPatternType = iota
	PatternPrivateOnly
	PatternPrivateTagged
	PatternContentBased
)

func createPatternByType(patternType TestPatternType) any {
	switch patternType {
	case PatternPrivateOnly:
		return createPrivateOnlyPattern()
	case PatternPrivateTagged:
		return createPrivateTaggedPattern()
	case PatternContentBased:
		return createContentBasedPattern()
	case PatternDefault:
		fallthrough
	default:
		return createDefaultPattern()
	}
}

// =========================
// Basic tests
// =========================

// TestRedaction_BasicCases consolidates basic pattern tests with minimal duplication
func TestRedaction_BasicCases(t *testing.T) {
	type testCase struct {
		name         string
		patternType  TestPatternType
		option       masq.Option
		shouldRedact bool
	}

	run := func(tc testCase) func(t *testing.T) {
		return func(t *testing.T) {
			logger, buf := createTestLogger(tc.option)
			pattern := createPatternByType(tc.patternType)
			logger.Info("test", "data", pattern)
			out := buf.String()
			if tc.shouldRedact {
				assertContainsRedacted(t, out)
			} else {
				assertNotRedacted(t, out, pattern)
			}
		}
	}

	cases := []testCase{
		{"Default_WithTag", PatternDefault, masq.WithTag("secret"), true},
		{"Default_WithFieldName_Name", PatternDefault, masq.WithFieldName("Name"), true},
		{"Default_WithType_Custom", PatternDefault, masq.WithType[redactUserId](), true},
		{"PrivateOnly_CannotRedact", PatternPrivateOnly, masq.WithTag("secret"), false},
		{"PrivateTagged_CannotRedact", PatternPrivateTagged, masq.WithTag("secret"), false},
		{"ContentBased_ContainSecret", PatternContentBased, masq.WithContain("secret"), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, run(tc))
	}
}

// TestAllPatternTypesProcessable verifies patterns can be processed without panic
func TestAllPatternTypesProcessable(t *testing.T) {
	type testCase struct {
		name        string
		patternType TestPatternType
	}

	run := func(tc testCase) func(t *testing.T) {
		return func(t *testing.T) {
			logger, buf := createTestLogger(masq.WithTag("secret"))
			pattern := createPatternByType(tc.patternType)

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Pattern %s caused panic: %v", tc.name, r)
				}
			}()
			logger.Info("test", "data", pattern)
			_ = buf.String()
		}
	}

	cases := []testCase{
		{"Default", PatternDefault},
		{"PrivateOnly", PatternPrivateOnly},
		{"PrivateTagged", PatternPrivateTagged},
		{"ContentBased", PatternContentBased},
	}

	for _, tc := range cases {
		t.Run(tc.name, run(tc))
	}
}

// Migrated: map value redaction with tagged fields
func TestMigratedMapValueRedaction(t *testing.T) {
	type Trigger struct {
		Id string `masq:"secret"`
	}

	m := masq.New(masq.WithTag("secret"))
	attr := slog.Attr{
		Key: "masq",
		Value: slog.AnyValue(map[string]Trigger{
			"example-key": {
				Id: "example-id",
			},
		}),
	}

	result := m(nil, attr)
	redactedMap := gt.Cast[map[string]Trigger](t, result.Value.Any())
	gt.V(t, len(redactedMap)).Equal(1)
	trigger := redactedMap["example-key"]
	gt.V(t, trigger.Id).Equal("[REDACTED]")
}

// Migrated: redaction of external unexported structs
func TestMigratedRedactExternalUnexportedStructs(t *testing.T) {
	t.Run("Redact sensitive fields in unexported structs", func(t *testing.T) {
		original := NewPublicUser()
		mask := masq.NewMasq(
			masq.WithFieldName("password"),
			masq.WithFieldPrefix("api"),
			masq.WithContain("secret"),
		)
		copied := gt.Cast[*PublicUser](t, mask.Redact(original))

		gt.V(t, copied.ID).Equal("user-123")
		gt.V(t, copied.Email).Equal("john@example.com")
		gt.V(t, copied.username).Equal("john_doe")
		gt.V(t, copied.password).Equal("[REDACTED]")
	})

	t.Run("Redact nested sensitive data", func(t *testing.T) {
		original := NewPublicConfig()
		mask := masq.NewMasq(
			masq.WithFieldName("password"),
			masq.WithFieldName("dbPassword"),
			masq.WithFieldName("apiKey"),
			masq.WithFieldName("token"),
			masq.WithContain("secret"),
			masq.WithContain("postgres://"),
		)

		copied := gt.Cast[*PublicConfig](t, mask.Redact(original))

		gt.V(t, copied.AppName).Equal("TestApp")
		gt.V(t, copied.Version).Equal("1.0.0")

		gt.V(t, copied.apiKey).Equal("[REDACTED]")
		gt.V(t, copied.dbPassword).Equal("[REDACTED]")

		endpoint1 := copied.Settings.endpoints[0]
		gt.V(t, endpoint1.name).Equal("api")
		gt.V(t, endpoint1.url).Equal("https://api.example.com")
		gt.V(t, endpoint1.auth.token).Equal("[REDACTED]")

		creds := copied.Settings.credentials
		gt.V(t, creds.username).Equal("admin")
		gt.V(t, creds.password).Equal("[REDACTED]")
		gt.V(t, creds.apiKey).Equal("[REDACTED]")
	})

	t.Run("Redact selected by field name prefix", func(t *testing.T) {
		type testStruct struct {
			Public      string
			apiKey      string
			password    string
			secretKey   string
			normalField string
		}

		original := &testStruct{
			Public:      "public",
			apiKey:      "sk-1234567890abcdef",
			password:    "my-password",
			secretKey:   "my-secret",
			normalField: "normal",
		}

		mask := masq.NewMasq(
			masq.WithFieldPrefix("api"),
			masq.WithFieldName("password"),
			masq.WithContain("secret"),
		)
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, copied.apiKey).Equal("[REDACTED]")
		gt.V(t, copied.password).Equal("[REDACTED]")
		// Value-based filter cannot be applied to unexported fields
		gt.V(t, copied.secretKey).Equal("my-secret")
		gt.V(t, copied.normalField).Equal("normal")
	})

	t.Run("Redact unexported struct fields with tags", func(t *testing.T) {
		type inner struct {
			value  string
			secret string `masq:"secret"`
		}
		type testStruct struct {
			Public     string
			unexported inner
			tagged     string `masq:"secret"`
		}

		original := &testStruct{
			Public:     "public",
			unexported: inner{value: "normal", secret: "confidential"},
			tagged:     "tagged-secret",
		}

		mask := masq.NewMasq(masq.WithTag("secret"))
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, copied.unexported.value).Equal("normal")
		gt.V(t, copied.unexported.secret).Equal("[REDACTED]")
		gt.V(t, copied.tagged).Equal("[REDACTED]")
	})

	t.Run("Redact unexported fields in slices", func(t *testing.T) {
		type item struct {
			id       string
			password string
		}
		type testStruct struct {
			Public string
			items  []item
		}

		original := &testStruct{
			Public: "public",
			items:  []item{{id: "1", password: "pass1"}, {id: "2", password: "pass2"}},
		}

		mask := masq.NewMasq(masq.WithFieldName("password"))
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, len(copied.items)).Equal(2)
		gt.V(t, copied.items[0].id).Equal("1")
		gt.V(t, copied.items[0].password).Equal("[REDACTED]")
		gt.V(t, copied.items[1].id).Equal("2")
		gt.V(t, copied.items[1].password).Equal("[REDACTED]")
	})

	t.Run("Redact with custom redactor for unexported fields", func(t *testing.T) {
		type testStruct struct {
			Public   string
			apiKey   string
			password string
		}

		original := &testStruct{Public: "public", apiKey: "sk-1234567890abcdef", password: "mypassword"}

		mask := masq.NewMasq(
			masq.WithFieldName("apiKey", masq.MaskWithSymbol('*', 10)),
			masq.WithFieldName("password", masq.RedactString(func(s string) string { return "XXX" })),
		)
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, copied.apiKey).Equal("********** (remained 9 chars)")
		gt.V(t, copied.password).Equal("XXX")
	})

	t.Run("Redact nested unexported pointer fields", func(t *testing.T) {
		type credential struct {
			username string
			password string
		}
		type config struct {
			name string
			cred *credential
		}
		type testStruct struct {
			Public string
			conf   *config
		}

		original := &testStruct{
			Public: "public",
			conf:   &config{name: "prod", cred: &credential{username: "admin", password: "secret123"}},
		}

		mask := masq.NewMasq(masq.WithFieldName("password"))
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, copied.conf.name).Equal("prod")
		gt.V(t, copied.conf.cred.username).Equal("admin")
		gt.V(t, copied.conf.cred.password).Equal("[REDACTED]")
	})
}

// Migrated: map[string]any redaction
func TestMigratedMapAny(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(
			masq.WithFieldName("Secret", masq.RedactString(func(s string) string { return "REDACTED" })),
		),
	}))
	logger.Info("hello", slog.Any("target", map[string]any{"Secret": "xxx"}))
	gt.S(t, buf.String()).Contains("REDACTED")
}

// Migrated: WithPrefix for map
func TestMigratedFilterWithPrefixForMap(t *testing.T) {
	type myRecord struct{ Data map[string]string }
	record := myRecord{Data: map[string]string{"secure_phone": "090-0000-0000"}}
	logger, buf := createTestLogger(masq.WithFieldPrefix("secure_"))
	logger.With("record", record).Info("Got record")
	output := buf.String()
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("Failed to filter: %s", output)
	}
	if strings.Contains(output, "090-0000-0000") {
		t.Errorf("Failed to filter: %s", output)
	}
}

// Migrated: WithTag for custom type
func TestMigratedFilterWithTagForCustomType(t *testing.T) {
	type myRecord struct {
		Data map[string]string `masq:"secret"`
	}
	record := myRecord{Data: map[string]string{"phone": "090-0000-0000"}}
	logger, buf := createTestLogger(masq.WithTag("secret"))
	logger.With("record", record).Info("Got record")
	output := buf.String()
	if strings.Contains(output, "090-0000-0000") {
		t.Errorf("Failed to filter: %s", output)
	}
}

// Migrated: Allowed type
func TestMigratedAllowedType(t *testing.T) {
	type myRecord struct{ Time time.Time }
	now := time.Now().Add(-24 * time.Hour)
	record := myRecord{Time: now}
	logger, buf := createTestLogger(masq.WithAllowedType(reflect.TypeOf(time.Time{})))
	logger.With("record", record).Info("Got record")
	if !strings.Contains(buf.String(), now.Format(time.RFC3339Nano)) {
		t.Errorf("Failed to filter: %s", buf.String())
	}
}
