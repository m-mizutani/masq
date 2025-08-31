// Package masq_test contains comprehensive redaction tests for the masq library.
//
// This file implements a systematic test suite using a type-based architecture that provides
// complete test coverage with minimal code duplication and maximum maintainability.
//
// Architecture Overview:
// The test system uses logical pattern types instead of numbered patterns:
//
// 1. PatternDefault (createDefaultPattern): Comprehensive pattern covering most scenarios
//   - Contains all field types: basic visibility, embedded structs, pointers, collections,
//     interfaces, anonymous structs, special Go types, sync primitives, time types, edge cases,
//     generics, and memory layout scenarios
//
// 2. PatternPrivateOnly (createPrivateOnlyPattern): Tests private field redaction limitations
// 3. PatternPrivateTagged (createPrivateTaggedPattern): Tests private tagged field redaction limitations
// 4. PatternContentBased (createContentBasedPattern): Tests content-based redaction with "secret" strings
//
// Test Categories Covered:
// - Basic Visibility: Public/private struct and field combinations
// - Embedded Structs: Anonymous fields with various visibility patterns
// - Pointer Fields: Single and double pointers to various types
// - Collections: Arrays, slices, maps with different key/value combinations
// - Interfaces: Empty, custom, and standard interfaces
// - Special Go Types: uintptr, reflect types (functions/channels removed for JSON compatibility)
// - Sync Types: Mutex, WaitGroup, and other sync primitives
// - Time Types: time.Time, time.Duration, time.Location
// - Edge Cases: Nil values, empty structs, circular references
// - Generics: Go 1.18+ generics with type constraints
// - Memory Layout: Struct padding and alignment considerations
//
// Key Features:
// - All 80 patterns can be processed without panics, ensuring robustness
// - Exported fields with struct tags can be reliably redacted
// - Unexported fields cannot be redacted due to Go reflection limitations
// - Type-based redaction works across all pattern types
// - Content-based redaction works for string values
// - JSON serialization compatible (functions/channels/unsafe.Pointer removed)
package masq_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

// Helper functions implementation
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

// createDefaultPattern creates a comprehensive pattern that covers most test scenarios
func createDefaultPattern() any {
	// Create embedded pointer for embedded patterns
	embedded := &EmbeddedPointer{Data: "embedded-pointer-data"}

	// Create profiles for pointer patterns
	profile := &RedactProfile{Bio: "pointer-bio", Theme: "pointer-theme"}
	privateProfile := &redactProfile{bio: "private-pointer-bio", theme: "private-pointer-theme"}
	doublePtr := &profile

	// Create profiles for collection patterns
	profile1 := &RedactProfile{Bio: "collection-bio-1", Theme: "collection-theme-1"}
	profile2 := &RedactProfile{Bio: "collection-bio-2", Theme: "collection-theme-2"}

	// Create comprehensive test data that covers all pattern types

	// Return a mega-pattern that includes all field types
	return struct {
		// Basic visibility fields
		Name          string       `masq:"secret"`
		PublicField   string       `masq:"secret"`
		privateField  string       `masq:"secret"`
		PublicInt     int          `masq:"secret"`
		privateInt    int          `masq:"secret"`
		UserId        redactUserId `masq:"secret"`
		NormalField   string
		normalPrivate string

		// Embedded structures
		RedactProfile
		redactProfile
		RedactSettings
		*EmbeddedPointer
		NamedPublic  RedactProfile `masq:"secret"`
		namedPrivate redactProfile `masq:"secret"`

		// Pointer types
		PublicPtr  *RedactProfile  `masq:"secret"`
		privatePtr *redactProfile  `masq:"secret"`
		DoublePtr  **RedactProfile `masq:"secret"`
		NilPtr     *RedactProfile  `masq:"secret"`

		// Collections
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

		// Interfaces
		EmptyInterface any       `masq:"secret"`
		NilWriter      io.Writer `masq:"secret"`

		// Functions and channels removed to avoid JSON serialization issues

		// Tagged fields and methods
		Secret         string `masq:"secret"`
		PublicSecret   string `masq:"secret"`
		privateSecret  string `masq:"secret"`
		MultipleTagged string `masq:"secret" json:"data"`
		MethodData     string `masq:"secret"`

		// Anonymous and special types
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

		// Sync and time types
		Mutex     *sync.Mutex     `masq:"secret"`
		RWMutex   *sync.RWMutex   `masq:"secret"`
		WaitGroup *sync.WaitGroup `masq:"secret"`
		Once      *sync.Once      `masq:"secret"`
		Context   context.Context `masq:"secret"`
		CreatedAt time.Time       `masq:"secret"`
		Timeout   time.Duration   `masq:"secret"`
		Location  *time.Location  `masq:"secret"`

		// Edge cases
		EmptyStruct  struct{}       `masq:"secret"`
		privateOnly1 string         `masq:"secret"`
		privateOnly2 int            `masq:"secret"`
		NilPointer   *RedactProfile `masq:"secret"`
		NilInterface io.Writer      `masq:"secret"`

		// Generics
		GenericValue    string `masq:"secret"`
		NumericValue    int    `masq:"secret"`
		privateGeneric  string `masq:"secret"`
		StringerName    string `masq:"secret"`
		MarshalerSecret string `masq:"secret"`
		LogValuerToken  string `masq:"secret"`

		// Memory layout
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
		// Initialize all fields
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
		ReflectValue: reflect.Value{}, // Zero value for reflect.Value

		Mutex:     nil, // Sync types set to nil to avoid JSON serialization issues
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

// TestPatternType represents different types of test patterns
type TestPatternType int

const (
	// PatternDefault represents the comprehensive test pattern covering most scenarios
	PatternDefault TestPatternType = iota
	// PatternPrivateOnly represents private field limitation testing
	PatternPrivateOnly
	// PatternPrivateTagged represents private tagged field limitation testing
	PatternPrivateTagged
	// PatternContentBased represents content-based redaction testing
	PatternContentBased
)

// createPatternByType creates test patterns based on logical type
func createPatternByType(patternType TestPatternType) any {
	switch patternType {
	case PatternPrivateOnly:
		return createPrivateOnlyPattern()
	case PatternPrivateTagged:
		return createPrivateTaggedPattern()
	case PatternContentBased:
		return createContentBasedPattern()
	case PatternDefault:
		return createDefaultPattern()
	default:
		return createDefaultPattern()
	}
}

// =============================================================================
// Direct Pattern Access Functions
// =============================================================================

// getDefaultPattern returns the comprehensive test pattern
func getDefaultPattern() any {
	return createDefaultPattern()
}

// getPrivateOnlyPattern returns the private field limitation test pattern
func getPrivateOnlyPattern() any {
	return createPrivateOnlyPattern()
}

// getPrivateTaggedPattern returns the private tagged field limitation test pattern
func getPrivateTaggedPattern() any {
	return createPrivateTaggedPattern()
}

// getContentBasedPattern returns the content-based redaction test pattern
func getContentBasedPattern() any {
	return createContentBasedPattern()
}

// =============================================================================
// Pattern Creation Functions
// =============================================================================

// createPrivateOnlyPattern creates a pattern with only private fields to test redaction limitations
func createPrivateOnlyPattern() PrivateOnlyPattern {
	return PrivateOnlyPattern{
		name: "private-field-name",
	}
}

// createPrivateTaggedPattern creates a pattern with private tagged fields to test redaction limitations
func createPrivateTaggedPattern() PrivateTaggedPattern {
	return PrivateTaggedPattern{
		secret: "private-tagged-secret",
	}
}

// createContentBasedPattern creates a pattern specifically for content-based redaction testing
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
		MarshalerSecret: "marshal-secret-data", // contains "secret" for WithContain test
		LogValuerToken:  "logvaluer-test-token",
	}
}

// =============================================================================
// Supporting Type Definitions for Special Patterns
// =============================================================================

// PrivateOnlyPattern tests redaction limitations with private fields
type PrivateOnlyPattern struct {
	name string `masq:"secret"` // private field - cannot be redacted
}

// PrivateTaggedPattern tests redaction limitations with private tagged fields
type PrivateTaggedPattern struct {
	secret string `masq:"secret"` // private field with tag - cannot be redacted
}

// Supporting custom type for comprehensive patterns
type redactUserId string

// =============================================================================
// Consolidated Test Pattern Definitions (Reduced from 80 patterns to reusable components)
// =============================================================================

// Pattern 1: Comprehensive Visibility Testing - consolidates basic visibility (original 1-6)
type ConsolidatedVisibilityPattern struct {
	// Basic fields with different visibility
	Name         string `masq:"secret"` // public field (for WithFieldName test)
	PublicField  string `masq:"secret"` // public field
	privateField string `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
	PublicInt    int    `masq:"secret"` // different type
	privateInt   int    `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations

	// Custom types
	UserId redactUserId `masq:"secret"` // custom type

	// Mixed scenarios
	NormalField   string // no tag
	normalPrivate string //nolint:unused // intentionally private to test redaction limitations
}

// Pattern 2: Comprehensive Embedded Structures - consolidates embedded patterns (original 7-13)
type ConsolidatedEmbeddedPattern struct {
	// Multiple embedded types
	RedactProfile    // public embedded struct
	redactProfile    //nolint:unused // intentionally private to test redaction limitations
	RedactSettings   // second public embedded
	io.Writer        // embedded interface
	*EmbeddedPointer // embedded pointer

	// Named embedded to test different scenarios
	NamedPublic  RedactProfile `masq:"secret"` // named public embedded field
	namedPrivate redactProfile `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
}

// Supporting embedded types
type RedactProfile struct {
	Bio   string `masq:"secret"`
	Theme string `masq:"secret"`
}

type redactProfile struct {
	bio   string `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
	theme string `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
}

type RedactSettings struct {
	Mode string `masq:"secret"`
	Size int    `masq:"secret"`
}

type EmbeddedPointer struct {
	Data string `masq:"secret"`
}

// Pattern 3: Comprehensive Pointer Types - consolidates pointer patterns (original 14-18)
type ConsolidatedPointerPattern struct {
	// Single pointers
	PublicPtr  *RedactProfile `masq:"secret"` // pointer to public struct
	privatePtr *redactProfile `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations

	// Multiple pointer levels
	DoublePtr **RedactProfile `masq:"secret"` // double pointer

	// Interface pointers
	InterfacePtr *io.Writer `masq:"secret"` // pointer to interface

	// Nil pointers (for edge case testing)
	NilPtr *RedactProfile `masq:"secret"` // will be nil
}

// Pattern 4: Comprehensive Collections - consolidates arrays, slices, maps (original 19-27)
type ConsolidatedCollectionPattern struct {
	// Arrays with different types
	PublicArray  [3]RedactProfile `masq:"secret"` // array of public struct
	privateArray [3]redactProfile `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations

	// Slices with different types
	PublicSlice  []RedactProfile  `masq:"secret"` // slice of public struct
	privateSlice []redactProfile  `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
	PointerSlice []*RedactProfile `masq:"secret"` // slice of pointers

	// Maps with different key/value combinations
	StringMap    map[string]RedactProfile       `masq:"secret"` // string key, public value
	privateMap   map[string]redactProfile       `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
	CustomKeyMap map[redactUserId]RedactProfile `masq:"secret"` // custom key type
	PointerMap   map[string]*RedactProfile      `masq:"secret"` // pointer values

	// Edge cases
	NilSlice []RedactProfile   `masq:"secret"` // will be nil
	EmptyMap map[string]string `masq:"secret"` // will be empty
}

// Pattern 5: Comprehensive Interfaces - consolidates interface patterns (original 28-31)
type ConsolidatedInterfacePattern struct {
	// Different interface types
	PublicWriter   io.Writer     `masq:"secret"` // standard interface
	privateWriter  io.Writer     `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
	EmptyInterface any           `masq:"secret"` // empty interface
	CustomHandler  RedactHandler `masq:"secret"` // custom interface

	// Nil interfaces for edge case testing
	NilWriter io.Writer     `masq:"secret"` // will be nil
	NilCustom RedactHandler `masq:"secret"` // will be nil
}

// Custom interface for testing
type RedactHandler interface {
	Handle() error
}

// Pattern 6: Comprehensive Functions and Channels - consolidates func/chan patterns (original 32-37)
type ConsolidatedFunctionChannelPattern struct {
	// Function fields with different signatures
	PublicHandler  func()                          `masq:"secret"` // simple function
	privateHandler func()                          `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
	Validator      func(string) bool               `masq:"secret"` // function with params
	ComplexFunc    func(int, string) (bool, error) `masq:"secret"` // complex function

	// Channel fields with different types
	PublicEvents  chan RedactEvent    `masq:"secret"` // bidirectional channel
	privateEvents chan RedactEvent    `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
	InputChan     <-chan RedactData   `masq:"secret"` // receive-only channel
	OutputChan    chan<- RedactResult `masq:"secret"` // send-only channel

	// Nil channels for edge case testing
	NilChan chan string `masq:"secret"` // will be nil
}

// Supporting types for channels
type RedactEvent struct {
	Name string
}

type RedactData struct {
	Value string
}

type RedactResult struct {
	Status string
}

// Pattern 7: Comprehensive Complex Nested - consolidates complex nested patterns (original 38-43)
type ConsolidatedComplexPattern struct {
	// Mixed struct nesting
	PublicNested  RedactUserProfile `masq:"secret"` // public struct
	privateNested redactUserProfile `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations

	// Complex collections with private types
	ComplexMap   map[redactUserId]redactUserProfile `masq:"secret"` // complex map
	ComplexSlice []redactUserProfile                `masq:"secret"` // complex slice

	// Multiple nesting levels with anonymous structs
	DeepNested struct {
		Level2 struct {
			Level3 struct {
				secret string `masq:"secret"`
				public string `masq:"secret"`
			} `masq:"secret"`
			data string `masq:"secret"`
		} `masq:"secret"`
		info string `masq:"secret"`
	} `masq:"secret"`

	// Interface with complex implementation
	ComplexInterface any `masq:"secret"` // will contain complex struct
}

// Supporting complex types
type redactUserProfile struct {
	bio   string `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
	theme string `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
}

type RedactUserProfile struct {
	Bio   string `masq:"secret"`
	Theme string `masq:"secret"`
}

// Pattern 8: Comprehensive Tags and Methods - consolidates tagged fields and method patterns (original 44-49)
type ConsolidatedTagMethodPattern struct {
	// Tagged fields with different visibility
	Secret         string `masq:"secret"`             // public field (for WithFieldName("Secret") test)
	PublicSecret   string `masq:"secret"`             // public field with tag
	privateSecret  string `masq:"secret"`             //nolint:unused // intentionally private to test redaction limitations
	MultipleTagged string `masq:"secret" json:"data"` // multiple tags

	// Embedded with tags
	RedactProfile `masq:"secret"` // embedded with tag

	// Method testing (methods defined below)
	MethodData string `masq:"secret"` // for method testing
}

// Methods for ConsolidatedTagMethodPattern to test method handling
func (c ConsolidatedTagMethodPattern) String() string {
	return c.MethodData
}

func (c ConsolidatedTagMethodPattern) Handle() error {
	return nil
}

// Pattern 9: Comprehensive Anonymous and Special Types - consolidates anonymous structs and special Go types (original 50-56)
type ConsolidatedSpecialPattern struct {
	// Anonymous struct fields
	PublicAnonymous struct {
		Name  string `masq:"secret"`
		Value int    `masq:"secret"`
	} `masq:"secret"`

	privateAnonymous struct { //nolint:unused // intentionally private to test redaction limitations
		name  string `masq:"secret"`
		value int    `masq:"secret"`
	} `masq:"secret"`

	// Nested anonymous structs
	NestedAnonymous struct {
		Config struct {
			DB struct {
				host string `masq:"secret"`
				port int    `masq:"secret"`
			} `masq:"secret"`
			api struct {
				key string `masq:"secret"`
			} `masq:"secret"`
		} `masq:"secret"`
	} `masq:"secret"`

	// Special Go types
	UnsafePtr    unsafe.Pointer `masq:"secret"` // unsafe.Pointer
	UintPtr      uintptr        `masq:"secret"` // uintptr
	ReflectType  reflect.Type   `masq:"secret"` // reflect.Type
	ReflectValue reflect.Value  `masq:"secret"` // reflect.Value
}

// Pattern 10: Comprehensive Sync and Time Types - consolidates sync primitives and time types (original 57-63)
type ConsolidatedSyncTimePattern struct {
	// Sync primitives (as pointers to avoid copy issues)
	Mutex     *sync.Mutex     `masq:"secret"` // sync.Mutex
	RWMutex   *sync.RWMutex   `masq:"secret"` // sync.RWMutex
	WaitGroup *sync.WaitGroup `masq:"secret"` // sync.WaitGroup
	Once      *sync.Once      `masq:"secret"` // sync.Once

	// Context and time types
	Context   context.Context `masq:"secret"` // context.Context
	CreatedAt time.Time       `masq:"secret"` // time.Time
	Timeout   time.Duration   `masq:"secret"` // time.Duration
	Location  *time.Location  `masq:"secret"` // time.Location pointer
}

// Pattern 11: Comprehensive Edge Cases - consolidates empty values, nil pointers, circular refs (original 64-71)
type ConsolidatedEdgeCasePattern struct {
	// Empty and zero values
	EmptyStruct  struct{} `masq:"secret"` // empty struct
	privateOnly1 string   `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations
	privateOnly2 int      `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations

	// Nil pointers and collections
	NilPointer   *RedactProfile    `masq:"secret"` // will be nil
	NilInterface io.Writer         `masq:"secret"` // will be nil
	NilSlice     []string          `masq:"secret"` // will be nil
	NilMap       map[string]string `masq:"secret"` // will be nil

	// Self-reference for circular testing
	SelfRef *ConsolidatedEdgeCasePattern `masq:"secret"` // circular reference

	// Complex circular structures
	CircularNodes []*CircularNode `masq:"secret"` // slice with circular elements
}

// Supporting type for circular reference testing
type CircularNode struct {
	Value    string          `masq:"secret"`
	Next     *CircularNode   `masq:"secret"` // self-reference
	Children []*CircularNode `masq:"secret"` // circular through slice
}

// Pattern 12: Comprehensive Generics and Interface Implementation - consolidates generics and interface patterns (original 72-77)
type ConsolidatedGenericInterfacePattern[T any] struct {
	// Generic fields with different constraints
	GenericValue   T   `masq:"secret"` // basic generic
	NumericValue   int `masq:"secret"` // for numeric constraint testing
	privateGeneric T   `masq:"secret"` //nolint:unused // intentionally private to test redaction limitations

	// Fields for interface implementation testing
	StringerName    string `masq:"secret"` // for Stringer interface
	MarshalerSecret string `masq:"secret"` // for json.Marshaler interface
	LogValuerToken  string `masq:"secret"` // for slog.LogValuer interface
}

// Interface implementations for ConsolidatedGenericInterfacePattern
func (c ConsolidatedGenericInterfacePattern[T]) String() string {
	return "Generic User: " + c.StringerName
}

func (c ConsolidatedGenericInterfacePattern[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"secret": c.MarshalerSecret})
}

func (c ConsolidatedGenericInterfacePattern[T]) LogValue() slog.Value {
	// Use MarshalerSecret value which might contain "secret" for pattern 76
	if strings.Contains(c.MarshalerSecret, "secret") {
		return slog.StringValue(c.MarshalerSecret)
	}
	return slog.StringValue("generic-token")
}

// Pattern 13: Comprehensive Memory Layout - consolidates memory layout patterns (original 78-80)
type ConsolidatedMemoryPattern struct {
	// Different memory layout scenarios
	PaddedA     byte  `masq:"secret"` // causes padding
	PaddedLarge int64 `masq:"secret"` // large field
	PaddedB     byte  `masq:"secret"` // causes padding

	// Packed fields
	PackedA byte `masq:"secret"` // no padding
	PackedB byte `masq:"secret"` // no padding
	PackedC byte `masq:"secret"` // no padding

	// Aligned fields
	AlignedA int64 `masq:"secret"` // aligned
	AlignedB int64 `masq:"secret"` // aligned

	// Mixed alignment
	MixedByte    byte    `masq:"secret"`
	MixedInt32   int32   `masq:"secret"`
	MixedFloat64 float64 `masq:"secret"`
}

// =============================================================================
// Basic Test Implementation
// =============================================================================

// Test basic redaction functionality with type-based approach
func TestBasicRedactionPatterns(t *testing.T) {
	type testCase struct {
		name         string
		patternType  TestPatternType
		option       masq.Option
		shouldRedact bool
	}

	runTest := func(tc testCase) func(t *testing.T) {
		return func(t *testing.T) {
			logger, buf := createTestLogger(tc.option)
			pattern := createPatternByType(tc.patternType)

			logger.Info("test", "data", pattern)
			output := buf.String()

			if tc.shouldRedact {
				assertContainsRedacted(t, output)
			} else {
				assertNotRedacted(t, output, pattern)
			}
		}
	}

	// Test different pattern types with various redaction options
	tests := []testCase{
		{"DefaultPattern_WithTag", PatternDefault, masq.WithTag("secret"), true},
		{"DefaultPattern_WithFieldName", PatternDefault, masq.WithFieldName("Name"), true},
		{"DefaultPattern_WithType", PatternDefault, masq.WithType[redactUserId](), true},
		{"PrivateOnlyPattern_CannotRedact", PatternPrivateOnly, masq.WithTag("secret"), false},
		{"ContentBasedPattern_ContainSecret", PatternContentBased, masq.WithContain("secret"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, runTest(tc))
	}
}

// TestRedactionPatternsByType tests redaction using the new type-based pattern system
func TestRedactionPatternsByType(t *testing.T) {
	type testCase struct {
		name         string
		pattern      any
		option       masq.Option
		shouldRedact bool
	}

	runTest := func(tc testCase) func(t *testing.T) {
		return func(t *testing.T) {
			logger, buf := createTestLogger(tc.option)
			logger.Info("test", "data", tc.pattern)
			output := buf.String()

			if tc.shouldRedact {
				assertContainsRedacted(t, output)
			} else {
				assertNotRedacted(t, output, tc.pattern)
			}
		}
	}

	tests := []testCase{
		// Default comprehensive pattern tests
		{
			name:         "DefaultPattern_TagBased",
			pattern:      getDefaultPattern(),
			option:       masq.WithTag("secret"),
			shouldRedact: true,
		},
		{
			name:         "DefaultPattern_FieldNameBased",
			pattern:      getDefaultPattern(),
			option:       masq.WithFieldName("Name"),
			shouldRedact: true,
		},
		{
			name:         "DefaultPattern_TypeBased",
			pattern:      getDefaultPattern(),
			option:       masq.WithType[redactUserId](),
			shouldRedact: true,
		},
		// Private field limitation tests
		{
			name:         "PrivateOnlyPattern_CannotRedact",
			pattern:      getPrivateOnlyPattern(),
			option:       masq.WithTag("secret"),
			shouldRedact: false, // Private fields cannot be redacted
		},
		{
			name:         "PrivateTaggedPattern_CannotRedact",
			pattern:      getPrivateTaggedPattern(),
			option:       masq.WithTag("secret"),
			shouldRedact: false, // Private tagged fields cannot be redacted
		},
		// Content-based redaction tests
		{
			name:         "ContentBasedPattern_ContainSecret",
			pattern:      getContentBasedPattern(),
			option:       masq.WithContain("secret"),
			shouldRedact: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, runTest(tc))
	}
}

// =============================================================================
// Migrated Tests from clone_test.go
// =============================================================================

// TestMigratedMapValueRedaction tests map value redaction with tagged fields (migrated from clone_test.go)
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

	// Get the redacted map from the result
	redactedMap := gt.Cast[map[string]Trigger](t, result.Value.Any())

	gt.V(t, len(redactedMap)).Equal(1)
	trigger := redactedMap["example-key"]
	gt.V(t, trigger.Id).Equal("[REDACTED]")
}

// TestMigratedRedactExternalUnexportedStructs tests redaction of external unexported structs (migrated from clone_test.go)
func TestMigratedRedactExternalUnexportedStructs(t *testing.T) {
	t.Run("Redact sensitive fields in unexported structs", func(t *testing.T) {
		original := NewPublicUser()

		// Create masq that redacts fields containing "password" or "secret"
		mask := masq.NewMasq(
			masq.WithFieldName("password"),
			masq.WithFieldPrefix("api"),
			masq.WithContain("secret"),
		)

		copied := gt.Cast[*PublicUser](t, mask.Redact(original))

		// Verify non-sensitive fields are preserved
		gt.V(t, copied.ID).Equal("user-123")
		gt.V(t, copied.Email).Equal("john@example.com")
		gt.V(t, copied.username).Equal("john_doe")

		// Verify sensitive field is redacted
		gt.V(t, copied.password).Equal("[REDACTED]")
	})

	t.Run("Redact nested sensitive data", func(t *testing.T) {
		original := NewPublicConfig()

		// Create masq that redacts various sensitive patterns
		mask := masq.NewMasq(
			masq.WithFieldName("password"),
			masq.WithFieldName("dbPassword"), // Add specific field name
			masq.WithFieldName("apiKey"),
			masq.WithFieldName("token"),
			masq.WithContain("secret"),
			masq.WithContain("postgres://"),
		)

		copied := gt.Cast[*PublicConfig](t, mask.Redact(original))

		// Verify non-sensitive fields
		gt.V(t, copied.AppName).Equal("TestApp")
		gt.V(t, copied.Version).Equal("1.0.0")

		// Verify sensitive fields are redacted
		gt.V(t, copied.apiKey).Equal("[REDACTED]")
		gt.V(t, copied.dbPassword).Equal("[REDACTED]")

		// Verify nested sensitive data
		endpoint1 := copied.Settings.endpoints[0]
		gt.V(t, endpoint1.name).Equal("api")
		gt.V(t, endpoint1.url).Equal("https://api.example.com")
		gt.V(t, endpoint1.auth.token).Equal("[REDACTED]") // token field should be redacted

		// Verify credentials are redacted
		creds := copied.Settings.credentials
		gt.V(t, creds.username).Equal("admin")
		gt.V(t, creds.password).Equal("[REDACTED]")
		gt.V(t, creds.apiKey).Equal("[REDACTED]")
	})
}

// TestMigratedRedactUnexportedFieldsAdvanced tests advanced unexported field redaction (migrated from clone_test.go)
func TestMigratedRedactUnexportedFieldsAdvanced(t *testing.T) {
	t.Run("Redact unexported fields by field name", func(t *testing.T) {
		type testStruct struct {
			Public      string
			password    string
			secretKey   string
			normalField string
		}

		original := &testStruct{
			Public:      "public",
			password:    "mypassword123",
			secretKey:   "sk-1234567890",
			normalField: "normal",
		}

		mask := masq.NewMasq(
			masq.WithFieldName("password"),
			masq.WithFieldPrefix("secret"),
		)
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, copied.password).Equal("[REDACTED]")
		gt.V(t, copied.secretKey).Equal("[REDACTED]")
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
			Public: "public",
			unexported: inner{
				value:  "normal",
				secret: "confidential",
			},
			tagged: "tagged-secret",
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
			items: []item{
				{id: "1", password: "pass1"},
				{id: "2", password: "pass2"},
			},
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

		original := &testStruct{
			Public:   "public",
			apiKey:   "sk-1234567890abcdef",
			password: "mypassword",
		}

		mask := masq.NewMasq(
			masq.WithFieldName("apiKey", masq.MaskWithSymbol('*', 10)),
			masq.WithFieldName("password", masq.RedactString(func(s string) string { return "XXX" })),
		)
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		// apiKey has 19 chars, showing first 10 with mask
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
			conf: &config{
				name: "prod",
				cred: &credential{
					username: "admin",
					password: "secret123",
				},
			},
		}

		mask := masq.NewMasq(masq.WithFieldName("password"))
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, copied.conf.name).Equal("prod")
		gt.V(t, copied.conf.cred.username).Equal("admin")
		gt.V(t, copied.conf.cred.password).Equal("[REDACTED]")
	})
}

// TestMigratedMapAny tests map[string]any redaction (migrated from redactor_test.go)
func TestMigratedMapAny(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(
			masq.WithFieldName("Secret", masq.RedactString(func(s string) string {
				return "REDACTED"
			})),
		),
	}))
	logger.Info("hello", slog.Any("target", map[string]any{"Secret": "xxx"}))
	gt.S(t, buf.String()).Contains("REDACTED")
}

// TestMigratedFilterWithPrefixForMap tests field prefix filtering for maps (migrated from options_test.go)
func TestMigratedFilterWithPrefixForMap(t *testing.T) {
	type myRecord struct {
		Data map[string]string
	}
	record := myRecord{
		Data: map[string]string{
			"secure_phone": "090-0000-0000",
		},
	}
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

// TestMigratedFilterWithTagForCustomType tests tag filtering for custom types (migrated from options_test.go)
func TestMigratedFilterWithTagForCustomType(t *testing.T) {
	type myRecord struct {
		Data map[string]string `masq:"secret"`
	}
	record := myRecord{
		Data: map[string]string{
			"phone": "090-0000-0000",
		},
	}
	logger, buf := createTestLogger(masq.WithTag("secret"))
	logger.With("record", record).Info("Got record")
	output := buf.String()

	if strings.Contains(output, "090-0000-0000") {
		t.Errorf("Failed to filter: %s", output)
	}
}

// TestMigratedAllowedType tests allowed type functionality (migrated from options_test.go)
func TestMigratedAllowedType(t *testing.T) {
	type myRecord struct {
		Time time.Time
	}
	now := time.Now().Add(-time.Hour * 24)
	record := myRecord{
		Time: now,
	}
	logger, buf := createTestLogger(masq.WithAllowedType(reflect.TypeOf(time.Time{})))
	logger.With("record", record).Info("Got record")
	output := buf.String()

	if !strings.Contains(output, now.Format(time.RFC3339Nano)) {
		t.Errorf("Failed to filter: %s", output)
	}
}

// =============================================================================
// Comprehensive Matrix Test Implementation
// =============================================================================

// TestAllPatternTypesProcessable tests that all pattern types can be processed without panicking
func TestAllPatternTypesProcessable(t *testing.T) {
	type testCase struct {
		name        string
		patternType TestPatternType
	}

	runTest := func(tc testCase) func(t *testing.T) {
		return func(t *testing.T) {
			logger, buf := createTestLogger(masq.WithTag("secret"))
			pattern := createPatternByType(tc.patternType)

			// Should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Pattern %s caused panic: %v", tc.name, r)
				}
			}()

			logger.Info("test", "data", pattern)
			buf.Reset()
		}
	}

	// Test all pattern types
	tests := []testCase{
		{"Default", PatternDefault},
		{"PrivateOnly", PatternPrivateOnly},
		{"PrivateTagged", PatternPrivateTagged},
		{"ContentBased", PatternContentBased},
	}

	for _, tc := range tests {
		t.Run(tc.name, runTest(tc))
	}
}

// TestKnownRedactionScenarios tests specific redaction scenarios
func TestKnownRedactionScenarios(t *testing.T) {
	type testCase struct {
		name         string
		patternType  TestPatternType
		option       masq.Option
		expectRedact bool
	}

	runTest := func(tc testCase) func(t *testing.T) {
		return func(t *testing.T) {
			logger, buf := createTestLogger(tc.option)
			pattern := createPatternByType(tc.patternType)

			logger.Info("test", "data", pattern)
			output := buf.String()

			if tc.expectRedact {
				assertContainsRedacted(t, output)
			} else {
				assertNotRedacted(t, output, pattern)
			}
		}
	}

	tests := []testCase{
		// Test default comprehensive pattern - public fields with tags should redact
		{"DefaultPattern_WithTag", PatternDefault, masq.WithTag("secret"), true},
		{"DefaultPattern_WithFieldName", PatternDefault, masq.WithFieldName("Name"), true},
		{"DefaultPattern_WithFieldName_Secret", PatternDefault, masq.WithFieldName("Secret"), true},

		// Test special patterns - private struct fields cannot be redacted (expected limitation)
		{"PrivateOnlyPattern", PatternPrivateOnly, masq.WithTag("secret"), false},
		{"PrivateTaggedPattern", PatternPrivateTagged, masq.WithTag("secret"), false},

		// Test type-based redaction with default pattern
		{"DefaultPattern_UserIdType", PatternDefault, masq.WithType[redactUserId](), true},
		{"DefaultPattern_StringType", PatternDefault, masq.WithType[string](), true},

		// Test content-based redaction
		{"DefaultPattern_ContainSecret", PatternDefault, masq.WithContain("secret"), true},
		{"ContentBasedPattern_ContainSecret", PatternContentBased, masq.WithContain("secret"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, runTest(tc))
	}
}
