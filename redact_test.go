package masq_test

import (
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

// Test types for comprehensive matrix testing
type CustomType string
type customType string
type CustomInt int
type customInt int
type CustomBool bool
type customBool bool

// Complex custom types
type CustomStruct struct {
	Value string `masq:"secret"`
}

type customStruct struct {
	value string `masq:"secret"`
}

// Embedded structures
type embeddedUnexported struct {
	unexportedEmbeddedField string `masq:"secret"`
	unexportedInt           int    `masq:"secret"`
}

type EmbeddedExported struct {
	ExportedEmbeddedField string `masq:"secret"`
	ExportedInt           int    `masq:"secret"`
}

type deeplyEmbedded struct {
	Deep struct {
		Field string `masq:"secret"`
	} `masq:"secret"`
}

// Map key/value types
type unexportedKeyType string
type unexportedValueType string
type ExportedKeyType string
type ExportedValueType string

// Interface implementations
type Stringer interface {
	String() string
}

type StringerImpl struct {
	Value string `masq:"secret"`
}

func (s StringerImpl) String() string {
	return s.Value
}

type unexportedStringer struct {
	value string `masq:"secret"`
}

func (s unexportedStringer) String() string {
	return s.value
}

// Function types
type ExportedFunc func(string) string
type unexportedFunc func(string) string

// Channel types
type ExportedChan chan string
type unexportedChan chan string

// testRedactCase defines a test case for TestRedact
type testRedactCase struct {
	name        string
	filter      masq.Option
	redacted    []string // Fields that should be redacted (e.g., "[REDACTED]")
	notRedacted []string // Fields that should NOT be redacted but ARE successfully cloned
	notCloned   []string // Fields that CANNOT be cloned (become nil/zero due to limitations)
}

// Comprehensive test structure containing ALL field patterns
type TestStruct struct {
	// === EXPORTED PRIMITIVE TYPES ===
	ExportedString  string  `masq:"secret"`
	ExportedInt     int     `masq:"secret"`
	ExportedInt64   int64   `masq:"secret"`
	ExportedFloat64 float64 `masq:"secret"`
	ExportedBool    bool    `masq:"secret"`
	ExportedByte    byte    `masq:"secret"`
	ExportedRune    rune    `masq:"secret"`

	// === EXPORTED CUSTOM TYPES ===
	ExportedCustomString CustomType   `masq:"secret"`
	ExportedCustomInt    CustomInt    `masq:"secret"`
	ExportedCustomBool   CustomBool   `masq:"secret"`
	ExportedCustomStruct CustomStruct `masq:"secret"`

	// === EXPORTED COMPOUND TYPES ===
	ExportedPointer   *string           `masq:"secret"`
	ExportedSlice     []string          `masq:"secret"`
	ExportedArray     [3]string         `masq:"secret"`
	ExportedMap       map[string]string `masq:"secret"`
	ExportedInterface any               `masq:"secret"`
	ExportedStringer  Stringer          `masq:"secret"`
	ExportedFunc      ExportedFunc      `masq:"secret"`
	ExportedChan      ExportedChan      `masq:"secret"`

	// === EXPORTED NESTED STRUCTURES ===
	ExportedStruct      EmbeddedExported            `masq:"secret"`
	ExportedNestedPtr   *EmbeddedExported           `masq:"secret"`
	ExportedSliceStruct []EmbeddedExported          `masq:"secret"`
	ExportedMapStruct   map[string]EmbeddedExported `masq:"secret"`

	// === UNEXPORTED PRIMITIVE TYPES ===
	unexportedString  string  `masq:"secret"`
	unexportedInt     int     `masq:"secret"`
	unexportedInt64   int64   `masq:"secret"`
	unexportedFloat64 float64 `masq:"secret"`
	unexportedBool    bool    `masq:"secret"`
	unexportedByte    byte    `masq:"secret"`
	unexportedRune    rune    `masq:"secret"`

	// === UNEXPORTED CUSTOM TYPES ===
	unexportedCustomString customType   `masq:"secret"`
	unexportedCustomInt    customInt    `masq:"secret"`
	unexportedCustomBool   customBool   `masq:"secret"`
	unexportedCustomStruct customStruct `masq:"secret"`

	// === UNEXPORTED COMPOUND TYPES ===
	unexportedPointer   *string            `masq:"secret"`
	unexportedSlice     []string           `masq:"secret"`
	unexportedArray     [3]string          `masq:"secret"`
	unexportedMap       map[string]string  `masq:"secret"`
	unexportedInterface any                `masq:"secret"`
	unexportedStringer  unexportedStringer `masq:"secret"`
	unexportedFunc      unexportedFunc     `masq:"secret"`
	unexportedChan      unexportedChan     `masq:"secret"`

	// === UNEXPORTED NESTED STRUCTURES ===
	unexportedStruct      embeddedUnexported            `masq:"secret"`
	unexportedNestedPtr   *embeddedUnexported           `masq:"secret"`
	unexportedSliceStruct []embeddedUnexported          `masq:"secret"`
	unexportedMapStruct   map[string]embeddedUnexported `masq:"secret"`

	// === EMBEDDED STRUCTS ===
	embeddedUnexported
	EmbeddedExported
	deeplyEmbedded

	// === MAPS WITH UNEXPORTED KEY/VALUE TYPES ===
	MapUnexportedKey   map[unexportedKeyType]string              `masq:"secret"`
	MapUnexportedValue map[string]unexportedValueType            `masq:"secret"`
	MapUnexportedBoth  map[unexportedKeyType]unexportedValueType `masq:"secret"`
	MapExportedKey     map[ExportedKeyType]string                `masq:"secret"`
	MapExportedValue   map[string]ExportedValueType              `masq:"secret"`
	MapExportedBoth    map[ExportedKeyType]ExportedValueType     `masq:"secret"`

	// === COMPLEX INTERFACE CASES ===
	InterfaceString     any `masq:"secret"`
	InterfaceStruct     any `masq:"secret"`
	InterfaceUnexported any `masq:"secret"`
	InterfaceNil        any `masq:"secret"`

	// === PREFIX TEST FIELDS ===
	PrefixTestString  string `masq:"secret"`
	PrefixTestInt     int    `masq:"secret"`
	PrefixOtherString string `masq:"secret"`
	PrefixOtherInt    int    `masq:"secret"`

	// === DIFFERENT TAG VALUES ===
	TaggedSecret   string `masq:"secret"`
	TaggedPassword string `masq:"password"`
	TaggedToken    string `masq:"token"`
	UntaggedField  string

	// === SPECIAL CONTENT FOR CONTAIN/REGEX FILTERS ===
	ContainsSecret   string `masq:"secret"`
	ContainsPassword string `masq:"secret"`
	ContainsNothing  string `masq:"secret"`
	RegexPhone       string `masq:"secret"`
	RegexEmail       string `masq:"secret"`
	RegexNormal      string `masq:"secret"`
}

// Helper functions

// isRedacted checks if a value has been redacted
func isRedacted(original, redacted any) bool {
	// Check for [REDACTED] string
	if str, ok := redacted.(string); ok && str == "[REDACTED]" {
		return true
	}

	// Check for zero value
	if redacted == nil {
		return original != nil
	}

	rv := reflect.ValueOf(redacted)
	if !rv.IsValid() {
		return true
	}

	switch rv.Kind() {
	case reflect.String:
		return rv.String() == "[REDACTED]" || (rv.String() == "" && original != "")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0 && reflect.ValueOf(original).Int() != 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0 && reflect.ValueOf(original).Float() != 0
	case reflect.Bool:
		return !rv.Bool() && reflect.ValueOf(original).Bool()
	case reflect.Slice, reflect.Map:
		return rv.Len() == 0 && reflect.ValueOf(original).Len() != 0
	case reflect.Struct:
		// For structs, check if all fields are zero
		origRv := reflect.ValueOf(original)
		for i := 0; i < rv.NumField(); i++ {
			if rv.Field(i).CanInterface() && origRv.Field(i).CanInterface() {
				if !reflect.DeepEqual(rv.Field(i).Interface(), origRv.Field(i).Interface()) {
					return true
				}
			}
		}
	}

	return false
}

// getFieldValue gets a field value by name using reflection
func getFieldValue(v any, fieldName string) (any, bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	field := rv.FieldByName(fieldName)
	if !field.IsValid() {
		return nil, false
	}

	if field.CanInterface() {
		return field.Interface(), true
	}

	// For unexported fields, we can still get some information
	return fmt.Sprintf("<unexported %v>", field.Type()), true
}

// createTestData creates a TestStruct with all fields populated
func createTestData() *TestStruct {
	testStr := "test_pointer_value"
	testChan := make(ExportedChan, 1)
	testChanUnexported := make(unexportedChan, 1)
	testFunc := ExportedFunc(func(s string) string { return "exported_" + s })
	testFuncUnexported := unexportedFunc(func(s string) string { return "unexported_" + s })

	return &TestStruct{
		// Exported primitive types
		ExportedString:  "exported_string_value",
		ExportedInt:     12345,
		ExportedInt64:   int64(987654321),
		ExportedFloat64: 3.14159,
		ExportedBool:    true,
		ExportedByte:    byte('X'),
		ExportedRune:    rune('語'),

		// Exported custom types
		ExportedCustomString: CustomType("custom_exported_string"),
		ExportedCustomInt:    CustomInt(999),
		ExportedCustomBool:   CustomBool(true),
		ExportedCustomStruct: CustomStruct{Value: "custom_struct_value"},

		// Exported compound types
		ExportedPointer:   &testStr,
		ExportedSlice:     []string{"slice_item1", "slice_item2"},
		ExportedArray:     [3]string{"array_item1", "array_item2", "array_item3"},
		ExportedMap:       map[string]string{"key1": "value1", "key2": "value2"},
		ExportedInterface: "interface_string_value",
		ExportedStringer:  StringerImpl{Value: "stringer_value"},
		ExportedFunc:      testFunc,
		ExportedChan:      testChan,

		// Exported nested structures
		ExportedStruct:      EmbeddedExported{ExportedEmbeddedField: "nested_field", ExportedInt: 123},
		ExportedNestedPtr:   &EmbeddedExported{ExportedEmbeddedField: "nested_ptr_field", ExportedInt: 456},
		ExportedSliceStruct: []EmbeddedExported{{ExportedEmbeddedField: "slice_struct_field", ExportedInt: 789}},
		ExportedMapStruct:   map[string]EmbeddedExported{"struct_key": {ExportedEmbeddedField: "map_struct_field", ExportedInt: 101}},

		// Unexported primitive types
		unexportedString:  "unexported_string_value",
		unexportedInt:     54321,
		unexportedInt64:   int64(123456789),
		unexportedFloat64: 2.71828,
		unexportedBool:    false,
		unexportedByte:    byte('Y'),
		unexportedRune:    rune('文'),

		// Unexported custom types
		unexportedCustomString: customType("custom_unexported_string"),
		unexportedCustomInt:    customInt(888),
		unexportedCustomBool:   customBool(false),
		unexportedCustomStruct: customStruct{value: "custom_unexported_struct"},

		// Unexported compound types
		unexportedPointer:   &testStr,
		unexportedSlice:     []string{"unexported_slice1", "unexported_slice2"},
		unexportedArray:     [3]string{"unexported_arr1", "unexported_arr2", "unexported_arr3"},
		unexportedMap:       map[string]string{"unexported_key": "unexported_value"},
		unexportedInterface: "unexported_interface_value",
		unexportedStringer:  unexportedStringer{value: "unexported_stringer"},
		unexportedFunc:      testFuncUnexported,
		unexportedChan:      testChanUnexported,

		// Unexported nested structures
		unexportedStruct:      embeddedUnexported{unexportedEmbeddedField: "unexported_nested", unexportedInt: 777},
		unexportedNestedPtr:   &embeddedUnexported{unexportedEmbeddedField: "unexported_ptr", unexportedInt: 666},
		unexportedSliceStruct: []embeddedUnexported{{unexportedEmbeddedField: "unexported_slice_struct", unexportedInt: 555}},
		unexportedMapStruct:   map[string]embeddedUnexported{"key": {unexportedEmbeddedField: "unexported_map_struct", unexportedInt: 444}},

		// Embedded structs
		embeddedUnexported: embeddedUnexported{unexportedEmbeddedField: "embedded_unexported_field", unexportedInt: 333},
		EmbeddedExported:   EmbeddedExported{ExportedEmbeddedField: "embedded_exported_field", ExportedInt: 222},
		deeplyEmbedded: deeplyEmbedded{Deep: struct {
			Field string `masq:"secret"`
		}{Field: "deeply_nested_field"}},

		// Maps with unexported key/value types
		MapUnexportedKey:   map[unexportedKeyType]string{unexportedKeyType("unexported_key"): "map_value1"},
		MapUnexportedValue: map[string]unexportedValueType{"map_key1": unexportedValueType("unexported_value")},
		MapUnexportedBoth:  map[unexportedKeyType]unexportedValueType{unexportedKeyType("key"): unexportedValueType("value")},
		MapExportedKey:     map[ExportedKeyType]string{ExportedKeyType("exported_key"): "map_value2"},
		MapExportedValue:   map[string]ExportedValueType{"map_key2": ExportedValueType("exported_value")},
		MapExportedBoth:    map[ExportedKeyType]ExportedValueType{ExportedKeyType("exp_key"): ExportedValueType("exp_value")},

		// Complex interface cases
		InterfaceString:     "interface_string",
		InterfaceStruct:     CustomStruct{Value: "interface_struct_value"},
		InterfaceUnexported: customType("interface_unexported"),
		InterfaceNil:        nil,

		// Prefix test fields
		PrefixTestString:  "prefix_test_string",
		PrefixTestInt:     1001,
		PrefixOtherString: "prefix_other_string",
		PrefixOtherInt:    2002,

		// Different tag values
		TaggedSecret:   "tagged_secret_value",
		TaggedPassword: "tagged_password_value",
		TaggedToken:    "tagged_token_value",
		UntaggedField:  "untagged_field_value",

		// Special content for contain/regex filters
		ContainsSecret:   "this contains secret word",
		ContainsPassword: "this contains password word",
		ContainsNothing:  "this contains nothing special",
		RegexPhone:       "123-456-7890",
		RegexEmail:       "user@example.com",
		RegexNormal:      "normal text here",
	}
}

// TestClone tests the clone functionality for all 76 fields
func TestClone(t *testing.T) {
	original := createTestData()

	// Use masq without any filters to test pure cloning
	m := masq.NewMasq()
	cloned := m.Redact(original).(*TestStruct)

	// Test all 76 fields individually

	t.Run("ExportedPrimitiveTypes", func(t *testing.T) {
		gt.V(t, cloned.ExportedString).Equal(original.ExportedString)
		gt.V(t, cloned.ExportedInt).Equal(original.ExportedInt)
		gt.V(t, cloned.ExportedInt64).Equal(original.ExportedInt64)
		gt.V(t, cloned.ExportedFloat64).Equal(original.ExportedFloat64)
		gt.V(t, cloned.ExportedBool).Equal(original.ExportedBool)
		gt.V(t, cloned.ExportedByte).Equal(original.ExportedByte)
		gt.V(t, cloned.ExportedRune).Equal(original.ExportedRune)
	})

	t.Run("ExportedCustomTypes", func(t *testing.T) {
		gt.V(t, cloned.ExportedCustomString).Equal(original.ExportedCustomString)
		gt.V(t, cloned.ExportedCustomInt).Equal(original.ExportedCustomInt)
		gt.V(t, cloned.ExportedCustomBool).Equal(original.ExportedCustomBool)
		gt.V(t, cloned.ExportedCustomStruct).Equal(original.ExportedCustomStruct)
	})

	t.Run("ExportedCompoundTypes", func(t *testing.T) {
		gt.V(t, cloned.ExportedPointer).NotNil()
		gt.V(t, *cloned.ExportedPointer).Equal(*original.ExportedPointer)
		gt.V(t, cloned.ExportedSlice).Equal(original.ExportedSlice)
		gt.V(t, cloned.ExportedArray).Equal(original.ExportedArray)
		gt.V(t, cloned.ExportedMap).Equal(original.ExportedMap)
		gt.V(t, cloned.ExportedInterface).Equal(original.ExportedInterface)
		gt.V(t, cloned.ExportedStringer).Equal(original.ExportedStringer)
		// Functions and channels cannot be compared
		gt.V(t, cloned.ExportedFunc).NotNil()
		gt.V(t, cloned.ExportedChan).NotNil()
	})

	t.Run("ExportedNestedStructures", func(t *testing.T) {
		gt.V(t, cloned.ExportedStruct).Equal(original.ExportedStruct)
		gt.V(t, cloned.ExportedNestedPtr).NotNil()
		gt.V(t, *cloned.ExportedNestedPtr).Equal(*original.ExportedNestedPtr)
		gt.V(t, cloned.ExportedSliceStruct).Equal(original.ExportedSliceStruct)
		gt.V(t, cloned.ExportedMapStruct).Equal(original.ExportedMapStruct)
	})

	t.Run("UnexportedPrimitiveTypes", func(t *testing.T) {
		// Unexported fields are cloned
		gt.V(t, cloned.unexportedString).Equal(original.unexportedString)
		gt.V(t, cloned.unexportedInt).Equal(original.unexportedInt)
		gt.V(t, cloned.unexportedInt64).Equal(original.unexportedInt64)
		gt.V(t, cloned.unexportedFloat64).Equal(original.unexportedFloat64)
		gt.V(t, cloned.unexportedBool).Equal(original.unexportedBool)
		gt.V(t, cloned.unexportedByte).Equal(original.unexportedByte)
		gt.V(t, cloned.unexportedRune).Equal(original.unexportedRune)
	})

	t.Run("UnexportedCustomTypes", func(t *testing.T) {
		gt.V(t, cloned.unexportedCustomString).Equal(original.unexportedCustomString)
		gt.V(t, cloned.unexportedCustomInt).Equal(original.unexportedCustomInt)
		gt.V(t, cloned.unexportedCustomBool).Equal(original.unexportedCustomBool)
		// unexportedCustomStruct has unexported fields but the struct itself is cloned
		gt.V(t, fmt.Sprintf("%v", cloned.unexportedCustomStruct)).Equal(fmt.Sprintf("%v", original.unexportedCustomStruct))
	})

	t.Run("UnexportedCompoundTypes", func(t *testing.T) {
		// Pointers are preserved
		gt.V(t, cloned.unexportedPointer).Equal(original.unexportedPointer)
		gt.V(t, cloned.unexportedSlice).Equal(original.unexportedSlice)
		gt.V(t, cloned.unexportedArray).Equal(original.unexportedArray)
		// Unexported maps become nil for security
		gt.Nil(t, cloned.unexportedMap)
		// Unexported interface becomes nil for security
		gt.Nil(t, cloned.unexportedInterface)
		gt.V(t, fmt.Sprintf("%v", cloned.unexportedStringer)).Equal(fmt.Sprintf("%v", original.unexportedStringer))
		// Functions and channels
		gt.V(t, cloned.unexportedFunc).NotNil()
		gt.V(t, cloned.unexportedChan).NotNil()
	})

	t.Run("UnexportedNestedStructures", func(t *testing.T) {
		// These structs have unexported fields
		gt.V(t, fmt.Sprintf("%v", cloned.unexportedStruct)).Equal(fmt.Sprintf("%v", original.unexportedStruct))
		gt.V(t, cloned.unexportedNestedPtr).Equal(original.unexportedNestedPtr)
		gt.V(t, fmt.Sprintf("%v", cloned.unexportedSliceStruct)).Equal(fmt.Sprintf("%v", original.unexportedSliceStruct))
		// Unexported map struct becomes empty for security
		gt.V(t, len(cloned.unexportedMapStruct)).Equal(0)
	})

	t.Run("EmbeddedStructs", func(t *testing.T) {
		gt.V(t, cloned.embeddedUnexported.unexportedEmbeddedField).Equal(original.embeddedUnexported.unexportedEmbeddedField)
		gt.V(t, cloned.embeddedUnexported.unexportedInt).Equal(original.embeddedUnexported.unexportedInt)
		gt.V(t, cloned.EmbeddedExported.ExportedEmbeddedField).Equal(original.EmbeddedExported.ExportedEmbeddedField)
		gt.V(t, cloned.EmbeddedExported.ExportedInt).Equal(original.EmbeddedExported.ExportedInt)
		gt.V(t, cloned.deeplyEmbedded.Deep.Field).Equal(original.deeplyEmbedded.Deep.Field)
	})

	t.Run("MapsWithUnexportedTypes", func(t *testing.T) {
		// Maps with unexported types are zeroed for security
		gt.V(t, len(cloned.MapUnexportedKey)).Equal(0)
		gt.V(t, len(cloned.MapUnexportedValue)).Equal(0)
		gt.V(t, len(cloned.MapUnexportedBoth)).Equal(0)

		// Maps with exported types should be cloned normally
		gt.V(t, cloned.MapExportedKey).Equal(original.MapExportedKey)
		gt.V(t, cloned.MapExportedValue).Equal(original.MapExportedValue)
		gt.V(t, cloned.MapExportedBoth).Equal(original.MapExportedBoth)
	})

	t.Run("InterfaceFields", func(t *testing.T) {
		gt.V(t, cloned.InterfaceString).Equal(original.InterfaceString)
		gt.V(t, cloned.InterfaceStruct).Equal(original.InterfaceStruct)
		// InterfaceUnexported contains unexported type
		gt.V(t, fmt.Sprintf("%v", cloned.InterfaceUnexported)).Equal(fmt.Sprintf("%v", original.InterfaceUnexported))
		gt.Nil(t, cloned.InterfaceNil)
	})

	t.Run("PrefixFields", func(t *testing.T) {
		gt.V(t, cloned.PrefixTestString).Equal(original.PrefixTestString)
		gt.V(t, cloned.PrefixTestInt).Equal(original.PrefixTestInt)
		gt.V(t, cloned.PrefixOtherString).Equal(original.PrefixOtherString)
		gt.V(t, cloned.PrefixOtherInt).Equal(original.PrefixOtherInt)
	})

	t.Run("TaggedFields", func(t *testing.T) {
		gt.V(t, cloned.TaggedSecret).Equal(original.TaggedSecret)
		gt.V(t, cloned.TaggedPassword).Equal(original.TaggedPassword)
		gt.V(t, cloned.TaggedToken).Equal(original.TaggedToken)
		gt.V(t, cloned.UntaggedField).Equal(original.UntaggedField)
	})

	t.Run("ContentFields", func(t *testing.T) {
		gt.V(t, cloned.ContainsSecret).Equal(original.ContainsSecret)
		gt.V(t, cloned.ContainsPassword).Equal(original.ContainsPassword)
		gt.V(t, cloned.ContainsNothing).Equal(original.ContainsNothing)
		gt.V(t, cloned.RegexPhone).Equal(original.RegexPhone)
		gt.V(t, cloned.RegexEmail).Equal(original.RegexEmail)
		gt.V(t, cloned.RegexNormal).Equal(original.RegexNormal)
	})
}

// Define all field names for comprehensive testing
var allFieldNames = []string{
	// Exported primitives
	"ExportedString", "ExportedInt", "ExportedInt64", "ExportedFloat64",
	"ExportedBool", "ExportedByte", "ExportedRune",
	// Exported custom
	"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
	// Exported compound
	"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
	"ExportedInterface", "ExportedStringer", "ExportedFunc", "ExportedChan",
	// Exported nested
	"ExportedStruct", "ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
	// Unexported primitives
	"unexportedString", "unexportedInt", "unexportedInt64", "unexportedFloat64",
	"unexportedBool", "unexportedByte", "unexportedRune",
	// Unexported custom
	"unexportedCustomString", "unexportedCustomInt", "unexportedCustomBool", "unexportedCustomStruct",
	// Unexported compound
	"unexportedPointer", "unexportedSlice", "unexportedArray", "unexportedMap",
	"unexportedInterface", "unexportedStringer", "unexportedFunc", "unexportedChan",
	// Unexported nested
	"unexportedStruct", "unexportedNestedPtr", "unexportedSliceStruct", "unexportedMapStruct",
	// Maps with type variations
	"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
	"MapExportedKey", "MapExportedValue", "MapExportedBoth",
	// Interface fields
	"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
	// Prefix fields
	"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
	// Tagged fields
	"TaggedSecret", "TaggedPassword", "TaggedToken", "UntaggedField",
	// Content fields
	"ContainsSecret", "ContainsPassword", "ContainsNothing",
	"RegexPhone", "RegexEmail", "RegexNormal",
}

// Define groups of unexported fields (which can't be redacted by most filters)
var unexportedFields = []string{
	"unexportedString", "unexportedInt", "unexportedInt64", "unexportedFloat64",
	"unexportedBool", "unexportedByte", "unexportedRune",
	"unexportedCustomString", "unexportedCustomInt", "unexportedCustomBool", "unexportedCustomStruct",
	"unexportedPointer", "unexportedSlice", "unexportedArray", "unexportedMap",
	"unexportedInterface", "unexportedStringer", "unexportedFunc", "unexportedChan",
	"unexportedStruct", "unexportedNestedPtr", "unexportedSliceStruct", "unexportedMapStruct",
}

// TestRedact tests various filter options with full field coverage
func TestRedact(t *testing.T) {
	testCases := []testRedactCase{
		// WithTag tests
		{
			name:   "WithTag_secret",
			filter: masq.WithTag("secret"),
			redacted: []string{
				// All exported fields with masq:"secret" tag
				"ExportedString", "ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedSlice", "ExportedMap", "ExportedInterface", "ExportedStringer",
				"ExportedStruct", "ExportedSliceStruct", "ExportedMapStruct",
				// Maps with exported types with "secret" tag
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				// Interface fields with "secret" tag
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported",
				// Prefix fields with "secret" tag
				"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
				// Tagged fields
				"TaggedSecret",
				// Content fields with "secret" tag
				"ContainsSecret", "ContainsPassword", "ContainsNothing",
				"RegexPhone", "RegexEmail", "RegexNormal",
			},
			notRedacted: append([]string{
				// Special cases that can't be redacted
				"ExportedByte", "ExportedPointer", "ExportedArray", "ExportedFunc", "ExportedChan",
				"ExportedNestedPtr", "InterfaceNil",
				// Fields without "secret" tag
				"TaggedPassword", "TaggedToken", "UntaggedField",
			}, unexportedFields...), // All unexported fields can't be redacted by tag
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		{
			name:   "WithTag_password",
			filter: masq.WithTag("password"),
			redacted: []string{
				"TaggedPassword", // Only field with "password" tag
			},
			notRedacted: append([]string{
				// All exported fields except TaggedPassword
				"ExportedString", "ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedByte", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
				"ExportedInterface", "ExportedStringer", "ExportedFunc", "ExportedChan",
				"ExportedStruct", "ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
				"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
				"TaggedSecret", "TaggedToken", "UntaggedField",
				"ContainsSecret", "ContainsPassword", "ContainsNothing",
				"RegexPhone", "RegexEmail", "RegexNormal",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		{
			name:   "WithTag_token",
			filter: masq.WithTag("token"),
			redacted: []string{
				"TaggedToken", // Only field with "token" tag
			},
			notRedacted: append([]string{
				// All exported fields except TaggedToken
				"ExportedString", "ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedByte", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
				"ExportedInterface", "ExportedStringer", "ExportedFunc", "ExportedChan",
				"ExportedStruct", "ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
				"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
				"TaggedSecret", "TaggedPassword", "UntaggedField",
				"ContainsSecret", "ContainsPassword", "ContainsNothing",
				"RegexPhone", "RegexEmail", "RegexNormal",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		// WithFieldName tests
		{
			name:   "WithFieldName_ExportedString",
			filter: masq.WithFieldName("ExportedString"),
			redacted: []string{
				"ExportedString",
			},
			notRedacted: append([]string{
				// All other exported fields
				"ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedByte", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
				"ExportedInterface", "ExportedStringer", "ExportedFunc", "ExportedChan",
				"ExportedStruct", "ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
				"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
				"TaggedSecret", "TaggedPassword", "TaggedToken", "UntaggedField",
				"ContainsSecret", "ContainsPassword", "ContainsNothing",
				"RegexPhone", "RegexEmail", "RegexNormal",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		// WithFieldPrefix tests
		{
			name:   "WithFieldPrefix_Prefix",
			filter: masq.WithFieldPrefix("Prefix"),
			redacted: []string{
				"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
			},
			notRedacted: append([]string{
				// All fields not starting with "Prefix"
				"ExportedString", "ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedByte", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
				"ExportedInterface", "ExportedStringer", "ExportedFunc", "ExportedChan",
				"ExportedStruct", "ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
				"TaggedSecret", "TaggedPassword", "TaggedToken", "UntaggedField",
				"ContainsSecret", "ContainsPassword", "ContainsNothing",
				"RegexPhone", "RegexEmail", "RegexNormal",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		{
			name:   "WithFieldPrefix_Exported",
			filter: masq.WithFieldPrefix("Exported"),
			redacted: []string{
				"ExportedString", "ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedSlice", "ExportedMap", "ExportedInterface", "ExportedStringer",
				"ExportedStruct", "ExportedSliceStruct", "ExportedMapStruct",
			},
			notRedacted: append([]string{
				// Special cases that can't be redacted
				"ExportedByte", "ExportedPointer", "ExportedArray", "ExportedFunc", "ExportedChan", "ExportedNestedPtr",
				// Fields not starting with "Exported"
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
				"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
				"TaggedSecret", "TaggedPassword", "TaggedToken", "UntaggedField",
				"ContainsSecret", "ContainsPassword", "ContainsNothing",
				"RegexPhone", "RegexEmail", "RegexNormal",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		// WithType tests
		{
			name:   "WithType_string",
			filter: masq.WithType[string](),
			redacted: []string{
				"ExportedString",
				"PrefixTestString", "PrefixOtherString",
				"TaggedSecret", "TaggedPassword", "TaggedToken", "UntaggedField",
				"ContainsSecret", "ContainsPassword", "ContainsNothing",
				"RegexPhone", "RegexEmail", "RegexNormal",
				// Structs containing strings
				"ExportedCustomStruct", "ExportedInterface", "ExportedStringer",
				"ExportedStruct", "InterfaceString", "InterfaceStruct",
			},
			notRedacted: append([]string{
				"ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedByte", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool",
				"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
				"ExportedFunc", "ExportedChan",
				"ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceUnexported", "InterfaceNil",
				"PrefixTestInt", "PrefixOtherInt",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		{
			name:   "WithType_int",
			filter: masq.WithType[int](),
			redacted: []string{
				"ExportedInt", "PrefixTestInt", "PrefixOtherInt",
				"ExportedStruct", // Contains int fields
			},
			notRedacted: append([]string{
				"ExportedString", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedByte", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
				"ExportedInterface", "ExportedStringer", "ExportedFunc", "ExportedChan",
				"ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
				"PrefixTestString", "PrefixOtherString",
				"TaggedSecret", "TaggedPassword", "TaggedToken", "UntaggedField",
				"ContainsSecret", "ContainsPassword", "ContainsNothing",
				"RegexPhone", "RegexEmail", "RegexNormal",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		// WithContain tests
		{
			name:   "WithContain_secret",
			filter: masq.WithContain("secret"),
			redacted: []string{
				"ContainsSecret", "TaggedSecret",
			},
			notRedacted: append([]string{
				"ExportedString", "ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedByte", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
				"ExportedInterface", "ExportedStringer", "ExportedFunc", "ExportedChan",
				"ExportedStruct", "ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
				"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
				"TaggedPassword", "TaggedToken", "UntaggedField",
				"ContainsPassword", "ContainsNothing",
				"RegexPhone", "RegexEmail", "RegexNormal",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		{
			name:   "WithContain_password",
			filter: masq.WithContain("password"),
			redacted: []string{
				"ContainsPassword", "TaggedPassword",
			},
			notRedacted: append([]string{
				"ExportedString", "ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedByte", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
				"ExportedInterface", "ExportedStringer", "ExportedFunc", "ExportedChan",
				"ExportedStruct", "ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
				"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
				"TaggedSecret", "TaggedToken", "UntaggedField",
				"ContainsSecret", "ContainsNothing",
				"RegexPhone", "RegexEmail", "RegexNormal",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		// WithRegex tests
		{
			name:   "WithRegex_phone",
			filter: masq.WithRegex(regexp.MustCompile(`^\d{3}-\d{3}-\d{4}$`)),
			redacted: []string{
				"RegexPhone",
			},
			notRedacted: append([]string{
				"ExportedString", "ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedByte", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
				"ExportedInterface", "ExportedStringer", "ExportedFunc", "ExportedChan",
				"ExportedStruct", "ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
				"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
				"TaggedSecret", "TaggedPassword", "TaggedToken", "UntaggedField",
				"ContainsSecret", "ContainsPassword", "ContainsNothing",
				"RegexEmail", "RegexNormal",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
		{
			name:   "WithRegex_email",
			filter: masq.WithRegex(regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`)),
			redacted: []string{
				"RegexEmail",
			},
			notRedacted: append([]string{
				"ExportedString", "ExportedInt", "ExportedInt64", "ExportedFloat64",
				"ExportedBool", "ExportedByte", "ExportedRune",
				"ExportedCustomString", "ExportedCustomInt", "ExportedCustomBool", "ExportedCustomStruct",
				"ExportedPointer", "ExportedSlice", "ExportedArray", "ExportedMap",
				"ExportedInterface", "ExportedStringer", "ExportedFunc", "ExportedChan",
				"ExportedStruct", "ExportedNestedPtr", "ExportedSliceStruct", "ExportedMapStruct",
				"MapExportedKey", "MapExportedValue", "MapExportedBoth",
				"InterfaceString", "InterfaceStruct", "InterfaceUnexported", "InterfaceNil",
				"PrefixTestString", "PrefixTestInt", "PrefixOtherString", "PrefixOtherInt",
				"TaggedSecret", "TaggedPassword", "TaggedToken", "UntaggedField",
				"ContainsSecret", "ContainsPassword", "ContainsNothing",
				"RegexPhone", "RegexNormal",
			}, unexportedFields...),
			notCloned: []string{
				// Maps with unexported types (always nil/zero for security)
				"MapUnexportedKey", "MapUnexportedValue", "MapUnexportedBoth",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := createTestData()
			m := masq.NewMasq(tc.filter)
			redacted := m.Redact(original).(*TestStruct)

			// Build expectations map from redacted/notRedacted/notCloned lists
			type expectation struct {
				redacted  bool
				notCloned bool
			}
			expectations := make(map[string]expectation)

			// Mark fields as redacted
			for _, field := range tc.redacted {
				expectations[field] = expectation{redacted: true, notCloned: false}
			}

			// Mark fields as not redacted but successfully cloned
			for _, field := range tc.notRedacted {
				expectations[field] = expectation{redacted: false, notCloned: false}
			}

			// Mark fields as not cloned (nil/zero due to limitations)
			for _, field := range tc.notCloned {
				expectations[field] = expectation{redacted: false, notCloned: true}
			}

			// Verify that we're testing all fields
			if len(expectations) != len(allFieldNames) {
				t.Errorf("[%s] Not testing all fields: expected %d fields, got %d",
					tc.name, len(allFieldNames), len(expectations))
			}

			// Check ALL fields for comprehensive verification
			for _, fieldName := range allFieldNames {
				expect, exists := expectations[fieldName]
				if !exists {
					t.Errorf("[%s] Field %s not specified in test expectations", tc.name, fieldName)
					continue
				}

				origValue, hasOrig := getFieldValue(original, fieldName)
				redactedValue, hasRedacted := getFieldValue(redacted, fieldName)

				if !hasOrig || !hasRedacted {
					continue // Skip fields that can't be accessed
				}

				// Some fields can't be redacted due to their type
				if fieldName == "ExportedFunc" || fieldName == "unexportedFunc" ||
					fieldName == "ExportedChan" || fieldName == "unexportedChan" {
					continue // Functions and channels can't be redacted
				}

				isActuallyRedacted := isRedacted(origValue, redactedValue)

				// Check if field is nil/zero (not cloned)
				rv := reflect.ValueOf(redactedValue)
				isNilOrZero := !rv.IsValid() || rv.IsZero()

				if expect.notCloned {
					// Field should be nil/zero due to cloning limitations
					if !isNilOrZero {
						t.Errorf("[%s] Field %s should not be cloned (nil/zero) but was: %v", tc.name, fieldName, redactedValue)
					}
				} else if expect.redacted {
					// Field should be redacted
					if !isActuallyRedacted {
						t.Errorf("[%s] Field %s should be redacted but wasn't", tc.name, fieldName)
					}
				} else {
					// Field should be cloned without redaction
					if isActuallyRedacted {
						t.Errorf("[%s] Field %s should not be redacted but was", tc.name, fieldName)
					}
				}
			}
		})
	}
}
