package masq

import (
	"reflect"
	"regexp"
)

// Masq is exported for testing
type Masq = masq

// NewMasq creates a new masq instance for testing
func NewMasq(options ...Option) *Masq {
	return newMasq(options...)
}

// Redact is exported for testing
func (x *Masq) Redact(v any) any {
	return x.redact("", v)
}

// ExtractValueSafely is exported for testing private field access
func ExtractValueSafely(v reflect.Value) (any, bool) {
	return extractValueSafely(v)
}

// Censor constructors exported for unit testing.
// These mirror the internal new*Censor helpers used by the WithXxx options.
func NewStringCensor(target string) Censor        { return newStringCensor(target) }
func NewRegexCensor(target *regexp.Regexp) Censor { return newRegexCensor(target) }
func NewTypeCensor[T any]() Censor                { return newTypeCensor[T]() }
func NewTagCensor(tag string) Censor              { return newTagCensor(tag) }
func NewFieldNameCensor(name string) Censor       { return newFieldNameCensor(name) }
func NewFieldPrefixCensor(prefix string) Censor   { return newFieldPrefixCensor(prefix) }

// ApplyCensorWithValue exposes applyCensorWithValue for unit testing the
// reflect.Value-aware dispatch path.
func ApplyCensorWithValue(c Censor, fieldName string, value reflect.Value, tag string) bool {
	return applyCensorWithValue(c, fieldName, value, tag)
}
