package masq

import (
	"reflect"
	"regexp"
	"strings"
)

// Censor is a function to check if the field should be redacted. It receives field name, value, and tag of struct if the value is in struct.
// If the field should be redacted, it returns true.
type Censor func(fieldName string, value any, tag string) bool
type Censors []Censor

func (x Censors) ShouldRedact(fieldName string, value any, tag string) bool {
	for _, censor := range x {
		if censor(fieldName, value, tag) {
			return true
		}
	}
	return false
}

// string
func newStringCensor(target string) Censor {
	return func(fieldName string, value any, tag string) bool {
		if value == nil {
			return false
		}
		v := reflect.ValueOf(value)
		if v.Kind() != reflect.String {
			return false
		}

		return strings.Contains(v.String(), target)
	}
}

// regex
func newRegexCensor(target *regexp.Regexp) Censor {
	return func(fieldName string, value any, tag string) bool {
		if value == nil {
			return false
		}
		v := reflect.ValueOf(value)
		if v.Kind() != reflect.String {
			return false
		}

		return target.FindString(v.String()) != ""
	}
}

// type
func newTypeCensor[T any]() Censor {
	return func(fieldName string, value any, tag string) bool {
		var v T
		return reflect.TypeOf(v) == reflect.TypeOf(value)
	}
}

// tag
func newTagCensor(tagValue string) Censor {
	return func(fieldName string, value any, tag string) bool {
		return tag == tagValue
	}
}

// field name
func newFieldNameCensor(name string) Censor {
	return func(fieldName string, value any, tag string) bool {
		return name == fieldName
	}
}

// field name prefix
func newFieldPrefixCensor(prefix string) Censor {
	return func(fieldName string, value any, tag string) bool {
		return strings.HasPrefix(fieldName, prefix)
	}
}

// applyCensorWithValue applies a censor function to a reflect.Value, handling both exported and unexported fields
// It tries to extract the value safely and then applies the censor
func applyCensorWithValue(censor Censor, fieldName string, value reflect.Value, tag string) bool {
	// First, try the normal path if the value can be interfaced
	if value.CanInterface() {
		return censor(fieldName, value.Interface(), tag)
	}

	// For unexported fields, try to extract the value safely
	if extractedValue, ok := extractValueSafely(value); ok {
		return censor(fieldName, extractedValue, tag)
	}

	// If we can't extract the value, fall back to nil (existing behavior for field name/tag based censors)
	return censor(fieldName, nil, tag)
}
