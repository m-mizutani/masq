package masq

import (
	"reflect"
	"strings"
)

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
