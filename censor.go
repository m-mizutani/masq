package masq

import (
	"reflect"
	"regexp"
	"strings"
)

// Censor is a function to check if the field should be redacted. It receives field name, value, and tag of struct if the value is in struct.
// If the field should be redacted, it returns true.
type Censor func(fieldName string, value any, tags map[string]Tag, masqTagKey string) bool
type Censors []Censor

func (x Censors) ShouldRedact(fieldName string, value any, tags map[string]Tag, masqTagKey string) bool {
	for _, censor := range x {
		if censor(fieldName, value, tags, masqTagKey) {
			return true
		}
	}
	return false
}

// string
func newStringCensor(target string) Censor {
	return func(fieldName string, value any, tags map[string]Tag, masqTagKey string) bool {
		v := reflect.ValueOf(value)
		if v.Kind() != reflect.String {
			return false
		}

		return strings.Contains(v.String(), target)
	}
}

// regex
func newRegexCensor(target *regexp.Regexp) Censor {
	return func(fieldName string, value any, tags map[string]Tag, masqTagKey string) bool {
		v := reflect.ValueOf(value)
		if v.Kind() != reflect.String {
			return false
		}

		return target.FindString(v.String()) != ""
	}
}

// type
func newTypeCensor[T any]() Censor {
	return func(fieldName string, value any, tags map[string]Tag, masqTagKey string) bool {
		var v T
		return reflect.TypeOf(v) == reflect.TypeOf(value)
	}
}

// tag
func newTagCensor(tagValue string) Censor {
	return func(fieldName string, value any, tags map[string]Tag, masqTagKey string) bool {
		tag, ok := tags[masqTagKey]
		if !ok {
			return false
		}
		return tag.Value == tagValue
	}
}

func newTagMatchCensor(tagKey string, matchFn func(tagValue string) bool) Censor {
	return func(fieldName string, value any, tags map[string]Tag, masqTagKey string) bool {
		tag, ok := tags[tagKey]
		if !ok {
			return false
		}
		return matchFn(tag.Value)
	}
}

func newTagKeyValueCensor(tagKey string, targetValue string) Censor {
	return newTagMatchCensor(tagKey, func(tagValue string) bool {
		return tagValue == targetValue
	})
}

func newTagKeyValueCensorWithRegex(tagKey string, target *regexp.Regexp) Censor {
	return newTagMatchCensor(tagKey, func(tagValue string) bool {
		return target.FindString(tagValue) != ""
	})
}

func newTagKeyValueContainsCensor(tagKey string, targetValue string) Censor {
	return newTagMatchCensor(tagKey, func(tagValue string) bool {
		return strings.Contains(tagValue, targetValue)
	})
}

// field name
func newFieldNameCensor(name string) Censor {
	return func(fieldName string, value any, tags map[string]Tag, masqTagKey string) bool {
		return name == fieldName
	}
}

// field name prefix
func newFieldPrefixCensor(prefix string) Censor {
	return func(fieldName string, value any, tags map[string]Tag, masqTagKey string) bool {
		return strings.HasPrefix(fieldName, prefix)
	}
}
