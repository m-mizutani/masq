package masq

import (
	"reflect"
	"regexp"
	"strings"
)

type Filter interface {
	// ReplaceString is called when checking string type. The argument is the value to be checked, and the return value should be the value to be replaced. If nothing needs to be done, the method should return the argument as is. This method is intended for the case where you want to hide a part of a string.
	ReplaceString(s string) string

	// ShouldRedact is called for all values to be checked. The field name of the value to be checked, the value to be checked, and tag value if the structure has `zlog` tag will be passed as arguments. If the return value is false, nothing is done; if it is true, the entire field is hidden. Hidden values will be replaced with the value "[filtered]" if string type. For other type, empty value will be set.
	ShouldRedact(fieldName string, value any, tag string) bool
}

type Filters []Filter

func (x Filters) ReplaceString(s string) string {
	for _, f := range x {
		s = f.ReplaceString(s)
	}
	return s
}

func (x Filters) ShouldRedact(fieldName string, value any, tag string) bool {
	for _, f := range x {
		if f.ShouldRedact(fieldName, value, tag) {
			return true
		}
	}
	return false
}

// string
type stringFilter struct {
	target   string
	replaced string
}

func newStringFilter(target, replaced string) *stringFilter {
	return &stringFilter{
		target:   target,
		replaced: replaced,
	}
}

func (x *stringFilter) ReplaceString(s string) string {
	return strings.ReplaceAll(s, x.target, x.replaced)
}

func (x *stringFilter) ShouldRedact(_ string, _ any, _ string) bool {
	return false
}

// regex
type regexFilter struct {
	target   *regexp.Regexp
	replaced string
}

func newRegexFilter(target *regexp.Regexp, replaced string) *regexFilter {
	return &regexFilter{
		target:   target,
		replaced: replaced,
	}
}

func (x *regexFilter) ReplaceString(s string) string {
	return x.target.ReplaceAllString(s, x.replaced)
}

func (x *regexFilter) ShouldRedact(_ string, _ any, _ string) bool {
	return false
}

// type
type typeFilter[T any] struct {
	target reflect.Type
}

func newTypeFilter[T any]() *typeFilter[T] {
	var v T
	return &typeFilter[T]{
		target: reflect.TypeOf(v),
	}
}

func (x *typeFilter[T]) ReplaceString(s string) string {
	return s
}

func (x *typeFilter[T]) ShouldRedact(_ string, v any, _ string) bool {
	return x.target == reflect.TypeOf(v)
}

// tag
type tagFilter struct {
	target string
}

func newTagFilter(tag string) *tagFilter {
	return &tagFilter{
		target: tag,
	}
}

func (x *tagFilter) ReplaceString(s string) string {
	return s
}

func (x *tagFilter) ShouldRedact(_ string, _ any, tag string) bool {
	return x.target == tag
}

// field name
type fieldNameFilter struct {
	target string
}

func newFieldNameFilter(fieldName string) *fieldNameFilter {
	return &fieldNameFilter{
		target: fieldName,
	}
}

func (x *fieldNameFilter) ReplaceString(s string) string {
	return s
}

func (x *fieldNameFilter) ShouldRedact(fieldName string, _ any, _ string) bool {
	return x.target == fieldName
}

// field name
type fieldPrefixFilter struct {
	target string
}

func newFieldPrefixFilter(fieldName string) *fieldPrefixFilter {
	return &fieldPrefixFilter{
		target: fieldName,
	}
}

func (x *fieldPrefixFilter) ReplaceString(s string) string {
	return s
}

func (x *fieldPrefixFilter) ShouldRedact(fieldName string, _ any, _ string) bool {
	return strings.HasPrefix(fieldName, x.target)
}
