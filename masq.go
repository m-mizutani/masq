package masq

import (
	"reflect"
	"regexp"

	"golang.org/x/exp/slog"
)

const (
	DefaultRedactMessage = "[REDACTED]"
)

type masq struct {
	RedactMessage string
	filters       Filters
	allowedTypes  map[reflect.Type]struct{}
}

type Option func(m *masq)

func newMasq(options ...Option) *masq {
	m := &masq{
		RedactMessage: DefaultRedactMessage,
		allowedTypes:  map[reflect.Type]struct{}{},
	}

	for _, opt := range options {
		opt(m)
	}

	return m
}

func (x *masq) redact(k string, v any) any {
	if v == nil {
		return nil
	}
	copied := x.clone(k, reflect.ValueOf(v), "")
	return copied.Interface()
}

func New(options ...Option) func(groups []string, a slog.Attr) slog.Attr {
	m := newMasq(options...)

	return func(groups []string, attr slog.Attr) slog.Attr {
		masked := m.redact(attr.Key, attr.Value.Any())
		return slog.Any(attr.Key, masked)
	}
}

func WithRedactMessage(msg string) Option {
	return func(m *masq) {
		m.RedactMessage = msg
	}
}

func WithFilter(filter Filter) Option {
	return func(m *masq) {
		m.filters = append(m.filters, filter)
	}
}

func WithString(target string) Option {
	return func(m *masq) {
		m.filters = append(m.filters, newStringFilter(target, m.RedactMessage))
	}
}

func WithRegex(target *regexp.Regexp) Option {
	return func(m *masq) {
		m.filters = append(m.filters, newRegexFilter(target, m.RedactMessage))
	}
}

func WithType[T any]() Option {
	return func(m *masq) {
		m.filters = append(m.filters, newTypeFilter[T]())
	}
}

func WithTag(tag string) Option {
	return func(m *masq) {
		m.filters = append(m.filters, newTagFilter(tag))
	}
}

func WithFieldName(fieldName string) Option {
	return func(m *masq) {
		m.filters = append(m.filters, newFieldNameFilter(fieldName))
	}
}

func WithFieldPrefix(fieldName string) Option {
	return func(m *masq) {
		m.filters = append(m.filters, newFieldPrefixFilter(fieldName))
	}
}

func WithAllowedType(types ...reflect.Type) Option {
	return func(m *masq) {
		for _, t := range types {
			m.allowedTypes[t] = struct{}{}
		}
	}
}
