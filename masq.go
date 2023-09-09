package masq

import (
	"reflect"
	"regexp"

	"log/slog"
)

const (
	DefaultRedactMessage = "[REDACTED]"
)

type masq struct {
	redactMessage string
	filters       Filters
	censors       Censors
	allowedTypes  map[reflect.Type]struct{}
}

type Option func(m *masq)

func newMasq(options ...Option) *masq {
	m := &masq{
		redactMessage: DefaultRedactMessage,
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
		m.redactMessage = msg
	}
}

func WithFilter(filter Filter) Option {
	return func(m *masq) {
		m.filters = append(m.filters, filter)
	}
}

func WithString(target string) Option {
	return func(m *masq) {
		m.filters = append(m.filters, newStringFilter(target, m.redactMessage))
	}
}

func WithRegex(target *regexp.Regexp) Option {
	return func(m *masq) {
		m.filters = append(m.filters, newRegexFilter(target, m.redactMessage))
	}
}

func WithCensor(censor Censor) Option {
	return func(m *masq) {
		m.censors = append(m.censors, censor)
	}
}

func WithType[T any]() Option {
	return func(m *masq) {
		m.censors = append(m.censors, newTypeCensor[T]())
	}
}

func WithTag(tag string) Option {
	return func(m *masq) {
		m.censors = append(m.censors, newTagCensor(tag))
	}
}

func WithFieldName(fieldName string) Option {
	return func(m *masq) {
		m.censors = append(m.censors, newFieldNameCensor(fieldName))
	}
}

func WithFieldPrefix(fieldName string) Option {
	return func(m *masq) {
		m.censors = append(m.censors, newFieldPrefixCensor(fieldName))
	}
}

func WithAllowedType(types ...reflect.Type) Option {
	return func(m *masq) {
		for _, t := range types {
			m.allowedTypes[t] = struct{}{}
		}
	}
}
