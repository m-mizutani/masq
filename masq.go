package masq

import (
	"reflect"
	"regexp"

	"golang.org/x/exp/slog"
)

const (
	DefaultConcealMessage = "[FILTERED]"
)

type masq struct {
	ConcealMessage string
	filters        Filters
}

type Option func(m *masq)

func newMasq(options ...Option) *masq {
	m := &masq{
		ConcealMessage: DefaultConcealMessage,
	}

	for _, opt := range options {
		opt(m)
	}

	return m
}

func (x *masq) conceal(v any) any {
	copied := x.clone("", reflect.ValueOf(v), "")
	return copied.Interface()
}

func New(options ...Option) func(groups []string, a slog.Attr) slog.Attr {
	m := newMasq(options...)

	return func(groups []string, attr slog.Attr) slog.Attr {
		masked := m.conceal(attr.Value.Any())
		return slog.Any(attr.Key, masked)
	}
}

func WithConcealMessage(msg string) Option {
	return func(m *masq) {
		m.ConcealMessage = msg
	}
}

func WithFilter(filter Filter) Option {
	return func(m *masq) {
		m.filters = append(m.filters, filter)
	}
}

func WithString(target string) Option {
	return func(m *masq) {
		m.filters = append(m.filters, newStringFilter(target, m.ConcealMessage))
	}
}

func WithRegex(target *regexp.Regexp) Option {
	return func(m *masq) {
		m.filters = append(m.filters, newRegexFilter(target, m.ConcealMessage))
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
