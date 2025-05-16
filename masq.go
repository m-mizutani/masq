package masq

import (
	"context"
	"reflect"

	"log/slog"
)

const (
	// DefaultTagKey is a default key name of struct tag for masq. WithCustomTagKey option can change this value.
	DefaultTagKey = "masq"

	// DefaultRedactMessage is a default message to replace redacted value. WithRedactMessage option can change this value.
	DefaultRedactMessage = "[REDACTED]"
)

type masq struct {
	redactMessage string
	filters       []*Filter
	allowedTypes  map[reflect.Type]struct{}

	defaultRedactor Redactor
	masqTagKey      string
	tagKeys         map[string]struct{}
}

type Filter struct {
	censor    Censor
	redactors Redactors
}

type Tag struct {
	Key   string
	Value string
}

type Option func(m *masq)

func newMasq(options ...Option) *masq {
	m := &masq{
		redactMessage: DefaultRedactMessage,
		allowedTypes:  map[reflect.Type]struct{}{},
		masqTagKey:    DefaultTagKey,
		tagKeys:       map[string]struct{}{},
	}
	m.defaultRedactor = func(src, dst reflect.Value) bool {
		switch src.Kind() {
		case reflect.String:
			dst.Elem().SetString(m.redactMessage)
		}
		return true
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

	ctx := context.Background()
	copied := x.clone(ctx, k, reflect.ValueOf(v), nil)
	return copied.Interface()
}

func New(options ...Option) func(groups []string, a slog.Attr) slog.Attr {
	m := newMasq(options...)

	return func(groups []string, attr slog.Attr) slog.Attr {
		masked := m.redact(attr.Key, attr.Value.Any())
		return slog.Any(attr.Key, masked)
	}
}
