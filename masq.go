package masq

import (
	"context"
	"reflect"

	"log/slog"
)

const (
	DefaultRedactMessage = "[REDACTED]"
	DefaultTagKey        = "masq"
)

type masq struct {
	redactMessage string
	tagKey        string
	filters       []*Filter
	allowedTypes  map[reflect.Type]struct{}

	defaultRedactor Redactor
}

type Filter struct {
	censor    Censor
	redactors Redactors
}

type Option func(m *masq)

func newMasq(options ...Option) *masq {
	m := &masq{
		redactMessage: DefaultRedactMessage,
		allowedTypes:  map[reflect.Type]struct{}{},
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
	copied := x.clone(ctx, k, reflect.ValueOf(v), "")
	return copied.Interface()
}

func New(options ...Option) func(groups []string, a slog.Attr) slog.Attr {
	m := newMasq(options...)

	return func(groups []string, attr slog.Attr) slog.Attr {
		masked := m.redact(attr.Key, attr.Value.Any())
		return slog.Any(attr.Key, masked)
	}
}
