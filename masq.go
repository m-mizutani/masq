package masq

import (
	"reflect"

	"log/slog"
)

const (
	DefaultRedactMessage = "[REDACTED]"
)

type masq struct {
	redactMessage string
	censors       Censors
	allowedTypes  map[reflect.Type]struct{}
	redactor      func(src reflect.Value) reflect.Value
}

type Option func(m *masq)

func newMasq(options ...Option) *masq {
	m := &masq{
		redactMessage: DefaultRedactMessage,
		allowedTypes:  map[reflect.Type]struct{}{},
	}

	m.redactor = func(src reflect.Value) reflect.Value {
		dst := reflect.New(src.Type())
		switch src.Kind() {
		case reflect.String:
			dst.Elem().SetString(m.redactMessage)
		}

		if !dst.CanInterface() {
			return dst
		}
		return dst.Elem()
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
