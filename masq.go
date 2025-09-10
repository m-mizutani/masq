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
	tagKey          string
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
		tagKey:        DefaultTagKey,
	}
	m.defaultRedactor = func(src, dst reflect.Value) bool {
		switch src.Kind() {
		case reflect.String:
			if dst.Elem().CanSet() {
				dst.Elem().SetString(m.redactMessage)
			} else {
				// For unexported fields, use unsafe operations
				if dst.Elem().CanAddr() {
					unsafeCopyValue(dst.Elem(), reflect.ValueOf(m.redactMessage))
				}
			}
		case reflect.Bool:
			defaultBool := false
			if dst.Elem().CanSet() {
				dst.Elem().SetBool(defaultBool)
			} else if dst.Elem().CanAddr() {
				unsafeCopyValue(dst.Elem(), reflect.ValueOf(defaultBool))
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			defaultInt := int64(0)
			if dst.Elem().CanSet() {
				dst.Elem().SetInt(defaultInt)
			} else if dst.Elem().CanAddr() {
				// For typed integers, create zero value of the same type
				zeroVal := reflect.Zero(dst.Elem().Type())
				unsafeCopyValue(dst.Elem(), zeroVal)
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			defaultUint := uint64(0)
			if dst.Elem().CanSet() {
				dst.Elem().SetUint(defaultUint)
			} else if dst.Elem().CanAddr() {
				zeroVal := reflect.Zero(dst.Elem().Type())
				unsafeCopyValue(dst.Elem(), zeroVal)
			}
		default:
			// For other types (structs, slices, etc.), try to set to zero value
			if dst.Elem().CanSet() {
				dst.Elem().Set(reflect.Zero(src.Type()))
			} else if dst.Elem().CanAddr() {
				zeroVal := reflect.Zero(dst.Elem().Type())
				unsafeCopyValue(dst.Elem(), zeroVal)
			}
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
