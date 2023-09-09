package masq

import (
	"reflect"
	"regexp"
)

func WithRedactMessage(msg string) Option {
	return func(m *masq) {
		m.redactMessage = msg
	}
}

func WithContain(target string) Option {
	return func(m *masq) {
		m.censors = append(m.censors, newStringCensor(target))
	}
}

func WithRegex(target *regexp.Regexp) Option {
	return func(m *masq) {
		m.censors = append(m.censors, newRegexCensor(target))
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
