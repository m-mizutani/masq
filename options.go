package masq

import (
	"reflect"
	"regexp"
)

// WithCensor is an option to add a censor function to masq. If the censor function returns true, the field will be redacted. The redactor functions will be applied to the field. If the redactor functions return true, the redaction will be stopped. If the all redactor functions return false, the default redactor will be applied. The default redactor redacts the field with the redact message.
func WithCensor(censor Censor, redactors ...Redactor) Option {
	return func(m *masq) {
		m.filters = append(m.filters, &Filter{
			censor:    censor,
			redactors: redactors,
		})
	}
}

// WithContain is an option to check if the field contains the target string. If the field contains the target string, the field will be redacted.
func WithContain(target string, redactors ...Redactor) Option {
	return WithCensor(newStringCensor(target), redactors...)
}

// WithRegex is an option to check if the field matches the target regex. If the field matches the target regex, the field will be redacted.
func WithRegex(target *regexp.Regexp, redactors ...Redactor) Option {
	return WithCensor(newRegexCensor(target), redactors...)
}

// WithType is an option to check if the field is matched with the target type. If the field is the target type, the field will be redacted.
func WithType[T any](redactors ...Redactor) Option {
	return WithCensor(newTypeCensor[T](), redactors...)
}

// WithTag is an option to check if the field is matched with the target struct tag in `masq:"xxx"`. If the field has the target tag, the field will be redacted.
func WithTag(tag string, redactors ...Redactor) Option {
	return WithCensor(newTagCensor(tag), redactors...)
}

// WithCustomTagKey is an option to set the custom tag key. The default tag key is `masq`. If the field has the target tag in the custom tag key AND the field is matched with the target tag specified by WithTag, the field will be redacted. If tagKey is empty, WithCustomTagKey panics.
func WithCustomTagKey(tagKey string) Option {
	if tagKey == "" {
		panic("masq: tag key must not be empty")
	}

	return func(m *masq) {
		m.tagKey = tagKey
	}
}

// WithFieldName is an option to check if the field name is matched with the target field name. If the field name is the target field name, the field will be redacted.
func WithFieldName(fieldName string, redactors ...Redactor) Option {
	return WithCensor(newFieldNameCensor(fieldName), redactors...)
}

// WithFieldPrefix is an option to check if the field name has the target prefix. If the field name has the target prefix, the field will be redacted.
func WithFieldPrefix(fieldName string, redactors ...Redactor) Option {
	return WithCensor(newFieldPrefixCensor(fieldName), redactors...)
}

// WithAllowedType is an option to allow the type to be redacted. If the field is matched with the target type, the field will not be redacted.
func WithAllowedType(types ...reflect.Type) Option {
	return func(m *masq) {
		for _, t := range types {
			m.allowedTypes[t] = struct{}{}
		}
	}
}

// WithRedactMessage is an option to set the redact message. The default redact message is `[REDACTED]`.
func WithRedactMessage(message string) Option {
	return func(m *masq) {
		m.redactMessage = message
	}
}
