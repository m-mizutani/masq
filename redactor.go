package masq

import (
	"fmt"
	"reflect"
	"strings"
)

// Redactor is a function to redact value. It receives source and destination value. If the redaction is done, it must return true. If the redaction is not done, it must return false. If the redaction is not done, the next redactor will be applied. If all redactors are not done, the default redactor will be applied.
type Redactor func(src, dst reflect.Value) bool

type Redactors []Redactor

func (x Redactors) Redact(src, dst reflect.Value) bool {
	for _, redactor := range x {
		if redactor(src, dst) {
			return true
		}
	}
	return false
}

// RedactString is a redactor to redact string value. It receives a function to redact string. The function receives the string value and returns the redacted string value. The returned Redact function always returns true if the source value is string. Otherwise, it returns false.
func RedactString(redact func(s string) string) Redactor {
	return func(src, dst reflect.Value) bool {
		if src.Kind() != reflect.String {
			return false
		}

		dst.Elem().SetString(redact(src.String()))
		return true
	}
}

// MaskWithSymbol is a redactor to redact string value with masked string that have the same length as the source string value. It can help the developer to know the length of the string value. The returned Redact function always returns true if the source value is string. Otherwise, it returns false.
func MaskWithSymbol(symbol rune, max int) Redactor {
	return RedactString(func(s string) string {
		if len(s) > max {
			return strings.Repeat(string(symbol), max) + fmt.Sprintf(" (remained %d chars)", len(s)-max)
		}
		return strings.Repeat(string(symbol), len(s))
	})
}
