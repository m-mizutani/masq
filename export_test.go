package masq

import "reflect"

// Masq is exported for testing
type Masq = masq

// NewMasq creates a new masq instance for testing
func NewMasq(options ...Option) *Masq {
	return newMasq(options...)
}

// Redact is exported for testing
func (x *Masq) Redact(v any) any {
	return x.redact("", v)
}

// ExtractValueSafely is exported for testing private field access
func ExtractValueSafely(v reflect.Value) (interface{}, bool) {
	return extractValueSafely(v)
}
