package masq_test

import (
	"reflect"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

func ExampleMaskWithSymbol() {
	out := &fixedTimeWriter{}

	type myRecord struct {
		ID    string
		Phone string
		Email string
	}
	record := myRecord{
		ID:    "m-mizutani",
		Phone: "090-0000-0000",
		// too long email address
		Email: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@example.com",
	}

	logger := newLogger(out, masq.New(
		masq.WithFieldName("Phone", masq.MaskWithSymbol('*', 32)),
		masq.WithFieldName("Email", masq.MaskWithSymbol('*', 12)),
	))
	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"Email":"************ (remained 36 chars)","ID":"m-mizutani","Phone":"*************"},"time":"2022-12-25T09:00:00.123456789"}
}

func TestRedactString(t *testing.T) {
	upper := masq.RedactString(func(s string) string { return "U:" + s })

	t.Run("redacts string Kind", func(t *testing.T) {
		src := "secret"
		dst := new(string)
		ok := upper(reflect.ValueOf(src), reflect.ValueOf(dst))
		gt.V(t, ok).Equal(true)
		gt.V(t, *dst).Equal("U:secret")
	})

	t.Run("redacts string held in interface", func(t *testing.T) {
		var src any = "secret"
		var dst any
		dstPtr := reflect.ValueOf(&dst).Elem()
		dstPtr.Set(reflect.ValueOf(""))
		ok := upper(reflect.ValueOf(&src).Elem(), reflect.ValueOf(&dst))
		gt.V(t, ok).Equal(true)
		gt.V(t, dst).Equal("U:secret")
	})

	t.Run("returns false for non-string Kind", func(t *testing.T) {
		src := 42
		dst := new(int)
		ok := upper(reflect.ValueOf(src), reflect.ValueOf(dst))
		gt.V(t, ok).Equal(false)
	})

	t.Run("returns false for nil interface", func(t *testing.T) {
		var src any
		var dst any
		ok := upper(reflect.ValueOf(&src).Elem(), reflect.ValueOf(&dst))
		gt.V(t, ok).Equal(false)
	})
}

func TestMaskWithSymbol(t *testing.T) {
	t.Run("repeats symbol matching length when shorter than max", func(t *testing.T) {
		mask := masq.MaskWithSymbol('*', 10)
		src := "abc"
		dst := new(string)
		ok := mask(reflect.ValueOf(src), reflect.ValueOf(dst))
		gt.V(t, ok).Equal(true)
		gt.V(t, *dst).Equal("***")
	})

	t.Run("appends remained chars notation when longer than max", func(t *testing.T) {
		mask := masq.MaskWithSymbol('#', 4)
		src := "abcdefgh"
		dst := new(string)
		ok := mask(reflect.ValueOf(src), reflect.ValueOf(dst))
		gt.V(t, ok).Equal(true)
		gt.V(t, *dst).Equal("#### (remained 4 chars)")
	})

	t.Run("returns false for non-string", func(t *testing.T) {
		mask := masq.MaskWithSymbol('*', 4)
		src := 123
		dst := new(int)
		ok := mask(reflect.ValueOf(src), reflect.ValueOf(dst))
		gt.V(t, ok).Equal(false)
	})
}

func TestCustomRedactorFallthrough(t *testing.T) {
	type secretField string
	type record struct {
		Token secretField
		Name  string
	}

	// Custom redactor that only handles strings, returns false otherwise.
	// For non-matching values the chain should fall through to the default redactor.
	called := 0
	customStringOnly := masq.Redactor(func(src, dst reflect.Value) bool {
		called++
		if src.Kind() == reflect.String {
			dst.Elem().SetString("CUSTOM")
			return true
		}
		return false
	})

	m := masq.NewMasq(masq.WithType[secretField](customStringOnly))
	r := record{Token: "abc", Name: "n"}
	got := gt.Cast[record](t, m.Redact(r))
	gt.V(t, got.Token).Equal(secretField("CUSTOM"))
	gt.V(t, got.Name).Equal("n")
	gt.V(t, called > 0).Equal(true)
}

func TestDefaultRedactorByKind(t *testing.T) {
	type all struct {
		Target string
		I      int
		I8     int8
		U      uint
		U16    uint16
		B      bool
		F      float64
		Sub    struct{ V string }
		Slc    []string
		Map    map[string]string
		Ptr    *string
	}
	v := "x"
	in := all{
		Target: "secret", I: 7, I8: 7, U: 7, U16: 7, B: true, F: 1.5,
		Sub: struct{ V string }{V: "v"},
		Slc: []string{"a"}, Map: map[string]string{"k": "v"}, Ptr: &v,
	}

	cases := []struct {
		name  string
		field string
		check func(t *testing.T, got all)
	}{
		{"string", "Target", func(t *testing.T, got all) { gt.V(t, got.Target).Equal("[REDACTED]") }},
		{"int", "I", func(t *testing.T, got all) { gt.V(t, got.I).Equal(0) }},
		{"int8", "I8", func(t *testing.T, got all) { gt.V(t, got.I8).Equal(int8(0)) }},
		{"uint", "U", func(t *testing.T, got all) { gt.V(t, got.U).Equal(uint(0)) }},
		{"uint16", "U16", func(t *testing.T, got all) { gt.V(t, got.U16).Equal(uint16(0)) }},
		{"bool", "B", func(t *testing.T, got all) { gt.V(t, got.B).Equal(false) }},
		{"float64", "F", func(t *testing.T, got all) { gt.V(t, got.F).Equal(0.0) }},
		{"struct", "Sub", func(t *testing.T, got all) { gt.V(t, got.Sub.V).Equal("") }},
		{"slice", "Slc", func(t *testing.T, got all) { gt.V(t, got.Slc).Nil() }},
		{"map", "Map", func(t *testing.T, got all) { gt.V(t, got.Map).Nil() }},
		{"pointer", "Ptr", func(t *testing.T, got all) { gt.V(t, got.Ptr).Nil() }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := masq.NewMasq(masq.WithFieldName(tc.field))
			tc.check(t, gt.Cast[all](t, m.Redact(in)))
		})
	}
}
