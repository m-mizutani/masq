package masq_test

import (
	"reflect"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

// extractTarget exposes one field per Kind so reflection-based tests can
// reach unexported and exported fields side-by-side.
type extractTarget struct {
	Exported string

	str   string
	b     bool
	i     int
	i8    int8
	i16   int16
	i32   int32
	i64   int64
	u     uint
	u8    uint8
	u16   uint16
	u32   uint32
	u64   uint64
	f32   float32
	f64   float64
	c64   complex64
	c128  complex128
	ptr   *string
	slc   []int
	mp    map[string]int
	arr   [2]int
	iface any
	subSt struct{ X int }
}

func TestExtractValueSafely(t *testing.T) {
	pv := "p"
	target := extractTarget{
		Exported: "exp",
		str:      "s", b: true,
		i: 1, i8: 1, i16: 1, i32: 1, i64: 1,
		u: 1, u8: 1, u16: 1, u32: 1, u64: 1,
		f32: 1.5, f64: 2.5,
		c64: complex(1, 2), c128: complex(3, 4),
		ptr:   &pv,
		slc:   []int{1, 2, 3},
		mp:    map[string]int{"k": 1},
		arr:   [2]int{9, 8},
		iface: "ifaceVal",
		subSt: struct{ X int }{X: 7},
	}

	v := reflect.ValueOf(&target).Elem()

	t.Run("invalid value returns false", func(t *testing.T) {
		got, ok := masq.ExtractValueSafely(reflect.Value{})
		gt.V(t, ok).Equal(false)
		gt.V(t, got).Nil()
	})

	t.Run("exported field uses normal Interface path", func(t *testing.T) {
		got, ok := masq.ExtractValueSafely(v.FieldByName("Exported"))
		gt.V(t, ok).Equal(true)
		gt.V(t, got).Equal("exp")
	})

	cases := []struct {
		field string
		want  any
	}{
		{"str", "s"},
		{"b", true},
		{"i", int(1)}, {"i8", int8(1)}, {"i16", int16(1)}, {"i32", int32(1)}, {"i64", int64(1)},
		{"u", uint(1)}, {"u8", uint8(1)}, {"u16", uint16(1)}, {"u32", uint32(1)}, {"u64", uint64(1)},
		{"f32", float32(1.5)}, {"f64", float64(2.5)},
		{"c64", complex64(complex(1, 2))}, {"c128", complex128(complex(3, 4))},
		{"slc", []int{1, 2, 3}},
		{"mp", map[string]int{"k": 1}},
		{"arr", [2]int{9, 8}},
		{"subSt", struct{ X int }{X: 7}},
	}

	for _, tc := range cases {
		t.Run("unexported "+tc.field, func(t *testing.T) {
			got, ok := masq.ExtractValueSafely(v.FieldByName(tc.field))
			gt.V(t, ok).Equal(true)
			gt.V(t, got).Equal(tc.want)
		})
	}

	t.Run("unexported pointer is non-nil", func(t *testing.T) {
		got, ok := masq.ExtractValueSafely(v.FieldByName("ptr"))
		gt.V(t, ok).Equal(true)
		// Pointer comes back as a typed *string we can dereference.
		ptr, isStr := got.(*string)
		gt.V(t, isStr).Equal(true)
		gt.V(t, *ptr).Equal("p")
	})

	t.Run("unexported interface holding string", func(t *testing.T) {
		got, ok := masq.ExtractValueSafely(v.FieldByName("iface"))
		gt.V(t, ok).Equal(true)
		gt.V(t, got).Equal("ifaceVal")
	})

	t.Run("nil unexported pointer", func(t *testing.T) {
		nilTarget := extractTarget{}
		nv := reflect.ValueOf(&nilTarget).Elem()
		_, ok := masq.ExtractValueSafely(nv.FieldByName("ptr"))
		gt.V(t, ok).Equal(true)
	})
}

func TestExtractValueSafely_NonAddressable(t *testing.T) {
	// A value retrieved from an unexported field of a non-addressable struct
	// is itself not addressable. extractValueSafely must return (nil, false).
	v := reflect.ValueOf(struct {
		inner struct {
			x string
		}
	}{}).FieldByName("inner").FieldByName("x")
	gt.V(t, v.CanInterface()).Equal(false)
	gt.V(t, v.CanAddr()).Equal(false)

	got, ok := masq.ExtractValueSafely(v)
	gt.V(t, ok).Equal(false)
	gt.V(t, got).Nil()
}
