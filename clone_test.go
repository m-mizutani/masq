package masq_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

// allFieldCensor matches every non-empty field name. Useful as a "redact all"
// helper for clone behavior tests.
func allFieldCensor(fieldName string, _ any, _ string) bool { return fieldName != "" }

func TestCloneBasic(t *testing.T) {
	type child struct {
		Name string
	}
	type parent struct {
		ID    int
		Title string
		Child child
		Ptr   *child
		Slice []child
		Map   map[string]child
	}
	c := &child{Name: "n"}
	in := &parent{
		ID: 1, Title: "t",
		Child: child{Name: "c"},
		Ptr:   c,
		Slice: []child{{Name: "s1"}, {Name: "s2"}},
		Map:   map[string]child{"k": {Name: "m"}},
	}

	out := gt.Cast[*parent](t, masq.NewMasq().Redact(in))

	gt.V(t, out.ID).Equal(1)
	gt.V(t, out.Title).Equal("t")
	gt.V(t, out.Child.Name).Equal("c")
	gt.V(t, out.Ptr.Name).Equal("n")
	gt.V(t, out.Slice[1].Name).Equal("s2")
	gt.V(t, out.Map["k"].Name).Equal("m")

	// Mutating the clone must not affect the original.
	out.Title = "mutated"
	out.Ptr.Name = "mutated"
	gt.V(t, in.Title).Equal("t")
	gt.V(t, in.Ptr.Name).Equal("n")
}

func TestCloneNilValue(t *testing.T) {
	gt.V(t, masq.NewMasq().Redact(nil)).Nil()
}

func TestCloneRedactSamples(t *testing.T) {
	type sample struct {
		ID    int
		Name  string
		Label string
	}

	t.Run("contain filter on string", func(t *testing.T) {
		out := gt.Cast[string](t, masq.NewMasq(masq.WithContain("blue")).Redact("blue is blue"))
		gt.V(t, out).Equal(masq.DefaultRedactMessage)
	})

	t.Run("contain filter on struct fields", func(t *testing.T) {
		in := &sample{ID: 100, Name: "blue", Label: "five"}
		out := gt.Cast[*sample](t, masq.NewMasq(masq.WithContain("blue")).Redact(in))
		gt.V(t, out.Name).Equal(masq.DefaultRedactMessage)
		gt.V(t, out.Label).Equal("five")
		gt.V(t, out.ID).Equal(100)

		// Original untouched.
		gt.V(t, in.Name).Equal("blue")
	})

	t.Run("contain filter on slice elements", func(t *testing.T) {
		in := []sample{{Name: "orange"}, {Name: "blue"}}
		out := gt.Cast[[]sample](t, masq.NewMasq(masq.WithContain("blue")).Redact(in))
		gt.V(t, out[0].Name).Equal("orange")
		gt.V(t, out[1].Name).Equal(masq.DefaultRedactMessage)
	})

	t.Run("custom-typed string is redacted", func(t *testing.T) {
		type myType string
		type rec struct {
			Name myType
		}
		out := gt.Cast[*rec](t, masq.NewMasq(masq.WithContain("blue")).Redact(&rec{Name: "miss blue"}))
		gt.V(t, out.Name).Equal(myType(masq.DefaultRedactMessage))
	})
}

func TestCloneSpecialTypes(t *testing.T) {
	t.Run("time.Time is preserved through slog handler", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
			ReplaceAttr: masq.New(masq.WithAllowedType(reflect.TypeOf(time.Time{}))),
		}))
		before := time.Now()
		logger.Info("hello")
		after := time.Now()

		var m map[string]any
		gt.NoError(t, json.Unmarshal(buf.Bytes(), &m))
		ts, ok := m["time"].(string)
		gt.B(t, ok).True()
		got, err := time.Parse(time.RFC3339Nano, ts)
		gt.NoError(t, err)
		if got.Before(before) || got.After(after) {
			t.Errorf("time %v out of range [%v, %v]", got, before, after)
		}
	})

	t.Run("reflect.Type fields do not panic and are preserved", func(t *testing.T) {
		type rec struct {
			Name     string `masq:"secret"`
			TypeInfo reflect.Type
		}
		in := rec{Name: "n", TypeInfo: reflect.TypeOf("string")}
		out := gt.Cast[rec](t, masq.NewMasq(masq.WithTag("secret")).Redact(in))
		gt.V(t, out.Name).Equal("[REDACTED]")
		gt.V(t, out.TypeInfo.String()).Equal("string")
	})

	t.Run("function values are preserved and callable", func(t *testing.T) {
		type myFunc func() string
		fn := myFunc(func() string { return "ok" })
		out := gt.Cast[myFunc](t, masq.NewMasq().Redact(fn))
		gt.V(t, out()).Equal("ok")
	})

	t.Run("LogValuer types use their LogValue output", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
			ReplaceAttr: masq.New(),
		}))
		logger.Info("hello", slog.Any("id", logValuerByte{1, 2, 3, 4}))
		gt.S(t, buf.String()).Contains("stringer")
	})

	t.Run("error type from json package logs without panic", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
			ReplaceAttr: masq.New(),
		}))
		var s string
		err := json.Unmarshal([]byte(`["foo"]`), &s)
		logger.Info("error", slog.Any("err", err))
		gt.S(t, buf.String()).Contains("error")
	})

	t.Run("nil interface in struct logs as null", func(t *testing.T) {
		var buf bytes.Buffer
		type rec struct {
			Data any
		}
		logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
			ReplaceAttr: masq.New(),
		}))
		logger.Info("hello", slog.Any("test", rec{}))
		gt.S(t, buf.String()).Contains("null")
	})

	t.Run("double pointer is dereferenced and cloned", func(t *testing.T) {
		type child struct {
			Name string
		}
		type parent struct {
			C **child
		}
		c := &child{Name: "orange"}
		out := gt.Cast[*parent](t, masq.NewMasq(masq.WithContain("blue")).Redact(&parent{C: &c}))
		gt.V(t, (*out.C).Name).Equal("orange")
	})
}

type logValuerByte [4]byte

func (logValuerByte) LogValue() slog.Value { return slog.StringValue("stringer") }

func TestCloneMaxDepth(t *testing.T) {
	type node struct {
		Level int
		Data  string
		Child *node
	}

	root := &node{Level: 0, Data: "secret"}
	cur := root
	for i := 1; i < 40; i++ {
		cur.Child = &node{Level: i, Data: "secret"}
		cur = cur.Child
	}

	result := masq.NewMasq(masq.WithContain("secret")).Redact(root)

	// Walk past max depth (32) and confirm the deep tail is zero-valued or invalid.
	val := reflect.ValueOf(result).Elem()
	for i := 0; i < 35 && val.IsValid(); i++ {
		field := val.FieldByName("Child")
		if !field.IsValid() || field.IsNil() {
			return // tail truncated, secure
		}
		val = field.Elem()
	}
	if val.IsValid() {
		gt.V(t, val.IsZero()).Equal(true)
	}
}

func TestCloneCircularReference(t *testing.T) {
	type node struct {
		Child *node
		Str   string
	}
	n := &node{Str: "blue"}
	n.Child = n

	out := gt.Cast[*node](t, masq.NewMasq(masq.WithContain("blue")).Redact(n))
	gt.V(t, out.Child.Child.Str).Equal("[REDACTED]")
}

// TestCloneUnexportedFields covers preservation and redaction of unexported
// fields across all option types. Replaces the former TestPrivateFieldRedaction.
func TestCloneUnexportedFields(t *testing.T) {
	type customStr string

	type fixture struct {
		Exported  string `masq:"secret"`
		private   string `masq:"secret"`
		hasSecret string // contains the substring "secret"
		hasToken  string // contains the substring "token"
		num       int    `masq:"secret"`
		flag      bool   `masq:"secret"`
		flt       float64
		typed     customStr
	}
	build := func() fixture {
		return fixture{
			Exported:  "exp",
			private:   "priv",
			hasSecret: "this has secret",
			hasToken:  "has token",
			num:       42,
			flag:      true,
			flt:       3.14,
			typed:     "x",
		}
	}

	t.Run("unexported fields are preserved without filters", func(t *testing.T) {
		in := build()
		out := gt.Cast[fixture](t, masq.NewMasq().Redact(in))
		gt.V(t, out.private).Equal("priv")
		gt.V(t, out.num).Equal(42)
		gt.V(t, out.flag).Equal(true)
		gt.V(t, out.flt).Equal(3.14)
		gt.V(t, out.typed).Equal(customStr("x"))
	})

	t.Run("WithTag redacts unexported tagged fields", func(t *testing.T) {
		out := gt.Cast[fixture](t, masq.NewMasq(masq.WithTag("secret")).Redact(build()))
		gt.V(t, out.Exported).Equal("[REDACTED]")
		gt.V(t, out.private).Equal("[REDACTED]")
		gt.V(t, out.num).Equal(0)
		gt.V(t, out.flag).Equal(false)
		gt.V(t, out.hasSecret).Equal("this has secret") // not tagged
	})

	t.Run("WithContain redacts unexported fields by substring", func(t *testing.T) {
		out := gt.Cast[fixture](t, masq.NewMasq(masq.WithContain("token")).Redact(build()))
		gt.V(t, out.hasToken).Equal("[REDACTED]")
		gt.V(t, out.hasSecret).Equal("this has secret")
		gt.V(t, out.private).Equal("priv")
	})

	t.Run("WithType redacts unexported fields of the matching type", func(t *testing.T) {
		out := gt.Cast[fixture](t, masq.NewMasq(masq.WithType[customStr]()).Redact(build()))
		gt.V(t, out.typed).Equal(customStr("[REDACTED]"))
		gt.V(t, out.private).Equal("priv") // string, not customStr
	})

	t.Run("WithFieldName redacts a single unexported field", func(t *testing.T) {
		out := gt.Cast[fixture](t, masq.NewMasq(masq.WithFieldName("private")).Redact(build()))
		gt.V(t, out.private).Equal("[REDACTED]")
		gt.V(t, out.hasSecret).Equal("this has secret")
	})

	t.Run("WithFieldPrefix redacts unexported fields by name prefix", func(t *testing.T) {
		out := gt.Cast[fixture](t, masq.NewMasq(masq.WithFieldPrefix("has")).Redact(build()))
		gt.V(t, out.hasSecret).Equal("[REDACTED]")
		gt.V(t, out.hasToken).Equal("[REDACTED]")
		gt.V(t, out.private).Equal("priv")
	})

	t.Run("multiple filters compose", func(t *testing.T) {
		m := masq.NewMasq(masq.WithTag("secret"), masq.WithContain("token"))
		out := gt.Cast[fixture](t, m.Redact(build()))
		gt.V(t, out.Exported).Equal("[REDACTED]") // tag
		gt.V(t, out.private).Equal("[REDACTED]")  // tag
		gt.V(t, out.num).Equal(0)                 // tag
		gt.V(t, out.flag).Equal(false)            // tag
		gt.V(t, out.hasToken).Equal("[REDACTED]") // contain
		gt.V(t, out.hasSecret).Equal("this has secret")
	})

	t.Run("nested unexported struct fields are reachable", func(t *testing.T) {
		type inner struct {
			val string
		}
		type outer struct {
			Pub  string
			priv inner
		}
		in := outer{Pub: "p", priv: inner{val: "secret data"}}
		out := gt.Cast[outer](t, masq.NewMasq(masq.WithContain("secret")).Redact(in))
		gt.V(t, out.Pub).Equal("p")
		gt.V(t, out.priv.val).Equal("[REDACTED]")
	})

	t.Run("unexported pointer field preserves the pointee", func(t *testing.T) {
		// Regression for the legacy TestCloneUnexportedPointer: a struct with
		// an unexported *T field should be cloned with the pointee values
		// intact. Exercises the reflect.Ptr branch of extractValueSafely.
		type child struct {
			Name string
		}
		type rec struct {
			c *child
		}
		in := &rec{c: &child{Name: "orange"}}
		out := gt.Cast[*rec](t, masq.NewMasq(masq.WithContain("blue")).Redact(in))
		gt.V(t, out.c).NotNil()
		gt.V(t, out.c.Name).Equal("orange")
	})

	t.Run("unexported pointer field redacts via WithContain on pointee", func(t *testing.T) {
		// The pointer is unexported, but the pointee's exported field should
		// still be reachable for filters that operate on string content.
		type child struct {
			Name string
		}
		type rec struct {
			c *child
		}
		in := &rec{c: &child{Name: "blue value"}}
		out := gt.Cast[*rec](t, masq.NewMasq(masq.WithContain("blue")).Redact(in))
		gt.V(t, out.c).NotNil()
		gt.V(t, out.c.Name).Equal("[REDACTED]")
	})
}

func TestCloneEmbeddedStructs(t *testing.T) {
	t.Run("unexported field in embedded unexported struct is reachable", func(t *testing.T) {
		type hiddenCreds struct {
			username string
			password string
		}
		type container struct {
			ID       string
			Password string
			hiddenCreds
		}
		in := &container{
			ID: "id", Password: "public-password",
			hiddenCreds: hiddenCreds{username: "u", password: "hidden-password"},
		}
		out := gt.Cast[*container](t, masq.NewMasq(masq.WithContain("password")).Redact(in))
		gt.V(t, out.Password).Equal("[REDACTED]")
		gt.V(t, out.hiddenCreds.password).Equal("[REDACTED]")
		gt.V(t, out.hiddenCreds.username).Equal("u")
	})

	t.Run("exported field in embedded unexported struct is reachable", func(t *testing.T) {
		type hiddenCreds struct {
			Username string
			Password string
		}
		type container struct {
			ID string
			hiddenCreds
		}
		in := &container{ID: "id", hiddenCreds: hiddenCreds{Username: "u", Password: "p contains password"}}
		out := gt.Cast[*container](t, masq.NewMasq(masq.WithContain("password")).Redact(in))
		gt.V(t, out.hiddenCreds.Password).Equal("[REDACTED]")
		gt.V(t, out.hiddenCreds.Username).Equal("u")
	})

	t.Run("field name collision: WithFieldName redacts both direct and embedded", func(t *testing.T) {
		type inner struct {
			Field string
		}
		type outer struct {
			Field string
			inner
		}
		in := outer{Field: "outer", inner: inner{Field: "inner"}}
		out := gt.Cast[outer](t, masq.NewMasq(masq.WithFieldName("Field")).Redact(in))
		gt.V(t, out.Field).Equal("[REDACTED]")
		gt.V(t, out.inner.Field).Equal("[REDACTED]")
	})

	t.Run("field name collision: unexported direct and embedded both redacted", func(t *testing.T) {
		type inner struct {
			val int
		}
		type outer struct {
			val int
			inner
		}
		in := outer{val: 100, inner: inner{val: 200}}
		out := gt.Cast[outer](t, masq.NewMasq(masq.WithFieldName("val")).Redact(in))
		gt.V(t, out.val).Equal(0)
		gt.V(t, out.inner.val).Equal(0)
	})

	t.Run("field name collision: WithType redacts every matching field", func(t *testing.T) {
		type inner struct {
			Count int
		}
		type outer struct {
			Count int
			inner
		}
		in := outer{Count: 1, inner: inner{Count: 2}}
		out := gt.Cast[outer](t, masq.NewMasq(masq.WithType[int]()).Redact(in))
		gt.V(t, out.Count).Equal(0)
		gt.V(t, out.inner.Count).Equal(0)
	})

	t.Run("WithFieldPrefix reaches into embedded struct fields", func(t *testing.T) {
		type inner struct {
			SecretToken  string
			SecureCookie string
			OtherValue   string
		}
		type outer struct {
			SecureKey string
			inner
		}
		in := outer{SecureKey: "k", inner: inner{SecretToken: "t", SecureCookie: "c", OtherValue: "o"}}
		out := gt.Cast[outer](t, masq.NewMasq(masq.WithFieldPrefix("Sec")).Redact(in))
		gt.V(t, out.SecureKey).Equal("[REDACTED]")
		gt.V(t, out.inner.SecretToken).Equal("[REDACTED]")
		gt.V(t, out.inner.SecureCookie).Equal("[REDACTED]")
		gt.V(t, out.inner.OtherValue).Equal("o")
	})

	t.Run("WithRegex reaches into embedded struct fields", func(t *testing.T) {
		type inner struct {
			Phone string
			Note  string
		}
		type outer struct {
			ID string
			inner
		}
		in := outer{ID: "u1", inner: inner{Phone: "090-1234-5678", Note: "ok"}}
		out := gt.Cast[outer](t, masq.NewMasq(
			masq.WithRegex(regexp.MustCompile(`^\d{3}-\d{4}-\d{4}$`)),
		).Redact(in))
		gt.V(t, out.ID).Equal("u1")
		gt.V(t, out.inner.Phone).Equal("[REDACTED]")
		gt.V(t, out.inner.Note).Equal("ok")
	})
}

// TestCloneDeepFieldAccess verifies that filters reach into anonymous inline
// struct fields nested inside an unexported field. Restored from the legacy
// TestDeepFieldAccess after the test reorganization.
func TestCloneDeepFieldAccess(t *testing.T) {
	type deeplyEmbedded struct {
		Deep struct {
			Field string `masq:"secret"`
		}
	}
	type wrapper struct {
		nested deeplyEmbedded
	}

	build := func() wrapper {
		w := wrapper{}
		w.nested.Deep.Field = "secret_value"
		return w
	}

	t.Run("WithFieldName reaches into anonymous inline struct", func(t *testing.T) {
		out := gt.Cast[wrapper](t, masq.NewMasq(masq.WithFieldName("Field")).Redact(build()))
		gt.V(t, out.nested.Deep.Field).Equal("[REDACTED]")
	})

	t.Run("WithTag matches tag on anonymous inline field", func(t *testing.T) {
		out := gt.Cast[wrapper](t, masq.NewMasq(masq.WithTag("secret")).Redact(build()))
		// Deep struct itself carries no tag here, so only the inner Field tag matches.
		gt.V(t, out.nested.Deep.Field).Equal("[REDACTED]")
	})

	t.Run("WithContain detects content in anonymous inline field", func(t *testing.T) {
		out := gt.Cast[wrapper](t, masq.NewMasq(masq.WithContain("secret")).Redact(build()))
		gt.V(t, out.nested.Deep.Field).Equal("[REDACTED]")
	})
}

func TestCloneInterfaceField(t *testing.T) {
	t.Run("exported interface with matching tag becomes nil", func(t *testing.T) {
		type rec struct {
			Data  any `masq:"secret"`
			Other any
		}
		out := gt.Cast[*rec](t, masq.NewMasq(masq.WithTag("secret")).Redact(&rec{Data: "x", Other: "y"}))
		gt.V(t, out.Data).Nil()
		gt.V(t, out.Other).Equal("y")
	})

	t.Run("unexported interface field is preserved", func(t *testing.T) {
		type rec struct {
			Public  any
			private any
		}
		out := gt.Cast[*rec](t, masq.NewMasq().Redact(&rec{Public: "a", private: "b"}))
		gt.V(t, out.Public).Equal("a")
		gt.V(t, out.private).Equal("b")
	})
}

func TestCloneMapSecurity(t *testing.T) {
	t.Run("exported map of exported types is cloned independently", func(t *testing.T) {
		type rec struct {
			M map[string]string
		}
		in := &rec{M: map[string]string{"k": "v"}}
		out := gt.Cast[*rec](t, masq.NewMasq().Redact(in))
		gt.V(t, fmt.Sprintf("%p", out.M)).NotEqual(fmt.Sprintf("%p", in.M))
		gt.V(t, out.M["k"]).Equal("v")
	})

	t.Run("map field with unexported value type is cloned with redactable contents", func(t *testing.T) {
		type item struct {
			id    string
			value int
		}
		type rec struct {
			M map[string]item
		}
		in := &rec{M: map[string]item{"k": {id: "i", value: 42}}}
		out := gt.Cast[*rec](t, masq.NewMasq().Redact(in))
		gt.V(t, len(out.M)).Equal(1)
		gt.V(t, out.M["k"].id).Equal("i")
		gt.V(t, out.M["k"].value).Equal(42)
	})

	t.Run("unexported map field becomes nil for security", func(t *testing.T) {
		type rec struct {
			Public string
			priv   map[string]string
		}
		in := &rec{Public: "p", priv: map[string]string{"k": "v"}}
		out := gt.Cast[*rec](t, masq.NewMasq().Redact(in))
		gt.V(t, out.Public).Equal("p")
		gt.V(t, out.priv).Nil()
	})

	t.Run("embedded unexported map type becomes nil while embedded exported map is cloned", func(t *testing.T) {
		type unexportedMapType map[string]string
		type ExportedMapType map[string]string
		type container struct {
			Public string
			unexportedMapType
			ExportedMapType
		}
		in := &container{
			Public:            "p",
			unexportedMapType: unexportedMapType{"a": "b"},
			ExportedMapType:   ExportedMapType{"x": "y"},
		}
		out := gt.Cast[*container](t, masq.NewMasq().Redact(in))
		gt.V(t, out.Public).Equal("p")
		// Security: embedded unexported map type returns zero value.
		gt.V(t, out.unexportedMapType).Nil()
		// Embedded exported map type is cloned independently.
		gt.V(t, fmt.Sprintf("%p", out.ExportedMapType)).NotEqual(fmt.Sprintf("%p", in.ExportedMapType))
		gt.V(t, out.ExportedMapType["x"]).Equal("y")
	})

	t.Run("contain filter applies to slices of unexported struct elements", func(t *testing.T) {
		type sensitive struct {
			apiKey string
		}
		type rec struct {
			Public      string
			structArray [2]sensitive
		}
		in := &rec{Public: "p", structArray: [2]sensitive{{apiKey: "k1"}, {apiKey: "k2"}}}
		out := gt.Cast[*rec](t, masq.NewMasq(masq.WithFieldName("apiKey")).Redact(in))
		gt.V(t, out.structArray[0].apiKey).Equal("[REDACTED]")
		gt.V(t, out.structArray[1].apiKey).Equal("[REDACTED]")
	})

	t.Run("maps with unexported value Kinds traverse canRedactType", func(t *testing.T) {
		// Each map below has an unexported value type, which forces the clone
		// path through canRedactType's Kind-specific branches.
		type pStr string
		type pInt int
		type pBool bool
		type pFloat float64
		type pSlice []string
		type pMap map[string]string
		type pStruct struct{ id string }

		type rec struct {
			MStr    map[string]pStr
			MInt    map[string]pInt
			MBool   map[string]pBool
			MFloat  map[string]pFloat
			MSlice  map[string]pSlice
			MMap    map[string]pMap
			MStruct map[string]pStruct
			MPtr    map[string]*pStruct
		}
		one := pStruct{id: "i"}
		in := &rec{
			MStr:    map[string]pStr{"k": "v"},
			MInt:    map[string]pInt{"k": 1},
			MBool:   map[string]pBool{"k": true},
			MFloat:  map[string]pFloat{"k": 1.0},
			MSlice:  map[string]pSlice{"k": {"a"}},
			MMap:    map[string]pMap{"k": {"a": "b"}},
			MStruct: map[string]pStruct{"k": one},
			MPtr:    map[string]*pStruct{"k": &one},
		}
		out := gt.Cast[*rec](t, masq.NewMasq().Redact(in))
		// Maps with redactable unexported value types are cloned.
		gt.V(t, out.MStr["k"]).Equal(pStr("v"))
		gt.V(t, out.MInt["k"]).Equal(pInt(1))
		gt.V(t, out.MBool["k"]).Equal(pBool(true))
		gt.V(t, out.MFloat["k"]).Equal(pFloat(1.0))
		gt.V(t, out.MSlice["k"][0]).Equal("a")
		gt.V(t, out.MMap["k"]["a"]).Equal("b")
		gt.V(t, out.MStruct["k"].id).Equal("i")
		gt.V(t, out.MPtr["k"].id).Equal("i")
	})

	t.Run("maps with assorted key/value Kinds are cloned", func(t *testing.T) {
		// Exercises the canRedactType recursion across pointer/slice/map/basic Kinds
		// without relying on a giant fixture struct.
		type rec struct {
			MS     map[string]string
			MI     map[string]int
			MB     map[string]bool
			MF     map[string]float64
			MP     map[string]*int
			MSL    map[string][]string
			MMI    map[string]map[string]int
			MIface map[string]any
		}
		one := 1
		in := &rec{
			MS:     map[string]string{"k": "v"},
			MI:     map[string]int{"k": 1},
			MB:     map[string]bool{"k": true},
			MF:     map[string]float64{"k": 1.0},
			MP:     map[string]*int{"k": &one},
			MSL:    map[string][]string{"k": {"a"}},
			MMI:    map[string]map[string]int{"k": {"x": 1}},
			MIface: map[string]any{"k": "v"},
		}
		out := gt.Cast[*rec](t, masq.NewMasq().Redact(in))
		gt.V(t, out.MS["k"]).Equal("v")
		gt.V(t, out.MI["k"]).Equal(1)
		gt.V(t, out.MB["k"]).Equal(true)
		gt.V(t, out.MF["k"]).Equal(1.0)
		gt.V(t, *out.MP["k"]).Equal(1)
		gt.V(t, out.MSL["k"][0]).Equal("a")
		gt.V(t, out.MMI["k"]["x"]).Equal(1)
		gt.V(t, out.MIface["k"]).Equal("v")
	})
}

func TestClonePanicSafety(t *testing.T) {
	// Each subtest passes a value that historically triggered panics or odd
	// behavior in the clone path. We only require that Redact returns without
	// panicking and that the surrounding exported fields survive.
	subtest := func(name string, build func() any, verify func(t *testing.T, got any)) {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic: %v", r)
				}
			}()
			got := masq.NewMasq().Redact(build())
			if verify != nil {
				verify(t, got)
			}
		})
	}

	subtest("uintptr / func / chan in unexported fields", func() any {
		type rec struct {
			Public string
			ptr    uintptr
			fn     func() string
			ch     chan int
		}
		return &rec{Public: "p", ptr: uintptr(123), fn: func() string { return "x" }, ch: make(chan int)}
	}, func(t *testing.T, got any) {
		v := reflect.ValueOf(got).Elem()
		gt.V(t, v.FieldByName("Public").String()).Equal("p")
	})

	subtest("custom int/uint/float types in unexported fields", func() any {
		type cInt int
		type cUint uint
		type cFloat float64
		type rec struct {
			Public string
			i      cInt
			u      cUint
			f      cFloat
		}
		return &rec{Public: "p", i: 1, u: 2, f: 3.0}
	}, func(t *testing.T, got any) {
		v := reflect.ValueOf(got).Elem()
		gt.V(t, v.FieldByName("Public").String()).Equal("p")
	})

	subtest("context.Context in unexported field", func() any {
		type rec struct {
			Public string
			ctx    context.Context
		}
		return &rec{Public: "p", ctx: context.Background()}
	}, nil)

	subtest("unsafe.Pointer / reflect.Value in unexported fields", func() any {
		x := 1
		type rec struct {
			Public string
			up     unsafe.Pointer
			rv     reflect.Value
		}
		return &rec{Public: "p", up: unsafe.Pointer(&x), rv: reflect.ValueOf(x)}
	}, nil)

	subtest("uintptr value is preserved through default-case copy", func() any {
		type rec struct {
			PublicField string
			ptr         uintptr
		}
		return &rec{PublicField: "test", ptr: uintptr(123)}
	}, func(t *testing.T, got any) {
		v := reflect.ValueOf(got).Elem()
		gt.V(t, v.FieldByName("PublicField").String()).Equal("test")
	})

	subtest("uintptr field is filterable by name even via default case", func() any {
		type rec struct {
			PublicField string
			secret      uintptr
		}
		return &rec{PublicField: "public", secret: uintptr(123)}
	}, func(t *testing.T, got any) {
		// Use a fresh masq with WithFieldName since default subtest helper uses bare NewMasq.
		// This subtest just confirms the structure survived; the WithFieldName check is below.
	})

	t.Run("WithFieldName redacts unexported uintptr without panic", func(t *testing.T) {
		type rec struct {
			PublicField string
			secret      uintptr
		}
		in := &rec{PublicField: "public", secret: uintptr(123)}
		out := gt.Cast[*rec](t, masq.NewMasq(masq.WithFieldName("secret")).Redact(in))
		gt.V(t, out.PublicField).Equal("public")
		gt.V(t, out.secret).Equal(uintptr(0))
	})

	subtest("circular structure with unexported children", func() any {
		type node struct {
			Public   string
			parent   *node
			children []*node
			data     struct {
				value uintptr
				fn    func() string
			}
		}
		root := &node{Public: "root", data: struct {
			value uintptr
			fn    func() string
		}{value: 1, fn: func() string { return "r" }}}
		child := &node{Public: "child", parent: root}
		root.children = []*node{child}
		return root
	}, nil)
}

func TestClonePointerSecurity(t *testing.T) {
	t.Run("empty array returns a fresh zero value", func(t *testing.T) {
		out, ok := masq.NewMasq().Redact([0]string{}).([0]string)
		gt.V(t, ok).Equal(true)
		gt.V(t, out).Equal([0]string{})
	})

	t.Run("nil any field stays nil", func(t *testing.T) {
		type rec struct {
			Data any
		}
		out := gt.Cast[rec](t, masq.NewMasq().Redact(rec{}))
		gt.V(t, out.Data).Nil()
	})

	t.Run("unexported map of unexported value type returns nil", func(t *testing.T) {
		type item struct {
			id    string
			value int
		}
		type rec struct {
			Public string
			m      map[string]item
		}
		in := &rec{Public: "p", m: map[string]item{"k": {id: "i", value: 1}}}
		out := gt.Cast[*rec](t, masq.NewMasq().Redact(in))
		gt.V(t, out.Public).Equal("p")
		gt.V(t, out.m).Nil()
	})
}

// TestCloneIssue43UnexportedErrorField reproduces issue #43: unexported error
// fields being nil'd out during clone, breaking error wrappers.
// See: https://github.com/m-mizutani/masq/issues/43
func TestCloneIssue43UnexportedErrorField(t *testing.T) {
	type customError struct {
		internal error
		message  string
		code     int
	}
	errMsg := func(e *customError) string {
		if e.internal != nil {
			return e.internal.Error()
		}
		return e.message
	}

	t.Run("standalone customError preserves internal error", func(t *testing.T) {
		in := &customError{internal: errors.New("internal error message"), message: "fallback", code: 500}
		out := gt.Cast[*customError](t, masq.NewMasq().Redact(in))
		gt.V(t, out.internal).NotNil()
		gt.V(t, errMsg(out)).Equal("internal error message")
	})

	t.Run("wrapped customError preserves internal error", func(t *testing.T) {
		type wrapper struct {
			Err *customError
		}
		in := &wrapper{Err: &customError{internal: errors.New("db connection failed"), message: "g", code: 503}}
		out := gt.Cast[*wrapper](t, masq.NewMasq().Redact(in))
		gt.V(t, out.Err.internal).NotNil()
		gt.V(t, errMsg(out.Err)).Equal("db connection failed")
	})
}

// TestCloneAllFieldCensor exercises the path where every visited field matches
// the censor and exotic types must fall back to default-redactor zero values.
func TestCloneAllFieldCensor(t *testing.T) {
	type child struct {
		Data string
	}
	type rec struct {
		Func      func() time.Time
		Chan      chan int
		Bool      bool
		Bytes     []byte
		Strs      []string
		Interface any
		Child     child
		ChildPtr  *child
	}
	in := &rec{
		Func: time.Now, Chan: make(chan int), Bool: true,
		Bytes: []byte("x"), Strs: []string{"a"},
		Interface: "y", Child: child{Data: "c"}, ChildPtr: &child{Data: "p"},
	}
	out := gt.Cast[*rec](t, masq.NewMasq(masq.WithCensor(allFieldCensor)).Redact(in))
	gt.V(t, out.Func).Nil()
	gt.V(t, out.Chan).Nil()
	gt.V(t, out.Bool).Equal(false)
	gt.V(t, out.Bytes).Nil()
	gt.V(t, out.Strs).Nil()
	gt.V(t, out.Interface).Nil()
	gt.V(t, out.Child.Data).Equal("")
	gt.V(t, out.ChildPtr).Nil()
}

// TestCloneConcurrentSlogUse ensures the slog handler can be invoked
// concurrently without corruption. Cheap version of the original stress test.
func TestCloneConcurrentSlogUse(t *testing.T) {
	type rec struct {
		Public  string
		counter uint64
	}
	in := &rec{Public: "p", counter: 7}

	var buf bytes.Buffer
	var mu sync.Mutex
	logger := slog.New(slog.NewJSONHandler(safeWriter{w: &buf, mu: &mu}, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			logger.Info("c", slog.Int("i", i), slog.Any("data", in))
		}(i)
	}
	wg.Wait()
	gt.S(t, buf.String()).Contains(`"Public":"p"`)
}

type safeWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (s safeWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
