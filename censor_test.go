package masq_test

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

func TestStringCensor(t *testing.T) {
	c := masq.NewStringCensor("secret")

	cases := []struct {
		name  string
		value any
		want  bool
	}{
		{"contains target", "this has secret inside", true},
		{"exact match", "secret", true},
		{"does not contain", "nothing here", false},
		{"non-string", 42, false},
		{"nil value", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gt.V(t, c("", tc.value, "")).Equal(tc.want)
		})
	}
}

func TestRegexCensor(t *testing.T) {
	c := masq.NewRegexCensor(regexp.MustCompile(`\d{3}-\d{4}`))

	cases := []struct {
		name  string
		value any
		want  bool
	}{
		{"matches", "tel: 090-1234", true},
		{"no match", "abc", false},
		{"non-string", 1234, false},
		{"nil", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gt.V(t, c("", tc.value, "")).Equal(tc.want)
		})
	}
}

func TestTypeCensor(t *testing.T) {
	type myStr string

	cIntForString := masq.NewTypeCensor[string]()
	gt.V(t, cIntForString("", "x", "")).Equal(true)
	gt.V(t, cIntForString("", myStr("x"), "")).Equal(false)
	gt.V(t, cIntForString("", 1, "")).Equal(false)

	cMyStr := masq.NewTypeCensor[myStr]()
	gt.V(t, cMyStr("", myStr("x"), "")).Equal(true)
	gt.V(t, cMyStr("", "x", "")).Equal(false)
}

func TestTagCensor(t *testing.T) {
	c := masq.NewTagCensor("secret")
	gt.V(t, c("Field", "v", "secret")).Equal(true)
	gt.V(t, c("Field", "v", "other")).Equal(false)
	gt.V(t, c("Field", "v", "")).Equal(false)
}

func TestFieldNameCensor(t *testing.T) {
	c := masq.NewFieldNameCensor("Token")
	gt.V(t, c("Token", "v", "")).Equal(true)
	gt.V(t, c("token", "v", "")).Equal(false) // case-sensitive
	gt.V(t, c("Other", "v", "")).Equal(false)
}

func TestFieldPrefixCensor(t *testing.T) {
	c := masq.NewFieldPrefixCensor("Secure")
	gt.V(t, c("SecurePhone", "v", "")).Equal(true)
	gt.V(t, c("Secure", "v", "")).Equal(true) // exact prefix counts
	gt.V(t, c("Insecure", "v", "")).Equal(false)
	// Empty prefix matches anything; this is the documented behaviour.
	cEmpty := masq.NewFieldPrefixCensor("")
	gt.V(t, cEmpty("Anything", "v", "")).Equal(true)
}

func TestApplyCensorWithValue(t *testing.T) {
	type holder struct {
		Public  string
		private string
	}
	h := holder{Public: "p", private: "abcsecret"}
	v := reflect.ValueOf(&h).Elem()

	containsSecret := masq.NewStringCensor("secret")

	t.Run("exported value uses Interface path", func(t *testing.T) {
		// "Public" does not contain "secret" -> false
		got := masq.ApplyCensorWithValue(containsSecret, "Public", v.FieldByName("Public"), "")
		gt.V(t, got).Equal(false)
	})

	t.Run("unexported value uses extractValueSafely path", func(t *testing.T) {
		// "private" contains "secret" -> true
		got := masq.ApplyCensorWithValue(containsSecret, "private", v.FieldByName("private"), "")
		gt.V(t, got).Equal(true)
	})

	t.Run("falls back to nil when value cannot be extracted", func(t *testing.T) {
		// Field of a non-addressable struct: extraction fails, censor is called with nil.
		// A field-name based censor still works because it ignores the value.
		nameCensor := masq.NewFieldNameCensor("inner")
		nv := reflect.ValueOf(struct{ inner string }{inner: "x"}).FieldByName("inner")
		gt.V(t, nv.CanInterface()).Equal(false)
		gt.V(t, nv.CanAddr()).Equal(false)
		got := masq.ApplyCensorWithValue(nameCensor, "inner", nv, "")
		gt.V(t, got).Equal(true)
	})
}
