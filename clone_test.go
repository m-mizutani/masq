package masq_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/masq"
)

func allFieldCensor(fieldName string, value interface{}, tag string) bool {
	return fieldName != ""
}

func TestClone(t *testing.T) {
	c := masq.NewMasq(masq.WithContain("blue"))

	t.Run("string", func(t *testing.T) {
		v := gt.Cast[string](t, c.Redact("blue is blue"))
		gt.V(t, v).Equal(masq.DefaultRedactMessage)
	})

	t.Run("nil", func(t *testing.T) {
		gt.V(t, c.Redact(nil)).Nil()
	})

	t.Run("struct", func(t *testing.T) {
		type testData struct {
			ID    int
			Name  string
			Label string
		}

		t.Run("original data is not modified when filtered", func(t *testing.T) {
			data := &testData{
				ID:    100,
				Name:  "blue",
				Label: "five",
			}
			copied := gt.Cast[*testData](t, c.Redact(data))

			gt.V(t, copied).NotNil()
			gt.Value(t, masq.DefaultRedactMessage).Equal(copied.Name)
			gt.Value(t, data.Name).Equal("blue")
			gt.Value(t, data.Label).Equal("five")
			gt.Value(t, copied.Label).Equal("five")
			gt.Value(t, copied.ID).Equal(100)
		})

		t.Run("non-ptr struct can be modified", func(t *testing.T) {
			data := testData{
				Name:  "blue",
				Label: "five",
			}
			copied := gt.Cast[testData](t, c.Redact(data))
			gt.V(t, copied.Name).Equal(masq.DefaultRedactMessage)
			gt.V(t, copied.Label).Equal("five")
		})

		t.Run("nested structure can be modified", func(t *testing.T) {
			type testDataParent struct {
				Child testData
			}

			data := &testDataParent{
				Child: testData{
					Name:  "blue",
					Label: "five",
				},
			}
			copied := gt.Cast[*testDataParent](t, c.Redact(data))
			gt.V(t, copied.Child.Name).Equal(masq.DefaultRedactMessage)
			gt.V(t, copied.Child.Label).Equal("five")
		})

		t.Run("map data", func(t *testing.T) {
			data := map[string]*testData{
				"xyz": {
					Name:  "blue",
					Label: "five",
				},
			}
			copied := gt.Cast[map[string]*testData](t, c.Redact(data))

			gt.V(t, copied["xyz"].Name).Equal(masq.DefaultRedactMessage)
			gt.V(t, copied["xyz"].Label).Equal("five")
		})

		t.Run("array data", func(t *testing.T) {
			data := []testData{
				{
					Name:  "orange",
					Label: "five",
				},
				{
					Name:  "blue",
					Label: "five",
				},
			}
			copied := gt.Cast[[]testData](t, c.Redact(data))
			gt.V(t, copied[0].Name).Equal("orange")
			gt.V(t, copied[1].Name).Equal(masq.DefaultRedactMessage)
			gt.V(t, copied[1].Label).Equal("five")
		})

		t.Run("array data with ptr", func(t *testing.T) {
			data := []*testData{
				{
					Name:  "orange",
					Label: "five",
				},
				{
					Name:  "blue",
					Label: "five",
				},
			}
			copied := gt.Cast[[]*testData](t, c.Redact(data))
			gt.V(t, copied[0].Name).Equal("orange")
			gt.V(t, copied[1].Name).Equal(masq.DefaultRedactMessage)
			gt.V(t, copied[1].Label).Equal("five")
		})

		t.Run("original type", func(t *testing.T) {
			type myType string
			type myData struct {
				Name myType
			}
			data := &myData{
				Name: "miss blue",
			}
			copied := gt.Cast[*myData](t, c.Redact(data))
			gt.V(t, copied.Name).Equal(myType(masq.DefaultRedactMessage))
		})

		t.Run("unexported field should be copied", func(t *testing.T) {
			type myStruct struct {
				unexported string
				Exported   string
			}

			data := &myStruct{
				unexported: "red",
				Exported:   "orange",
			}
			copied := gt.Cast[*myStruct](t, c.Redact(data))
			gt.V(t, copied.unexported).Equal("red")
			gt.V(t, copied.Exported).Equal("orange")
		})

		t.Run("various field", func(t *testing.T) {
			type child struct{}
			type myStruct struct {
				Func      func() time.Time
				Chan      chan int
				Bool      bool
				Bytes     []byte
				Array     [2]string
				Interface interface{}
				Child     *child
			}
			data := &myStruct{
				Func:      time.Now,
				Chan:      make(chan int),
				Bool:      true,
				Bytes:     []byte("timeless"),
				Array:     [2]string{"aa", "bb"},
				Interface: &struct{}{},
				Child:     nil,
			}
			copied := gt.Cast[*myStruct](t, c.Redact(data))

			// function type is not comparable, but it's ok if not nil
			gt.V(t, copied.Func).NotNil()
			gt.V(t, copied.Chan).Equal(data.Chan)
			gt.V(t, copied.Bool).Equal(data.Bool)
			gt.V(t, copied.Bytes).Equal(data.Bytes)
			gt.V(t, copied.Array).Equal(data.Array)
			gt.V(t, copied.Interface).Equal(data.Interface)
		})
	})

	t.Run("filter various type", func(t *testing.T) {
		mask := masq.NewMasq(
			masq.WithCensor(allFieldCensor),
		)
		s := "test"

		type child struct {
			Data string
		}
		type myStruct struct {
			Func      func() time.Time
			Chan      chan int
			Bool      bool
			Bytes     []byte
			Strs      []string
			StrsPtr   []*string
			Interface interface{}
			Child     child
			ChildPtr  *child
		}
		data := &myStruct{
			Func:      time.Now,
			Chan:      make(chan int),
			Bool:      true,
			Bytes:     []byte("timeless"),
			Strs:      []string{"aa"},
			StrsPtr:   []*string{&s},
			Interface: &s,
			Child:     child{Data: "x"},
			ChildPtr:  &child{Data: "y"},
		}

		copied := gt.Cast[*myStruct](t, mask.Redact(data))

		gt.Value(t, copied.Func).Nil()
		gt.Value(t, copied.Chan).Nil()
		gt.Value(t, copied.Bytes).Nil()
		gt.Value(t, copied.Strs).Nil()
		gt.Value(t, copied.StrsPtr).Nil()
		gt.Value(t, copied.Interface).Nil()
		gt.Value(t, copied.Child.Data).Equal("")
		gt.Value(t, copied.ChildPtr).Nil()
	})
}

func TestMapData(t *testing.T) {
	c := masq.NewMasq(masq.WithContain("blue"))

	type testData struct {
		ID    int
		Name  string
		Label string
	}

	data := map[string]*testData{
		"xyz": {
			Name:  "blue",
			Label: "five",
		},
	}
	copied := gt.Cast[map[string]*testData](t, c.Redact(data))

	gt.V(t, copied["xyz"].Name).Equal(masq.DefaultRedactMessage)
	gt.V(t, copied["xyz"].Label).Equal("five")

}

func TestCloneUnexportedPointer(t *testing.T) {
	c := masq.NewMasq(masq.WithContain("blue"))
	type child struct {
		Name string
	}
	type myStruct struct {
		c *child
	}
	data := &myStruct{
		c: &child{
			Name: "orange",
		},
	}
	copied := gt.Cast[*myStruct](t, c.Redact(data))
	gt.V(t, copied.c.Name).Equal("orange")
}

func TestDoublePointer(t *testing.T) {
	c := masq.NewMasq(masq.WithContain("blue"))
	type child struct {
		Name string
	}
	type myStruct struct {
		c **child
	}
	childData := &child{
		Name: "orange",
	}
	data := &myStruct{
		c: &childData,
	}
	copied := gt.Cast[*myStruct](t, c.Redact(data))
	gt.V(t, (*copied.c).Name).Equal("orange")
}

func TestTime(t *testing.T) {
	ts := time.Now().UTC()
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))
	logger.Info("hello")

	var out map[string]any
	gt.NoError(t, json.Unmarshal(buf.Bytes(), &out))

	tv, ok := out["time"].(string)
	gt.B(t, ok).True()
	gt.S(t, tv).Contains(ts.Format("2006-01-02"))
}

type byteType [4]byte

func (x byteType) LogValue() slog.Value { return slog.StringValue("stringer") }

func TestDirectUUID(t *testing.T) {
	newID := byteType{1, 2, 3, 4}
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))
	logger.Info("hello",
		slog.Any("id", newID),
	)

	gt.S(t, buf.String()).Contains("stringer")
}

func TestNilInterface(t *testing.T) {
	var buf bytes.Buffer
	type myStruct struct {
		Data interface{}
	}
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))
	logger.Info("hello", slog.Any("test", myStruct{}))
	gt.S(t, buf.String()).Contains("null")
}

func TestCircularReference(t *testing.T) {
	type myStruct struct {
		Child *myStruct
		Str   string
	}
	data := &myStruct{
		Str: "blue",
	}
	data.Child = data

	c := masq.NewMasq(masq.WithContain("blue"))
	newData := c.Redact(data).(*myStruct)
	gt.V(t, newData.Child.Child.Str).Equal("[REDACTED]")
}

func TestCloneJsonUnmarshalTypeError(t *testing.T) {
	var s string
	src := json.Unmarshal([]byte(`["foo"]`), &s).(*json.UnmarshalTypeError)
	dst := masq.NewMasq().Redact(src).(*json.UnmarshalTypeError)
	gt.Equal(t, dst, src)
}

func TestCloneFunc(t *testing.T) {
	type myFunc func() string
	src := myFunc(func() string { return "blue" })
	dst := masq.NewMasq().Redact(src).(myFunc)
	gt.Equal(t, dst(), "blue")
}
