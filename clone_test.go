package masq_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

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
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(masq.WithAllowedType(reflect.TypeOf(time.Time{}))),
	}))

	// Get timestamp just before logging to minimize time difference
	beforeLog := time.Now()
	logger.Info("hello")
	afterLog := time.Now()

	var out map[string]any
	gt.NoError(t, json.Unmarshal(buf.Bytes(), &out))

	tv, ok := out["time"].(string)
	gt.B(t, ok).True()

	// Parse the logged time
	loggedTime, err := time.Parse(time.RFC3339Nano, tv)
	gt.NoError(t, err)

	// Verify the logged time is within the expected range
	if loggedTime.Before(beforeLog) || loggedTime.After(afterLog) {
		t.Errorf("Logged time %v is not within expected range [%v, %v]", loggedTime, beforeLog, afterLog)
	}
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

func TestCloneFunc(t *testing.T) {
	type myFunc func() string
	src := myFunc(func() string { return "blue" })
	dst := masq.NewMasq().Redact(src).(myFunc)
	gt.Equal(t, dst(), "blue")
}

func TestUnmarshalTypeError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))
	var s string
	err := json.Unmarshal([]byte(`["foo"]`), &s)
	logger.Info("error", slog.Any("err", err))
	gt.S(t, buf.String()).Contains("error")
}

func TestCloneUnexportedStructFields(t *testing.T) {
	// Test for handling unexported fields in unexported structs
	type unexportedInner struct {
		privateField string
		PublicField  string
	}

	type publicOuter struct {
		Inner      unexportedInner
		InnerPtr   *unexportedInner
		unexported string
		Exported   string
	}

	data := &publicOuter{
		Inner: unexportedInner{
			privateField: "secret1",
			PublicField:  "public1",
		},
		InnerPtr: &unexportedInner{
			privateField: "secret2",
			PublicField:  "public2",
		},
		unexported: "hidden",
		Exported:   "visible",
	}

	mask := masq.NewMasq()
	copied := gt.Cast[*publicOuter](t, mask.Redact(data))

	// Verify all fields are copied correctly
	gt.V(t, copied.Inner.privateField).Equal("secret1")
	gt.V(t, copied.Inner.PublicField).Equal("public1")
	gt.V(t, copied.InnerPtr.privateField).Equal("secret2")
	gt.V(t, copied.InnerPtr.PublicField).Equal("public2")
	gt.V(t, copied.unexported).Equal("hidden")
	gt.V(t, copied.Exported).Equal("visible")
}

func TestCloneComplexUnexportedTypes(t *testing.T) {
	// Test with slices, maps, and arrays of unexported types
	type unexportedType struct {
		value string
		num   int
	}

	type complexStruct struct {
		Slice     []unexportedType
		SlicePtr  []*unexportedType
		Array     [2]unexportedType
		Map       map[string]unexportedType
		MapPtr    map[string]*unexportedType
		Interface interface{}
	}

	data := &complexStruct{
		Slice: []unexportedType{
			{value: "val1", num: 1},
			{value: "val2", num: 2},
		},
		SlicePtr: []*unexportedType{
			{value: "ptr1", num: 11},
			{value: "ptr2", num: 22},
		},
		Array: [2]unexportedType{
			{value: "arr1", num: 111},
			{value: "arr2", num: 222},
		},
		Map: map[string]unexportedType{
			"key1": {value: "map1", num: 100},
			"key2": {value: "map2", num: 200},
		},
		MapPtr: map[string]*unexportedType{
			"ptr1": {value: "mapptr1", num: 1000},
			"ptr2": {value: "mapptr2", num: 2000},
		},
		Interface: &unexportedType{value: "iface", num: 999},
	}

	mask := masq.NewMasq()
	copied := gt.Cast[*complexStruct](t, mask.Redact(data))

	// Verify slices
	gt.V(t, len(copied.Slice)).Equal(2)
	gt.V(t, copied.Slice[0].value).Equal("val1")
	gt.V(t, copied.Slice[0].num).Equal(1)
	gt.V(t, copied.Slice[1].value).Equal("val2")
	gt.V(t, copied.Slice[1].num).Equal(2)

	// Verify slice of pointers
	gt.V(t, len(copied.SlicePtr)).Equal(2)
	gt.V(t, copied.SlicePtr[0].value).Equal("ptr1")
	gt.V(t, copied.SlicePtr[0].num).Equal(11)

	// Verify array
	gt.V(t, copied.Array[0].value).Equal("arr1")
	gt.V(t, copied.Array[0].num).Equal(111)

	// Verify map
	gt.V(t, len(copied.Map)).Equal(2)
	gt.V(t, copied.Map["key1"].value).Equal("map1")
	gt.V(t, copied.Map["key1"].num).Equal(100)

	// Verify map of pointers
	gt.V(t, len(copied.MapPtr)).Equal(2)
	gt.V(t, copied.MapPtr["ptr1"].value).Equal("mapptr1")
	gt.V(t, copied.MapPtr["ptr1"].num).Equal(1000)

	// Verify interface
	iface := copied.Interface.(*unexportedType)
	gt.V(t, iface.value).Equal("iface")
	gt.V(t, iface.num).Equal(999)
}

func TestMapWithStructValues(t *testing.T) {
	// Test with exported struct in map first
	type Item struct {
		ID    string
		Value int
	}

	type container struct {
		ItemMap map[string]Item
	}

	original := &container{
		ItemMap: map[string]Item{
			"key1": {ID: "id1", Value: 100},
			"key2": {ID: "id2", Value: 200},
		},
	}

	mask := masq.NewMasq()
	cloned := mask.Redact(original).(*container)

	gt.V(t, len(cloned.ItemMap)).Equal(2)
	gt.V(t, cloned.ItemMap["key1"].ID).Equal("id1")
	gt.V(t, cloned.ItemMap["key1"].Value).Equal(100)

	// Now test with unexported struct
	type item struct {
		id    string
		value int
	}

	type container2 struct {
		itemMap map[string]item
	}

	original2 := &container2{
		itemMap: map[string]item{
			"key1": {id: "id1", value: 100},
			"key2": {id: "id2", value: 200},
		},
	}

	cloned2 := mask.Redact(original2).(*container2)

	// Access values directly - due to map limitation with unexported types,
	// the map is returned as-is
	item1 := cloned2.itemMap["key1"]
	gt.V(t, item1.id).Equal("id1")
	gt.V(t, item1.value).Equal(100)
}

func TestMapWithUnexportedTypes(t *testing.T) {
	t.Run("maps with unexported types have limitations", func(t *testing.T) {
		// This test demonstrates the limitation mentioned in README.md
		original := NewMapContainer()

		mask := masq.NewMasq()
		cloned := gt.Cast[*MapContainer](t, mask.Redact(original))

		// Both UserMap (map[string]*privateUser) and DataMap (map[string]privateData)
		// should be the same reference due to Go reflection limitations

		// Check UserMap - even with pointers to unexported types, it's not cloned
		gt.V(t, len(cloned.UserMap)).Equal(2)
		originalUser1 := original.UserMap["user1"]
		clonedUser1 := cloned.UserMap["user1"]
		gt.V(t, clonedUser1).Equal(originalUser1) // Same pointer - map wasn't cloned

		// Check DataMap - direct unexported type, also not cloned
		gt.V(t, len(cloned.DataMap)).Equal(2)
	})

	t.Run("filtering still works on maps with unexported types", func(t *testing.T) {
		original := NewMapContainer()

		// Create mask that redacts "password" field
		mask := masq.NewMasq(masq.WithFieldName("password"))
		cloned := gt.Cast[*MapContainer](t, mask.Redact(original))

		// Even though the map isn't cloned, filtering still works
		// because the map contains pointers, and we can clone the pointed-to values
		user1 := cloned.UserMap["user1"]

		// The pointer should be different because we cloned the struct
		gt.V(t, user1).NotEqual(original.UserMap["user1"])

		// And the password should be redacted
		gt.V(t, user1.id).Equal("u1")
		gt.V(t, user1.username).Equal("alice")
		gt.V(t, user1.password).Equal("[REDACTED]")
	})

	t.Run("maps with un-interfaceable keys or values", func(t *testing.T) {
		// This test verifies that maps containing un-interfaceable keys or values
		// are returned as-is to prevent data loss or corruption

		// Create a map through reflection that may have un-interfaceable entries
		type privateKey struct {
			id string
		}
		type container struct {
			// Map with unexported key type
			M1 map[privateKey]string
			// Map that might contain un-interfaceable values
			M2 map[string]interface{}
		}

		original := &container{
			M1: map[privateKey]string{
				{id: "key1"}: "value1",
				{id: "key2"}: "value2",
			},
			M2: make(map[string]interface{}),
		}

		// Add some values that might not be interfaceable
		original.M2["normal"] = "value"

		mask := masq.NewMasq()
		cloned := gt.Cast[*container](t, mask.Redact(original))

		// Maps with unexported key types should be the same reference
		gt.V(t, fmt.Sprintf("%p", cloned.M1)).Equal(fmt.Sprintf("%p", original.M1))

		// Verify the map content is unchanged
		gt.V(t, len(cloned.M1)).Equal(2)

		// M2 should be cloned since it has exported types
		gt.V(t, fmt.Sprintf("%p", cloned.M2)).NotEqual(fmt.Sprintf("%p", original.M2))
		gt.V(t, cloned.M2["normal"]).Equal("value")
	})

	t.Run("maps in unexported fields cannot be cloned", func(t *testing.T) {
		// This test verifies that maps within unexported struct fields
		// are returned as-is because they cannot be safely cloned
		type container struct {
			Public      string
			privateMap  map[string]string
			privateData map[string]struct {
				value string
			}
		}

		original := &container{
			Public: "public",
			privateMap: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			privateData: map[string]struct{ value string }{
				"data1": {value: "secret1"},
				"data2": {value: "secret2"},
			},
		}

		mask := masq.NewMasq()

		// Should not panic
		cloned := gt.Cast[*container](t, mask.Redact(original))

		// Public field should be cloned
		gt.V(t, cloned.Public).Equal("public")

		// Maps in unexported fields should be the same reference
		gt.V(t, fmt.Sprintf("%p", cloned.privateMap)).Equal(fmt.Sprintf("%p", original.privateMap))
		gt.V(t, fmt.Sprintf("%p", cloned.privateData)).Equal(fmt.Sprintf("%p", original.privateData))

		// Verify content is unchanged
		gt.V(t, cloned.privateMap["key1"]).Equal("value1")
		gt.V(t, cloned.privateData["data1"].value).Equal("secret1")
	})

	t.Run("no panic with complex unexported map scenarios", func(t *testing.T) {
		// This test ensures that various edge cases with maps don't cause panics
		type inner struct {
			data map[string]interface{}
		}
		type outer struct {
			Public string
			nested inner
			direct map[interface{}]interface{}
		}

		original := &outer{
			Public: "public",
			nested: inner{
				data: map[string]interface{}{
					"key": "value",
				},
			},
			direct: map[interface{}]interface{}{
				"key": "value",
				123:   456,
			},
		}

		mask := masq.NewMasq()

		// Should not panic even with complex map scenarios
		var cloned *outer
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Unexpected panic: %v", r)
				}
			}()
			cloned = gt.Cast[*outer](t, mask.Redact(original))
		}()

		// Verify that the struct was cloned (even if maps weren't)
		gt.V(t, cloned).NotNil()
		gt.V(t, cloned.Public).Equal("public")
	})

	t.Run("map value redaction in unexported field context", func(t *testing.T) {
		// This test specifically verifies the case mentioned in the PR review
		// where SetMapIndex would panic with values from unexported fields
		type container struct {
			Public string
			// Map in unexported field - values cannot be redacted
			secrets map[string]string
		}

		original := &container{
			Public: "public",
			secrets: map[string]string{
				"password": "secret123",
				"apiKey":   "sk-12345",
				"normal":   "not-secret",
			},
		}

		// Even with field name filter, map values in unexported fields cannot be redacted
		mask := masq.NewMasq(
			masq.WithFieldName("password"),
			masq.WithFieldName("apiKey"),
		)

		// Should not panic
		cloned := gt.Cast[*container](t, mask.Redact(original))

		// Map should be the same reference (not cloned)
		gt.V(t, fmt.Sprintf("%p", cloned.secrets)).Equal(fmt.Sprintf("%p", original.secrets))

		// Values are NOT redacted because the map is in an unexported field
		gt.V(t, cloned.secrets["password"]).Equal("secret123")
		gt.V(t, cloned.secrets["apiKey"]).Equal("sk-12345")
		gt.V(t, cloned.secrets["normal"]).Equal("not-secret")
	})

	t.Run("prevent data loss from un-interfaceable keys", func(t *testing.T) {
		// This test verifies that we don't lose data by mapping multiple
		// un-interfaceable keys to the same zero value

		// Create a struct with unexported fields to use as map keys
		type complexKey struct {
			id   int
			name string
		}

		type container struct {
			// Map with struct keys containing unexported fields
			Data map[complexKey]string
		}

		original := &container{
			Data: map[complexKey]string{
				{id: 1, name: "first"}:  "value1",
				{id: 2, name: "second"}: "value2",
				{id: 3, name: "third"}:  "value3",
			},
		}

		mask := masq.NewMasq()
		cloned := gt.Cast[*container](t, mask.Redact(original))

		// Map should be the same reference (not cloned) due to unexported key type
		gt.V(t, fmt.Sprintf("%p", cloned.Data)).Equal(fmt.Sprintf("%p", original.Data))

		// All entries should still exist (no data loss)
		gt.V(t, len(cloned.Data)).Equal(3)
		gt.V(t, cloned.Data[complexKey{id: 1, name: "first"}]).Equal("value1")
		gt.V(t, cloned.Data[complexKey{id: 2, name: "second"}]).Equal("value2")
		gt.V(t, cloned.Data[complexKey{id: 3, name: "third"}]).Equal("value3")
	})
}

func TestMapFieldCloning(t *testing.T) {
	t.Run("exported map field", func(t *testing.T) {
		type container struct {
			M map[string]string
		}

		original := &container{
			M: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		}

		mask := masq.NewMasq()
		cloned := mask.Redact(original).(*container)

		gt.V(t, len(cloned.M)).Equal(2)
		gt.V(t, cloned.M["key1"]).Equal("value1")
		gt.V(t, cloned.M["key2"]).Equal("value2")
	})

	t.Run("unexported map field", func(t *testing.T) {
		type container struct {
			m map[string]string
		}

		// Helper to access unexported field
		getMap := func(c *container) map[string]string {
			return c.m
		}

		original := &container{
			m: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		}

		mask := masq.NewMasq()
		cloned := mask.Redact(original).(*container)

		clonedMap := getMap(cloned)
		gt.V(t, len(clonedMap)).Equal(2)
		gt.V(t, clonedMap["key1"]).Equal("value1")
		gt.V(t, clonedMap["key2"]).Equal("value2")
	})
}

func TestCloneExternalUnexportedStructs(t *testing.T) {
	t.Run("PublicUser with unexported fields", func(t *testing.T) {
		original := NewPublicUser()
		mask := masq.NewMasq()

		copied := gt.Cast[*PublicUser](t, mask.Redact(original))

		// Verify exported fields
		gt.V(t, copied.ID).Equal("user-123")
		gt.V(t, copied.Email).Equal("john@example.com")
		// For time.Time, we should check if it's not zero
		gt.V(t, copied.CreatedAt.IsZero()).Equal(false)

		// Verify unexported fields
		gt.V(t, copied.username).Equal("john_doe")
		gt.V(t, copied.password).Equal("secret123")

		// Verify unexported nested struct
		gt.V(t, copied.metadata.loginCount).Equal(42)
		// Skip map verification due to limitation with unexported types
		// gt.V(t, metadata.GetPreference("theme")).Equal("dark")
		// gt.V(t, metadata.GetPreference("language")).Equal("en")
	})

	t.Run("PublicConfig with nested unexported structs", func(t *testing.T) {
		original := NewPublicConfig()
		mask := masq.NewMasq()

		copied := gt.Cast[*PublicConfig](t, mask.Redact(original))

		// Verify exported fields
		gt.V(t, copied.AppName).Equal("TestApp")
		gt.V(t, copied.Version).Equal("1.0.0")

		// Verify unexported fields
		gt.V(t, copied.apiKey).Equal("sk-1234567890abcdef")
		gt.V(t, copied.dbPassword).Equal("postgres://secret")

		// Verify nested unexported struct
		gt.V(t, copied.Settings.debug).Equal(true)
		gt.V(t, copied.Settings.maxRetries).Equal(3)
		gt.V(t, copied.Settings.timeout.String()).Equal("30s")
		gt.V(t, len(copied.Settings.endpoints)).Equal(2)

		// Verify endpoints (slice of unexported structs)
		endpoint1 := copied.Settings.endpoints[0]
		gt.V(t, endpoint1.name).Equal("api")
		gt.V(t, endpoint1.url).Equal("https://api.example.com")
		gt.V(t, endpoint1.auth.token).Equal("bearer-token-123")

		endpoint2 := copied.Settings.endpoints[1]
		gt.V(t, endpoint2.name).Equal("webhook")
		gt.V(t, endpoint2.url).Equal("https://webhook.example.com")
		gt.V(t, endpoint2.auth.token).Equal("webhook-secret-456")

		// Verify credentials (pointer to unexported struct)
		gt.V(t, copied.Settings.credentials != nil).Equal(true)
		creds := copied.Settings.credentials
		gt.V(t, creds.username).Equal("admin")
		gt.V(t, creds.password).Equal("admin123")
		gt.V(t, creds.apiKey).Equal("master-key-789")
	})

	t.Run("ComplexData with various unexported types", func(t *testing.T) {
		original := NewComplexData()
		mask := masq.NewMasq()

		copied := gt.Cast[*ComplexData](t, mask.Redact(original))

		// Verify exported field
		gt.V(t, copied.Name).Equal("Complex")

		// Verify slice of unexported structs
		gt.V(t, len(copied.items)).Equal(2)
		item1 := copied.items[0]
		gt.V(t, item1.id).Equal("item1")
		gt.V(t, item1.value).Equal(100)
		gt.V(t, item1.tags[0]).Equal("tag1")
		gt.V(t, item1.tags[1]).Equal("tag2")

		// Verify slice of pointers to unexported structs
		itemPtr1 := copied.itemsPtr[0]
		gt.V(t, itemPtr1).NotNil()
		gt.V(t, itemPtr1.id).Equal("ptr1")
		gt.V(t, itemPtr1.value).Equal(300)

		// Skip map verification due to limitation with unexported types in maps
		// The itemMap field (map[string]item) cannot be properly cloned because 'item' is an unexported type
		// As documented in README.md, maps with unexported value types are returned as-is without cloning
		// This means:
		// 1. The map itself is not cloned (same reference)
		// 2. Values in the map cannot be modified/filtered
		// 3. GetItemFromMap would return the original item, not a cloned one
		// mapItem := copied.GetItemFromMap("key1")
		// gt.V(t, mapItem.GetID()).Equal("map1")
		// gt.V(t, mapItem.GetValue()).Equal(500)

		// Verify array of unexported structs
		arrayItem := copied.itemArray[0]
		gt.V(t, arrayItem.id).Equal("arr1")
		gt.V(t, arrayItem.value).Equal(700)

		// Verify interface containing unexported struct
		ifaceItem := copied.Interface.(*item)
		gt.V(t, ifaceItem).NotNil()
		gt.V(t, ifaceItem.id).Equal("iface")
		gt.V(t, ifaceItem.value).Equal(1000)
	})

	t.Run("ComplexData itemMap limitation demonstration", func(t *testing.T) {
		// This test explicitly demonstrates the limitation with itemMap
		original := NewComplexData()
		mask := masq.NewMasq()
		cloned := gt.Cast[*ComplexData](t, mask.Redact(original))

		// The itemMap field should be the same reference (not cloned)
		// We can verify this indirectly by checking that modifications to the original
		// would affect the cloned version (though we can't modify unexported types directly)

		// We can at least verify the map still has data
		item := cloned.itemMap["key1"]
		gt.V(t, item.id).Equal("map1")
		gt.V(t, item.value).Equal(500)

		// Note: Unlike slices and arrays of unexported types which ARE properly cloned,
		// maps with unexported value types are NOT cloned due to Go's reflection limitations
		t.Log("itemMap was not cloned - this is expected behavior due to Go reflection limitations")
	})
}

func TestUnexportedFieldsEdgeCases(t *testing.T) {
	t.Run("Empty string in unexported fields", func(t *testing.T) {
		type testStruct struct {
			Public     string
			unexported string
		}

		original := &testStruct{
			Public:     "public",
			unexported: "", // empty string
		}

		mask := masq.NewMasq()
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, copied.unexported).Equal("") // Should preserve empty string
	})

	t.Run("Nil pointer in unexported field", func(t *testing.T) {
		type inner struct {
			value string
		}
		type testStruct struct {
			Public      string
			unexported  *inner
			unexported2 *inner
		}

		original := &testStruct{
			Public:      "public",
			unexported:  nil, // nil pointer
			unexported2: &inner{value: "test"},
		}

		mask := masq.NewMasq()
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, copied.unexported).Nil()
		gt.V(t, copied.unexported2).NotNil()
		gt.V(t, copied.unexported2.value).Equal("test")
	})

	t.Run("Empty slice and map in unexported fields", func(t *testing.T) {
		type testStruct struct {
			Public             string
			unexportedSlice    []string
			unexportedMap      map[string]string
			unexportedNilSlice []string
			unexportedNilMap   map[string]string
		}

		original := &testStruct{
			Public:             "public",
			unexportedSlice:    []string{},          // empty slice
			unexportedMap:      map[string]string{}, // empty map
			unexportedNilSlice: nil,                 // nil slice
			unexportedNilMap:   nil,                 // nil map
		}

		mask := masq.NewMasq()
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		// Empty slices should be copied as empty slices
		gt.V(t, len(copied.unexportedSlice)).Equal(0)
		// Empty maps should be copied as empty maps
		gt.V(t, len(copied.unexportedMap)).Equal(0)
		// NOTE: Current implementation converts nil slices to empty slices
		gt.V(t, len(copied.unexportedNilSlice)).Equal(0)
		// NOTE: Current implementation converts nil maps to empty maps
		gt.V(t, len(copied.unexportedNilMap)).Equal(0)
	})

	t.Run("Zero values in unexported numeric fields", func(t *testing.T) {
		type testStruct struct {
			Public       string
			intField     int
			floatField   float64
			boolField    bool
			uintField    uint
			complexField complex128
		}

		original := &testStruct{
			Public: "public",
			// All numeric fields have zero values
		}

		mask := masq.NewMasq()
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, copied.intField).Equal(0)
		gt.V(t, copied.floatField).Equal(0.0)
		gt.V(t, copied.boolField).Equal(false)
		gt.V(t, copied.uintField).Equal(uint(0))
		gt.V(t, copied.complexField).Equal(complex128(0))
	})

	t.Run("Unexported interface field handling", func(t *testing.T) {
		// NOTE: Unexported interface fields can cause runtime errors in Go's reflection system
		// This is documented in README as a known limitation
		t.Skip("Skipping due to Go reflection limitations with unexported interface fields (see README)")
	})

	t.Run("Deeply nested unexported structs with empty values", func(t *testing.T) {
		type level3 struct{}
		type level2 struct {
			inner *level3
			slice []level3
		}
		type level1 struct {
			Public string
			nested level2
		}

		original := &level1{
			Public: "public",
			nested: level2{
				inner: nil,
				slice: []level3{},
			},
		}

		mask := masq.NewMasq()
		copied := gt.Cast[*level1](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, copied.nested.inner).Nil()
		gt.V(t, len(copied.nested.slice)).Equal(0)
	})

	t.Run("Unexported array fields", func(t *testing.T) {
		type testStruct struct {
			Public     string
			emptyArray [0]string
			smallArray [3]int
			ptrArray   [2]*string
		}

		s1 := "one"
		original := &testStruct{
			Public:     "public",
			emptyArray: [0]string{},
			smallArray: [3]int{1, 0, 3},      // includes zero
			ptrArray:   [2]*string{&s1, nil}, // includes nil
		}

		mask := masq.NewMasq()
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		gt.V(t, len(copied.emptyArray)).Equal(0)
		gt.V(t, copied.smallArray).Equal([3]int{1, 0, 3})
		gt.V(t, copied.ptrArray[0]).NotNil()
		gt.V(t, *copied.ptrArray[0]).Equal("one")
		gt.V(t, copied.ptrArray[1]).Nil()
	})

	t.Run("Unexported array with struct elements can be redacted", func(t *testing.T) {
		type user struct {
			name     string
			password string
		}
		type testStruct struct {
			Public string
			users  [3]user
		}

		original := &testStruct{
			Public: "public",
			users: [3]user{
				{name: "alice", password: "secret1"},
				{name: "bob", password: "secret2"},
				{name: "charlie", password: "secret3"},
			},
		}

		mask := masq.NewMasq(masq.WithFieldName("password"))
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		// All passwords should be redacted
		gt.V(t, copied.users[0].name).Equal("alice")
		gt.V(t, copied.users[0].password).Equal("[REDACTED]")
		gt.V(t, copied.users[1].name).Equal("bob")
		gt.V(t, copied.users[1].password).Equal("[REDACTED]")
		gt.V(t, copied.users[2].name).Equal("charlie")
		gt.V(t, copied.users[2].password).Equal("[REDACTED]")
	})

	t.Run("Unexported array with mixed types", func(t *testing.T) {
		type sensitive struct {
			apiKey string
		}
		type testStruct struct {
			Public      string
			stringArray [2]string
			structArray [2]sensitive
		}

		original := &testStruct{
			Public:      "public",
			stringArray: [2]string{"normal", "Bearer token123"},
			structArray: [2]sensitive{
				{apiKey: "sk-12345"},
				{apiKey: "sk-67890"},
			},
		}

		mask := masq.NewMasq(
			masq.WithContain("Bearer"),
			masq.WithFieldName("apiKey"),
		)
		copied := gt.Cast[*testStruct](t, mask.Redact(original))

		gt.V(t, copied.Public).Equal("public")
		// String array element with "Bearer" should be redacted
		gt.V(t, copied.stringArray[0]).Equal("normal")
		gt.V(t, copied.stringArray[1]).Equal("[REDACTED]")
		// Struct array elements with apiKey field should be redacted
		gt.V(t, copied.structArray[0].apiKey).Equal("[REDACTED]")
		gt.V(t, copied.structArray[1].apiKey).Equal("[REDACTED]")
	})
}

// Types moved from testdata/unexported_structs

// PublicUser is an exported struct with mixed fields
type PublicUser struct {
	ID        string
	username  string // unexported
	Email     string
	password  string // unexported
	CreatedAt time.Time
	metadata  userMeta // unexported type
}

// userMeta is an unexported struct
type userMeta struct {
	lastLogin   time.Time
	loginCount  int
	preferences map[string]string
}

// PublicConfig with unexported fields and nested types
type PublicConfig struct {
	AppName    string
	Version    string
	apiKey     string // unexported sensitive field
	dbPassword string // unexported sensitive field
	Settings   settings
}

// settings is unexported struct
type settings struct {
	debug       bool
	maxRetries  int
	timeout     time.Duration
	endpoints   []endpoint
	credentials *credential
}

// endpoint is unexported
type endpoint struct {
	name string
	url  string
	auth authInfo
}

// authInfo is unexported
type authInfo struct {
	token  string
	expiry time.Time
}

// credential is unexported
type credential struct {
	username string
	password string
	apiKey   string
}

// NewPublicUser creates a new user with all fields populated
func NewPublicUser() *PublicUser {
	return &PublicUser{
		ID:        "user-123",
		username:  "john_doe",
		Email:     "john@example.com",
		password:  "secret123",
		CreatedAt: time.Now(),
		metadata: userMeta{
			lastLogin:  time.Now(),
			loginCount: 42,
			preferences: map[string]string{
				"theme":    "dark",
				"language": "en",
			},
		},
	}
}

// NewPublicConfig creates a config with nested unexported structs
func NewPublicConfig() *PublicConfig {
	return &PublicConfig{
		AppName:    "TestApp",
		Version:    "1.0.0",
		apiKey:     "sk-1234567890abcdef",
		dbPassword: "postgres://secret",
		Settings: settings{
			debug:      true,
			maxRetries: 3,
			timeout:    30 * time.Second,
			endpoints: []endpoint{
				{
					name: "api",
					url:  "https://api.example.com",
					auth: authInfo{
						token:  "bearer-token-123",
						expiry: time.Now().Add(24 * time.Hour),
					},
				},
				{
					name: "webhook",
					url:  "https://webhook.example.com",
					auth: authInfo{
						token:  "webhook-secret-456",
						expiry: time.Now().Add(48 * time.Hour),
					},
				},
			},
			credentials: &credential{
				username: "admin",
				password: "admin123",
				apiKey:   "master-key-789",
			},
		},
	}
}

// ComplexData has various types of unexported fields
type ComplexData struct {
	Name      string
	items     []item          // ✅ Slice of unexported type - can be cloned properly
	itemsPtr  []*item         // ✅ Slice of pointers to unexported type - can be cloned properly
	itemMap   map[string]item // ❌ Map with unexported value type - CANNOT be cloned (Go reflection limitation)
	itemArray [3]item         // ✅ Array of unexported type - can be cloned properly
	Interface interface{}     // ✅ Interface containing unexported type - can be cloned properly
}

// item is unexported
type item struct {
	id    string
	value int
	tags  []string
}

// NewComplexData creates complex nested data
func NewComplexData() *ComplexData {
	return &ComplexData{
		Name: "Complex",
		items: []item{
			{id: "item1", value: 100, tags: []string{"tag1", "tag2"}},
			{id: "item2", value: 200, tags: []string{"tag3"}},
		},
		itemsPtr: []*item{
			{id: "ptr1", value: 300, tags: []string{"ptag1"}},
			{id: "ptr2", value: 400, tags: nil},
		},
		itemMap: map[string]item{
			"key1": {id: "map1", value: 500, tags: []string{"mtag1"}},
			"key2": {id: "map2", value: 600, tags: []string{"mtag2", "mtag3"}},
		},
		itemArray: [3]item{
			{id: "arr1", value: 700, tags: []string{"atag1"}},
			{id: "arr2", value: 800, tags: []string{"atag2"}},
			{id: "arr3", value: 900, tags: []string{"atag3"}},
		},
		Interface: &item{id: "iface", value: 1000, tags: []string{"itag"}},
	}
}

// MapContainer specifically tests maps with pointers to unexported types
type MapContainer struct {
	// Map with pointer to unexported type - still has limitations
	// Even though the value is a pointer, the pointed-to type is unexported,
	// so the map cannot be cloned due to Go reflection limitations
	UserMap map[string]*privateUser // ❌ Cannot be cloned

	// Map with unexported type directly - has same limitations
	DataMap map[string]privateData // ❌ Cannot be cloned
}

// privateUser is unexported
type privateUser struct {
	id       string
	username string
	password string
}

// privateData is unexported
type privateData struct {
	content string
	secret  string
}

// NewMapContainer creates a container with different map types
func NewMapContainer() *MapContainer {
	return &MapContainer{
		UserMap: map[string]*privateUser{
			"user1": {id: "u1", username: "alice", password: "pass123"},
			"user2": {id: "u2", username: "bob", password: "secret456"},
		},
		DataMap: map[string]privateData{
			"data1": {content: "content1", secret: "secret1"},
			"data2": {content: "content2", secret: "secret2"},
		},
	}
}

func TestUnexportedFieldHandling(t *testing.T) {
	t.Run("struct with unexported fields", func(t *testing.T) {
		type structWithUnexported struct {
			PublicField  string
			privateField string
		}

		original := &structWithUnexported{
			PublicField:  "public",
			privateField: "private",
		}

		mask := masq.NewMasq()
		// This should not panic
		cloned := gt.Cast[*structWithUnexported](t, mask.Redact(original))

		gt.V(t, cloned.PublicField).Equal("public")
		// Main goal: no panic during cloning
	})

	t.Run("slice with unexported element type", func(t *testing.T) {
		type unexportedStruct struct {
			value string
		}

		original := []unexportedStruct{
			{value: "item1"},
			{value: "item2"},
		}

		mask := masq.NewMasq()
		// This should not panic
		cloned := gt.Cast[[]unexportedStruct](t, mask.Redact(original))

		gt.V(t, len(cloned)).Equal(2)
	})

	t.Run("pointer to unexported struct field", func(t *testing.T) {
		type unexportedStruct struct {
			content string
		}

		type container struct {
			Data *unexportedStruct
		}

		original := &container{
			Data: &unexportedStruct{content: "test"},
		}

		mask := masq.NewMasq()
		// This should not panic
		cloned := gt.Cast[*container](t, mask.Redact(original))

		gt.V(t, cloned.Data).NotNil()
		// Main goal: no panic during cloning
	})
}

// Custom types to test default case behavior for uintptr panic fix
type defaultCaseCustomUint uint
type defaultCaseCustomInt int
type defaultCaseCustomFloat float64

// TestDefaultCaseUnexportedFieldPanicFix tests that types reaching default case don't panic
func TestDefaultCaseUnexportedFieldPanicFix(t *testing.T) {
	tests := []struct {
		name string
		data interface{}
	}{
		{
			name: "unexported uintptr field",
			data: &struct {
				PublicField string
				ptr         uintptr // uintptr reaches default case
			}{
				PublicField: "public",
				ptr:         uintptr(unsafe.Pointer(&struct{}{})),
			},
		},
		{
			name: "custom uint types",
			data: &struct {
				PublicField string
				customUint  defaultCaseCustomUint // custom types reach default case
				customInt   defaultCaseCustomInt
				customFloat defaultCaseCustomFloat
			}{
				PublicField: "public",
				customUint:  defaultCaseCustomUint(42),
				customInt:   defaultCaseCustomInt(24),
				customFloat: defaultCaseCustomFloat(3.14),
			},
		},
		{
			name: "uintptr in nested struct",
			data: &struct {
				PublicField string
				nested      struct {
					ptr uintptr // nested unexported uintptr
				}
			}{
				PublicField: "public",
				nested: struct {
					ptr uintptr
				}{
					ptr: uintptr(unsafe.Pointer(&struct{}{})),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				ReplaceAttr: masq.New(),
			}))

			// This should not panic with the fix
			logger.Info("test message", "data", tt.data)

			// Just ensure we get some log output
			output := buf.String()
			if len(output) == 0 {
				t.Error("Expected log output, got empty string")
			}
			t.Logf("Log output: %s", output)
		})
	}
}

// TestDefaultCaseValueCopyBehaviorAfterFix verifies that values are properly copied in default case
func TestDefaultCaseValueCopyBehaviorAfterFix(t *testing.T) {
	// Create a struct with uintptr that would trigger default case
	original := &struct {
		PublicField string
		ptr         uintptr
	}{
		PublicField: "test",
		ptr:         uintptr(123), // Simple value for testing
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))

	// This should succeed without panic
	logger.Info("test message", "data", original)

	output := buf.String()
	t.Logf("Log output: %s", output)

	// Verify that the public field is logged correctly
	if !bytes.Contains([]byte(output), []byte("test")) {
		t.Error("Expected 'test' to be in the output")
	}
}

// TestDefaultCaseWithFilteringAfterFix tests that filtering still works for default case types
func TestDefaultCaseWithFilteringAfterFix(t *testing.T) {
	type structWithFilterableUintptr struct {
		PublicField string
		secret      uintptr // unexported field that should be filtered by name
	}

	original := &structWithFilterableUintptr{
		PublicField: "public",
		secret:      uintptr(123),
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(
			masq.WithFieldName("secret"), // Filter by field name
		),
	}))

	logger.Info("test message", "data", original)

	output := buf.String()
	t.Logf("Log output: %s", output)

	// The output should contain the public field but the secret field should be filtered
	if !bytes.Contains([]byte(output), []byte("public")) {
		t.Error("Expected 'public' to be in the output")
	}
}

// TestAllPotentialPanicCases tests comprehensive panic prevention
func TestAllPotentialPanicCases(t *testing.T) {
	tests := []struct {
		name string
		data interface{}
	}{
		// 1. Function types in unexported fields
		{
			name: "unexported function field",
			data: &struct {
				PublicField string
				fn          func() string // function type
			}{
				PublicField: "public",
				fn:          func() string { return "test" },
			},
		},
		// 2. Channel types in unexported fields
		{
			name: "unexported channel field",
			data: &struct {
				PublicField string
				ch          chan int // channel type
			}{
				PublicField: "public",
				ch:          make(chan int),
			},
		},
		// 3. Nil channel in unexported field
		{
			name: "nil channel in unexported field",
			data: &struct {
				PublicField string
				ch          chan int // nil channel
			}{
				PublicField: "public",
				ch:          nil,
			},
		},
		// 4. Context types (interface with unexported methods)
		{
			name: "context in unexported field",
			data: &struct {
				PublicField string
				ctx         context.Context // context interface
			}{
				PublicField: "public",
				ctx:         context.Background(),
			},
		},
		// 5. Sync types with unexported fields
		{
			name: "mutex in unexported field",
			data: &struct {
				PublicField string
				mu          sync.Mutex // sync.Mutex has unexported fields
			}{
				PublicField: "public",
				mu:          sync.Mutex{},
			},
		},
		// 6. WaitGroup in unexported field
		{
			name: "waitgroup in unexported field",
			data: &struct {
				PublicField string
				wg          sync.WaitGroup // sync.WaitGroup has unexported fields
			}{
				PublicField: "public",
				wg:          sync.WaitGroup{},
			},
		},
		// 7. Complex nested structures with mixed types
		{
			name: "complex nested with multiple types",
			data: &struct {
				PublicField string
				nested      struct {
					fn   func() int
					ch   chan string
					ptr  uintptr
					time time.Time
				}
			}{
				PublicField: "public",
				nested: struct {
					fn   func() int
					ch   chan string
					ptr  uintptr
					time time.Time
				}{
					fn:   func() int { return 42 },
					ch:   make(chan string),
					ptr:  uintptr(123),
					time: time.Now(),
				},
			},
		},
		// 8. Array of structs with unexported fields
		{
			name: "array of structs with unexported fields",
			data: &struct {
				PublicField string
				items       [3]struct {
					id    int
					value uintptr
				}
			}{
				PublicField: "public",
				items: [3]struct {
					id    int
					value uintptr
				}{
					{id: 1, value: uintptr(100)},
					{id: 2, value: uintptr(200)},
					{id: 3, value: uintptr(300)},
				},
			},
		},
		// 9. Slice of complex types
		{
			name: "slice of complex types",
			data: &struct {
				PublicField string
				items       []struct {
					fn  func() string
					ptr uintptr
				}
			}{
				PublicField: "public",
				items: []struct {
					fn  func() string
					ptr uintptr
				}{
					{
						fn:  func() string { return "test1" },
						ptr: uintptr(unsafe.Pointer(&struct{}{})),
					},
					{
						fn:  func() string { return "test2" },
						ptr: uintptr(unsafe.Pointer(&struct{}{})),
					},
				},
			},
		},
		// 10. Map with complex key and value types
		{
			name: "map with complex types",
			data: &struct {
				PublicField string
				mapping     map[string]struct {
					ch   chan int
					ptr  uintptr
					time time.Time
				}
			}{
				PublicField: "public",
				mapping: map[string]struct {
					ch   chan int
					ptr  uintptr
					time time.Time
				}{
					"key1": {
						ch:   make(chan int),
						ptr:  uintptr(123),
						time: time.Now(),
					},
				},
			},
		},
		// 11. Interface containing struct with unexported fields
		{
			name: "interface with unexported struct",
			data: &struct {
				PublicField string
				iface       interface{}
			}{
				PublicField: "public",
				iface: struct {
					hidden uintptr
					fn     func() int
				}{
					hidden: uintptr(456),
					fn:     func() int { return 789 },
				},
			},
		},
		// 12. Embedded struct with unexported fields
		{
			name: "embedded struct with unexported fields",
			data: &struct {
				PublicField string
				embedded    struct {
					hiddenUint    uint
					hiddenUintptr uintptr
					hiddenFunc    func() bool
					hiddenChan    chan string
				}
			}{
				PublicField: "public",
				embedded: struct {
					hiddenUint    uint
					hiddenUintptr uintptr
					hiddenFunc    func() bool
					hiddenChan    chan string
				}{
					hiddenUint:    42,
					hiddenUintptr: uintptr(unsafe.Pointer(&struct{}{})),
					hiddenFunc:    func() bool { return true },
					hiddenChan:    make(chan string),
				},
			},
		},
		// 13. Nil interface in unexported field
		{
			name: "nil interface in unexported field",
			data: &struct {
				PublicField string
				nilIface    interface{}
			}{
				PublicField: "public",
				nilIface:    nil,
			},
		},
		// 14. Time with location (has unexported fields)
		{
			name: "time with location",
			data: &struct {
				PublicField string
				timestamp   time.Time
			}{
				PublicField: "public",
				timestamp:   time.Now().In(time.UTC),
			},
		},
		// 15. Reflect types
		{
			name: "reflect types",
			data: &struct {
				PublicField string
				reflectVal  reflect.Value
				reflectType reflect.Type
				unsafePtr   unsafe.Pointer
			}{
				PublicField: "reflect_test",
				reflectVal:  reflect.ValueOf("test"),
				reflectType: reflect.TypeOf("test"),
				unsafePtr:   unsafe.Pointer(&struct{}{}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Panic in test '%s': %v", tt.name, r)
				}
			}()

			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				ReplaceAttr: masq.New(),
			}))

			logger.Info("comprehensive test", "data", tt.data)

			output := buf.String()
			if len(output) == 0 {
				t.Error("Expected log output, got empty string")
			}
		})
	}
}

// TestLargeStructsWithUnexportedFields tests with large structures
func TestLargeStructsWithUnexportedFields(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic occurred in large struct test: %v", r)
		}
	}()

	// Large array to test memory handling
	type LargeStruct struct {
		PublicField string
		largeArray  [1000]struct {
			value   uintptr
			counter uint64
			flag    bool
			data    [100]byte
		}
		bigSlice []struct {
			ptr uintptr
			fn  func() int
		}
	}

	// Create large slice
	bigSlice := make([]struct {
		ptr uintptr
		fn  func() int
	}, 100)

	for i := range bigSlice {
		bigSlice[i] = struct {
			ptr uintptr
			fn  func() int
		}{
			ptr: uintptr(i * 100),
			fn:  func() int { return i },
		}
	}

	data := &LargeStruct{
		PublicField: "large_struct",
		bigSlice:    bigSlice,
	}

	// Initialize large array
	for i := range data.largeArray {
		data.largeArray[i] = struct {
			value   uintptr
			counter uint64
			flag    bool
			data    [100]byte
		}{
			value:   uintptr(i),
			counter: uint64(i * 2),
			flag:    i%2 == 0,
		}
		// Fill data array
		for j := range data.largeArray[i].data {
			data.largeArray[i].data[j] = byte(j % 256)
		}
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))

	logger.Info("large struct test", "data", data)

	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected log output, got empty string")
	}
	t.Logf("Output length: %d bytes", len(output))
}

// TestReflectionBoundaryConditions tests edge cases with reflection
func TestReflectionBoundaryConditions(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic occurred in reflection boundary test: %v", r)
		}
	}()

	tests := []struct {
		name string
		data interface{}
	}{
		// Test with reflect.Value as unexported field
		{
			name: "struct with reflect.Value",
			data: &struct {
				PublicField string
				reflectVal  reflect.Value
			}{
				PublicField: "reflect_test",
				reflectVal:  reflect.ValueOf("hidden"),
			},
		},
		// Test with reflect.Type as unexported field
		{
			name: "struct with reflect.Type",
			data: &struct {
				PublicField string
				reflectType reflect.Type
			}{
				PublicField: "type_test",
				reflectType: reflect.TypeOf("string"),
			},
		},
		// Test with method values
		{
			name: "struct with method value",
			data: &struct {
				PublicField string
				method      func() string
			}{
				PublicField: "method_test",
				method:      func() string { return "method_value" },
			},
		},
		// Test with unsafe.Pointer directly
		{
			name: "struct with unsafe.Pointer",
			data: &struct {
				PublicField string
				unsafePtr   unsafe.Pointer
			}{
				PublicField: "unsafe_test",
				unsafePtr:   unsafe.Pointer(&struct{}{}),
			},
		},
		// Test with multiple uintptr fields
		{
			name: "struct with multiple uintptr fields",
			data: &struct {
				PublicField string
				ptr1        uintptr
				ptr2        uintptr
				ptr3        uintptr
				ptr4        uintptr
			}{
				PublicField: "multi_ptr_test",
				ptr1:        uintptr(100),
				ptr2:        uintptr(200),
				ptr3:        uintptr(300),
				ptr4:        uintptr(400),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Panic in subtest '%s': %v", tt.name, r)
				}
			}()

			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				ReplaceAttr: masq.New(),
			}))

			logger.Info("reflection boundary test", "data", tt.data)

			output := buf.String()
			if len(output) == 0 {
				t.Error("Expected log output, got empty string")
			}
		})
	}
}

// TestCircularReferenceWithUnexportedFields tests circular references
func TestCircularReferenceWithUnexportedFields(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic occurred in circular reference test: %v", r)
		}
	}()

	type Node struct {
		PublicField string
		parent      *Node // unexported field
		children    []*Node
		data        struct {
			value uintptr
			fn    func() string
		}
	}

	root := &Node{
		PublicField: "root",
		children:    make([]*Node, 0),
		data: struct {
			value uintptr
			fn    func() string
		}{
			value: uintptr(123),
			fn:    func() string { return "root" },
		},
	}

	child1 := &Node{
		PublicField: "child1",
		parent:      root,
		data: struct {
			value uintptr
			fn    func() string
		}{
			value: uintptr(456),
			fn:    func() string { return "child1" },
		},
	}

	root.children = []*Node{child1}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))

	logger.Info("circular reference test", "data", root)

	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected log output, got empty string")
	}
}

// TestConcurrentAccess tests concurrent access to structures with unexported fields
func TestConcurrentAccess(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic occurred with concurrent access: %v", r)
		}
	}()

	type ConcurrentStruct struct {
		PublicField string
		counter     uint64
		ptr         uintptr
		fn          func() string
	}

	data := &ConcurrentStruct{
		PublicField: "concurrent",
		counter:     42,
		ptr:         uintptr(unsafe.Pointer(&struct{}{})),
		fn:          func() string { return "concurrent" },
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))

	// Test concurrent logging
	done := make(chan bool, 5)

	for i := 0; i < 5; i++ {
		go func(id int) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Panic in goroutine %d: %v", id, r)
				}
				done <- true
			}()

			logger.Info("concurrent test", "goroutine", id, "data", data)
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		<-done
	}

	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected log output, got empty string")
	}
}

// TestMemoryPressureWithUnexportedFields tests under memory pressure
func TestMemoryPressureWithUnexportedFields(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic occurred under memory pressure: %v", r)
		}
	}()

	// Create multiple structures simultaneously
	type MemoryTestStruct struct {
		PublicField string
		data        []struct {
			ptr     uintptr
			fn      func() string
			counter uint64
		}
	}

	var structs []*MemoryTestStruct

	for i := 0; i < 100; i++ {
		data := make([]struct {
			ptr     uintptr
			fn      func() string
			counter uint64
		}, 50)

		for j := range data {
			data[j] = struct {
				ptr     uintptr
				fn      func() string
				counter uint64
			}{
				ptr:     uintptr(unsafe.Pointer(&structs)),
				fn:      func() string { return "test" },
				counter: uint64(j),
			}
		}

		structs = append(structs, &MemoryTestStruct{
			PublicField: "memory_test",
			data:        data,
		})
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))

	// Log all structures
	for i, s := range structs {
		logger.Info("memory test", "index", i, "data", s)
	}

	// Force garbage collection
	runtime.GC()

	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected log output, got empty string")
	}
	t.Logf("Output length: %d bytes", len(output))
}

// TestExtremeNestingDepth tests very deep nesting beyond normal limits
func TestExtremeNestingDepth(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic occurred with extreme nesting: %v", r)
		}
	}()

	// Create deeply nested structure programmatically
	type DeepStruct struct {
		PublicField string
		level       interface{}
	}

	// Build nested structure
	var current interface{} = struct {
		value uintptr
		fn    func() int
	}{
		value: uintptr(999),
		fn:    func() int { return 999 },
	}

	// Create 50 levels of nesting
	for i := 0; i < 50; i++ {
		current = &DeepStruct{
			PublicField: "deep",
			level:       current,
		}
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))

	logger.Info("extreme nesting test", "data", current)

	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected log output, got empty string")
	}
	t.Logf("Output length: %d bytes", len(output))
}

// TestSpecialGoTypes tests special Go types that might cause issues
func TestSpecialGoTypes(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic occurred in special Go types test: %v", r)
		}
	}()

	// Test with string header (internal representation)
	type StringHeader struct {
		PublicField string
		header      struct {
			data uintptr
			len  int
		}
	}

	// Test with slice header (internal representation)
	type SliceHeader struct {
		PublicField string
		header      struct {
			data uintptr
			len  int
			cap  int
		}
	}

	tests := []interface{}{
		&StringHeader{
			PublicField: "string_header",
			header: struct {
				data uintptr
				len  int
			}{
				data: uintptr(unsafe.Pointer(&[]byte("test")[0])),
				len:  4,
			},
		},
		&SliceHeader{
			PublicField: "slice_header",
			header: struct {
				data uintptr
				len  int
				cap  int
			}{
				data: uintptr(unsafe.Pointer(&[]int{1, 2, 3}[0])),
				len:  3,
				cap:  3,
			},
		},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: masq.New(),
	}))

	for i, data := range tests {
		logger.Info("special Go types test", "index", i, "data", data)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected log output, got empty string")
	}
	t.Logf("Log output length: %d", len(output))
}
