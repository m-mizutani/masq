package masq

import (
	"reflect"
	"unsafe"
)

// extractValueSafely extracts interface{} value from reflect.Value even for unexported fields
// It returns the extracted value and a boolean indicating success
func extractValueSafely(v reflect.Value) (interface{}, bool) {
	if !v.IsValid() {
		return nil, false
	}

	// If the value can be interfaced normally, use that
	if v.CanInterface() {
		return v.Interface(), true
	}

	// For unexported fields, we need to use unsafe operations
	if !v.CanAddr() {
		return nil, false
	}

	// Use the generic reflect.NewAt approach for all types to preserve exact type information
	newVal := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	if newVal.CanInterface() {
		return newVal.Interface(), true
	}

	// Fallback to type-specific unsafe operations if the generic approach doesn't work
	switch v.Kind() {
	case reflect.String:
		return *(*string)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Bool:
		return *(*bool)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Int:
		return *(*int)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Int8:
		return *(*int8)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Int16:
		return *(*int16)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Int32:
		return *(*int32)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Int64:
		return *(*int64)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Uint:
		return *(*uint)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Uint8:
		return *(*uint8)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Uint16:
		return *(*uint16)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Uint32:
		return *(*uint32)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Uint64:
		return *(*uint64)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Float32:
		return *(*float32)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Float64:
		return *(*float64)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Complex64:
		return *(*complex64)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Complex128:
		return *(*complex128)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Interface:
		// For interface{} types, we can try to extract the underlying value
		if !v.IsNil() {
			return extractValueSafely(v.Elem())
		}
		return nil, true
	case reflect.Ptr:
		// For pointer types, return the pointer value itself
		return *(*unsafe.Pointer)(unsafe.Pointer(v.UnsafeAddr())), true
	case reflect.Slice:
		// For slice types, we can extract the slice header
		if v.IsNil() {
			return nil, true
		}
		// Create a new reflect.Value that can be interfaced
		sliceType := v.Type()
		newSlice := reflect.NewAt(sliceType, unsafe.Pointer(v.UnsafeAddr())).Elem()
		if newSlice.CanInterface() {
			return newSlice.Interface(), true
		}
		return nil, false
	case reflect.Map:
		// For map types, handle similar to slice
		if v.IsNil() {
			return nil, true
		}
		mapType := v.Type()
		newMap := reflect.NewAt(mapType, unsafe.Pointer(v.UnsafeAddr())).Elem()
		if newMap.CanInterface() {
			return newMap.Interface(), true
		}
		return nil, false
	case reflect.Struct:
		// For struct types, we cannot safely extract as interface{} without knowing the type
		// Return the reflect.Value itself wrapped in a way that can be used for type checking
		structType := v.Type()
		newStruct := reflect.NewAt(structType, unsafe.Pointer(v.UnsafeAddr())).Elem()
		if newStruct.CanInterface() {
			return newStruct.Interface(), true
		}
		return nil, false
	case reflect.Array:
		// For array types, similar approach to struct
		arrayType := v.Type()
		newArray := reflect.NewAt(arrayType, unsafe.Pointer(v.UnsafeAddr())).Elem()
		if newArray.CanInterface() {
			return newArray.Interface(), true
		}
		return nil, false
	}

	return nil, false
}
