package masq

import (
	"context"
	"reflect"
	"unicode"
	"unsafe"
)

type ctxKeyDepth struct{}

const (
	maxDepth = 32
)

var (
	// ignoreTypes is a map of types that should not be redacted. It lists types that can not be copied. For example, reflect.Type is a pointer to a struct and copying it causes panic. Especially, reflect.rtype is unexported type. Then, the ignoreTypes is list of string of type name.
	ignoreTypes = map[string]struct{}{
		"*reflect.rtype": {},
	}
)

// unsafeCopyValue performs unsafe memory copying between two reflect.Values
// This is used when normal reflection methods cannot be used due to unexported fields
func unsafeCopyValue(dst, src reflect.Value) {
	if !dst.CanAddr() || !src.CanAddr() {
		return
	}
	// Ensure types are compatible
	if dst.Type() != src.Type() {
		return
	}
	dstPtr := unsafe.Pointer(dst.UnsafeAddr())
	srcPtr := unsafe.Pointer(src.UnsafeAddr())
	size := src.Type().Size()
	copy((*[1 << 30]byte)(dstPtr)[:size], (*[1 << 30]byte)(srcPtr)[:size])
}

// safeCopyValue attempts to copy a value from src to dst using the most appropriate method
// It handles both addressable and non-addressable cases without silent data loss
func safeCopyValue(dst, src reflect.Value) bool {
	if !dst.IsValid() || !src.IsValid() {
		return false
	}

	// Ensure types are compatible
	if dst.Type() != src.Type() {
		return false
	}

	// If both can use normal Set, do that
	if dst.CanSet() && src.CanInterface() {
		dst.Set(src)
		return true
	}

	// If both are addressable, use unsafe copy
	if dst.CanAddr() && src.CanAddr() {
		unsafeCopyValue(dst, src)
		return true
	}

	// If src is not addressable but can be interfaced, make it addressable first
	if !src.CanAddr() && src.CanInterface() && dst.CanAddr() {
		// Create an addressable copy of src
		addrSrc := reflect.New(src.Type()).Elem()
		addrSrc.Set(src)
		// addrSrc should always be addressable, but check to be safe
		if addrSrc.CanAddr() {
			unsafeCopyValue(dst, addrSrc)
			return true
		}
		// This should never happen, but fallback to false
		return false
	}

	// If we can't copy the data, return false to indicate failure
	return false
}

func (x *masq) clone(ctx context.Context, fieldName string, src reflect.Value, tag string) reflect.Value {
	// Make the value addressable if it's not already
	// This is crucial for properly handling embedded unexported structs
	if !src.CanAddr() && src.IsValid() && src.CanInterface() {
		addressableValue := reflect.New(src.Type()).Elem()
		addressableValue.Set(src)
		src = addressableValue
	}

	if v, ok := ctx.Value(ctxKeyDepth{}).(int); !ok {
		ctx = context.WithValue(ctx, ctxKeyDepth{}, 0)
	} else {
		if v >= maxDepth {
			// Security: Return zero value instead of original to prevent redaction bypass
			return reflect.Zero(src.Type())
		}
		ctx = context.WithValue(ctx, ctxKeyDepth{}, v+1)

	}

	if _, ok := x.allowedTypes[src.Type()]; ok {
		return src
	}
	if _, ok := ignoreTypes[src.Type().String()]; ok {
		return src
	}

	if src.Kind() == reflect.Ptr && src.IsNil() {
		return reflect.Zero(src.Type())
	}

	for _, filter := range x.filters {
		// Check if we can get the interface value
		var srcInterface interface{}
		canInterface := src.CanInterface()
		if canInterface {
			srcInterface = src.Interface()
		}

		// Apply filter even for unexported fields if it's based on field name or tag
		if (canInterface && filter.censor(fieldName, srcInterface, tag)) ||
			(!canInterface && filter.censor(fieldName, nil, tag)) {
			dst := reflect.New(src.Type())

			if !filter.redactors.Redact(src, dst) {
				_ = x.defaultRedactor(src, dst)
			}

			if !dst.CanInterface() {
				return dst
			}
			return dst.Elem()
		}
	}

	switch src.Kind() {
	case reflect.String:
		dst := reflect.New(src.Type())
		dst.Elem().SetString(src.String())
		return dst.Elem()

	case reflect.Struct:
		dst := reflect.New(src.Type())
		t := src.Type()

		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			srcValue := src.Field(i)
			dstValue := dst.Elem().Field(i)

			if !srcValue.CanInterface() {
				// Handle unexported fields
				if srcValue.CanAddr() {
					// First check if this field should be filtered
					tagValue := f.Tag.Get(x.tagKey)
					shouldRedact := false
					for _, filter := range x.filters {
						// For unexported fields, we can only check by field name or tag
						if filter.censor(f.Name, nil, tagValue) {
							shouldRedact = true
							// Field should be redacted
							dst := reflect.New(srcValue.Type())
							if !filter.redactors.Redact(srcValue, dst) {
								_ = x.defaultRedactor(srcValue, dst)
							}
							// Copy the redacted value safely
							safeCopyValue(dstValue, dst.Elem())
							break
						}
					}

					if shouldRedact {
						continue
					}

					// If the source is addressable, we can use unsafe to copy the value
					srcPtr := unsafe.Pointer(srcValue.UnsafeAddr())
					dstPtr := unsafe.Pointer(dstValue.UnsafeAddr())

					// Copy the value based on its kind
					switch srcValue.Kind() {
					case reflect.String:
						*(*string)(dstPtr) = *(*string)(srcPtr)
					case reflect.Bool:
						*(*bool)(dstPtr) = *(*bool)(srcPtr)
					case reflect.Int:
						*(*int)(dstPtr) = *(*int)(srcPtr)
					case reflect.Int8:
						*(*int8)(dstPtr) = *(*int8)(srcPtr)
					case reflect.Int16:
						*(*int16)(dstPtr) = *(*int16)(srcPtr)
					case reflect.Int32:
						*(*int32)(dstPtr) = *(*int32)(srcPtr)
					case reflect.Int64:
						*(*int64)(dstPtr) = *(*int64)(srcPtr)
					case reflect.Uint:
						*(*uint)(dstPtr) = *(*uint)(srcPtr)
					case reflect.Uint8:
						*(*uint8)(dstPtr) = *(*uint8)(srcPtr)
					case reflect.Uint16:
						*(*uint16)(dstPtr) = *(*uint16)(srcPtr)
					case reflect.Uint32:
						*(*uint32)(dstPtr) = *(*uint32)(srcPtr)
					case reflect.Uint64:
						*(*uint64)(dstPtr) = *(*uint64)(srcPtr)
					case reflect.Float32:
						*(*float32)(dstPtr) = *(*float32)(srcPtr)
					case reflect.Float64:
						*(*float64)(dstPtr) = *(*float64)(srcPtr)
					case reflect.Complex64:
						*(*complex64)(dstPtr) = *(*complex64)(srcPtr)
					case reflect.Complex128:
						*(*complex128)(dstPtr) = *(*complex128)(srcPtr)
					case reflect.Map:
						// Maps need very special handling when they're unexported
						tagValue := f.Tag.Get(x.tagKey)
						copied := x.clone(ctx, f.Name, srcValue, tagValue)

						// For unexported fields containing maps, we need to use unsafe
						if copied.CanInterface() && dstValue.CanAddr() {
							dstValue = reflect.NewAt(dstValue.Type(), unsafe.Pointer(dstValue.UnsafeAddr())).Elem()
							if dstValue.CanSet() {
								dstValue.Set(copied)
							} else {
								// Use safeCopyValue for proper fallback handling
								safeCopyValue(dstValue, copied)
							}
						} else if dstValue.CanAddr() && copied.Kind() == reflect.Map {
							// For maps that can't be set normally, we copy the map reference
							dstPtr := unsafe.Pointer(dstValue.UnsafeAddr())
							if copied.IsNil() {
								// Set to nil map
								*(*unsafe.Pointer)(dstPtr) = nil
							} else if copied.CanAddr() {
								srcPtr := unsafe.Pointer(copied.UnsafeAddr())
								// Copy the map reference
								*(*unsafe.Pointer)(dstPtr) = *(*unsafe.Pointer)(srcPtr)
							}
						}
						continue
					case reflect.Slice, reflect.Ptr:
						// Slices and pointers need special handling when they're unexported
						// We need to clone and then set using reflection
						tagValue := f.Tag.Get(x.tagKey)
						copied := x.clone(ctx, f.Name, srcValue, tagValue)
						// Set the cloned value to the destination field
						dstValue = reflect.NewAt(dstValue.Type(), unsafe.Pointer(dstValue.UnsafeAddr())).Elem()
						// Check if the copied value is valid and can be set
						if dstValue.CanSet() && copied.IsValid() && copied.CanInterface() {
							dstValue.Set(copied)
						} else if copied.IsValid() && copied.CanAddr() && dstValue.CanAddr() {
							// Use unsafe operations for unexported fields or non-settable values
							unsafeCopyValue(dstValue, copied)
						}
						continue
					case reflect.Struct:
						// For struct types, recursively clone to apply filters
						tagValue := f.Tag.Get(x.tagKey)
						copied := x.clone(ctx, f.Name, srcValue, tagValue)
						// We need to use unsafe operations to set the value
						if copied.CanAddr() && dstValue.CanAddr() {
							unsafeCopyValue(dstValue, copied)
						}
						continue
					case reflect.Array, reflect.Interface:
						// For complex types, recursively clone
						tagValue := f.Tag.Get(x.tagKey)
						copied := x.clone(ctx, f.Name, srcValue, tagValue)
						// We need to use unsafe operations to set the value
						if copied.CanAddr() && dstValue.CanAddr() {
							unsafeCopyValue(dstValue, copied)
						}
						continue
					default:
						// For unsupported types, use safe copy to avoid panics with unexported fields
						safeCopyValue(dstValue, srcValue)
					}
				} else {
					// If not addressable, we need to handle it carefully
					// For unexported fields, we can't use Set methods directly
					// Skip this field as we can't access it safely
					continue
				}
				continue
			}

			tagValue := f.Tag.Get(x.tagKey)
			copied := x.clone(ctx, f.Name, srcValue, tagValue)

			// Check if we can set the value directly
			if dstValue.CanSet() && copied.CanInterface() {
				dstValue.Set(copied)
			} else if dstValue.CanAddr() {
				// For unexported fields, we need to use unsafe pointer operations
				// Try to copy directly to dstValue first
				safeCopyValue(dstValue, copied)
			}
		}

		return dst.Elem()

	case reflect.Map:
		// Create a completely new map
		mapType := src.Type()

		// Check if the map key type is unexported
		keyType := mapType.Key()
		isUnexportedKeyType := isUnexported(keyType)

		// Check if the map value type is unexported
		valueType := mapType.Elem()
		isUnexportedValueType := isUnexported(valueType)

		// Security: If map has unexported key or value type, return zero value
		// This prevents potential information leakage at the cost of losing the map content
		if isUnexportedKeyType || isUnexportedValueType {
			return reflect.Zero(src.Type())
		}

		// Security: If map cannot be interfaced, return zero value for safety
		if !src.CanInterface() {
			return reflect.Zero(src.Type())
		}

		dst := reflect.MakeMapWithSize(mapType, src.Len())

		// Get all keys
		keys := src.MapKeys()

		for _, key := range keys {
			value := src.MapIndex(key)

			// Clone the value
			clonedValue := x.clone(ctx, key.String(), value, "")

			// Set in the destination map
			dst.SetMapIndex(key, clonedValue)
		}
		return dst

	case reflect.Slice:
		dst := reflect.MakeSlice(src.Type(), src.Len(), src.Cap())
		for i := 0; i < src.Len(); i++ {
			cloned := x.clone(ctx, fieldName, src.Index(i), "")
			dstElem := dst.Index(i)
			if dstElem.CanSet() && cloned.IsValid() && cloned.CanInterface() {
				dstElem.Set(cloned)
			} else if cloned.IsValid() && dstElem.CanAddr() && cloned.CanAddr() {
				// Use unsafe operations for unexported elements or non-settable values
				unsafeCopyValue(dstElem, cloned)
			}
		}
		return dst

	case reflect.Array:
		// Security: Always create new instance even for empty arrays
		dst := reflect.New(src.Type()).Elem()

		if src.Len() == 0 {
			return dst // Return new empty array instance
		}

		// If the source can be set directly, use normal approach
		if dst.CanSet() && src.CanInterface() {
			for i := 0; i < src.Len(); i++ {
				cloned := x.clone(ctx, fieldName, src.Index(i), "")
				dstElem := dst.Index(i)
				if dstElem.CanSet() && cloned.IsValid() && cloned.CanInterface() {
					dstElem.Set(cloned)
				} else if cloned.IsValid() && dstElem.CanAddr() && cloned.CanAddr() {
					// Use unsafe operations for unexported elements or non-settable values
					unsafeCopyValue(dstElem, cloned)
				}
			}
			return dst
		}

		// For unexported arrays, we need to copy the entire array at once
		if src.CanAddr() && dst.CanAddr() {
			unsafeCopyValue(dst, src)

			// Now process each element for potential redaction
			for i := 0; i < dst.Len(); i++ {
				elemValue := dst.Index(i)
				clonedElem := x.clone(ctx, fieldName, elemValue, "")

				// The element in the array is not settable, so we must use unsafe to copy the cloned value back.
				if elemValue.CanAddr() {
					safeCopyValue(elemValue, clonedElem)
				}
			}
		}

		return dst

	case reflect.Ptr:
		dst := reflect.New(src.Elem().Type())
		copied := x.clone(ctx, fieldName, src.Elem(), tag)

		// Check if destination can be set and copied value is valid
		// We need to check if copied value came from an unexported field by checking CanInterface
		if dst.Elem().CanSet() && copied.IsValid() && copied.CanInterface() {
			dst.Elem().Set(copied)
		} else if copied.IsValid() && dst.Elem().CanAddr() {
			// For unexported types or non-settable values, use unsafe operations
			// Make sure we have an addressable copied value
			if copied.CanAddr() {
				unsafeCopyValue(dst.Elem(), copied)
			} else {
				// If copied is not addressable, we need to handle this carefully
				// to avoid silent data loss
				safeCopyValue(dst.Elem(), copied)
			}
		}
		return dst

	case reflect.Interface:
		if src.IsNil() {
			// Security: Return zero value for consistency
			return reflect.Zero(src.Type())
		}
		return x.clone(ctx, fieldName, src.Elem(), tag)

	default:
		dst := reflect.New(src.Type())
		safeCopyValue(dst.Elem(), src)
		return dst.Elem()
	}
}

// isUnexported checks if a type is truly unexported.
// Unlike checking PkgPath() != "", this function correctly identifies
// built-in types and exported user-defined types.
// For pointer types, it checks the underlying type for security purposes.
func isUnexported(t reflect.Type) bool {
	// For pointer types, check the underlying type
	if t.Kind() == reflect.Pointer {
		return isUnexported(t.Elem())
	}

	// Built-in types (like string, int, etc.) have empty PkgPath and are always exported
	if t.PkgPath() == "" {
		return false
	}

	name := t.Name()
	// For named types, an unexported name starts with a lowercase letter.
	return name != "" && unicode.IsLower(rune(name[0]))
}
