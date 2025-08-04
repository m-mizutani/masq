package masq

import (
	"context"
	"reflect"
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

func (x *masq) clone(ctx context.Context, fieldName string, src reflect.Value, tag string) reflect.Value {
	if v, ok := ctx.Value(ctxKeyDepth{}).(int); !ok {
		ctx = context.WithValue(ctx, ctxKeyDepth{}, 0)
	} else {
		if v >= maxDepth {
			return src
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
		return reflect.New(src.Type()).Elem()
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
							// Copy the redacted value using unsafe
							srcPtr := unsafe.Pointer(dst.Elem().UnsafeAddr())
							dstPtr := unsafe.Pointer(dstValue.UnsafeAddr())
							size := dst.Elem().Type().Size()
							copy((*[1 << 30]byte)(dstPtr)[:size], (*[1 << 30]byte)(srcPtr)[:size])
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
							dstValue.Set(copied)
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
						dstValue.Set(copied)
						continue
					case reflect.Struct:
						// For struct types, recursively clone to apply filters
						tagValue := f.Tag.Get(x.tagKey)
						copied := x.clone(ctx, f.Name, srcValue, tagValue)
						// We need to use unsafe operations to set the value
						if copied.CanAddr() && dstValue.CanAddr() {
							dstPtr := unsafe.Pointer(dstValue.UnsafeAddr())
							srcPtr := unsafe.Pointer(copied.UnsafeAddr())
							size := copied.Type().Size()
							copy((*[1 << 30]byte)(dstPtr)[:size], (*[1 << 30]byte)(srcPtr)[:size])
						}
						continue
					case reflect.Array, reflect.Interface:
						// For complex types, recursively clone
						tagValue := f.Tag.Get(x.tagKey)
						copied := x.clone(ctx, f.Name, srcValue, tagValue)
						// We need to use unsafe operations to set the value
						if copied.CanAddr() && dstValue.CanAddr() {
							dstPtr := unsafe.Pointer(dstValue.UnsafeAddr())
							srcPtr := unsafe.Pointer(copied.UnsafeAddr())
							size := copied.Type().Size()
							copy((*[1 << 30]byte)(dstPtr)[:size], (*[1 << 30]byte)(srcPtr)[:size])
						}
						continue
					default:
						// For unsupported types, try to use reflection methods
						if srcValue.CanInt() {
							dstValue.SetInt(srcValue.Int())
						} else if srcValue.CanUint() {
							dstValue.SetUint(srcValue.Uint())
						} else if srcValue.CanFloat() {
							dstValue.SetFloat(srcValue.Float())
						} else if srcValue.CanComplex() {
							dstValue.SetComplex(srcValue.Complex())
						}
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
			if dstValue.CanSet() {
				dstValue.Set(copied)
			} else if dstValue.CanAddr() {
				// For unexported fields, we need to use unsafe pointer operations
				// First, we need to make the copied value addressable if it isn't
				var addrCopied reflect.Value
				if copied.CanAddr() {
					addrCopied = copied
				} else {
					// Create a new addressable value
					newVal := reflect.New(copied.Type())
					newVal.Elem().Set(copied)
					addrCopied = newVal.Elem()
				}

				dstPtr := unsafe.Pointer(dstValue.UnsafeAddr())
				srcPtr := unsafe.Pointer(addrCopied.UnsafeAddr())
				size := copied.Type().Size()
				copy((*[1 << 30]byte)(dstPtr)[:size], (*[1 << 30]byte)(srcPtr)[:size])
			}
		}

		return dst.Elem()

	case reflect.Map:
		// Create a completely new map
		mapType := src.Type()

		// Check if the map key type is unexported
		keyType := mapType.Key()
		isUnexportedKeyType := keyType.PkgPath() != ""

		// Check if the map value type is unexported
		valueType := mapType.Elem()
		isUnexportedValueType := valueType.PkgPath() != ""

		// If map has unexported key or value type, return the original map
		// This is a limitation due to Go's reflection API
		if isUnexportedKeyType || isUnexportedValueType {
			return src
		}

		// Check if we're in an unexported context by checking if we can create values
		// This happens when the map is inside an unexported struct field
		if !src.CanInterface() {
			return src
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
			dst.Index(i).Set(x.clone(ctx, fieldName, src.Index(i), ""))
		}
		return dst

	case reflect.Array:
		if src.Len() == 0 {
			return src // can not access to src.Index(0)
		}

		// For arrays, we need to create an addressable copy to work with
		dst := reflect.New(src.Type()).Elem()

		// If the source can be set directly, use normal approach
		if dst.CanSet() && src.CanInterface() {
			for i := 0; i < src.Len(); i++ {
				cloned := x.clone(ctx, fieldName, src.Index(i), "")
				dst.Index(i).Set(cloned)
			}
			return dst
		}

		// For unexported arrays, we need to copy the entire array at once
		if src.CanAddr() && dst.CanAddr() {
			srcPtr := unsafe.Pointer(src.UnsafeAddr())
			dstPtr := unsafe.Pointer(dst.UnsafeAddr())
			size := src.Type().Size()
			copy((*[1 << 30]byte)(dstPtr)[:size], (*[1 << 30]byte)(srcPtr)[:size])

			// Now process each element for potential redaction
			for i := 0; i < dst.Len(); i++ {
				elemValue := dst.Index(i)
				clonedElem := x.clone(ctx, fieldName, elemValue, "")

				// The element in the array is not settable, so we must use unsafe to copy the cloned value back.
				if elemValue.CanAddr() {
					var addrCopied reflect.Value
					if clonedElem.CanAddr() {
						addrCopied = clonedElem
					} else {
						// If the cloned value is not addressable, create a new addressable value and copy into it.
						newVal := reflect.New(clonedElem.Type())
						newVal.Elem().Set(clonedElem)
						addrCopied = newVal.Elem()
					}

					dstPtr := unsafe.Pointer(elemValue.UnsafeAddr())
					srcPtr := unsafe.Pointer(addrCopied.UnsafeAddr())
					size := clonedElem.Type().Size()
					copy((*[1 << 30]byte)(dstPtr)[:size], (*[1 << 30]byte)(srcPtr)[:size])
				}
			}
		}

		return dst

	case reflect.Ptr:
		dst := reflect.New(src.Elem().Type())
		copied := x.clone(ctx, fieldName, src.Elem(), tag)
		dst.Elem().Set(copied)
		return dst

	case reflect.Interface:
		if src.IsNil() {
			return src
		}
		return x.clone(ctx, fieldName, src.Elem(), tag)

	default:
		dst := reflect.New(src.Type())
		dst.Elem().Set(src)
		return dst.Elem()
	}
}
