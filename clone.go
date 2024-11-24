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

	if src.Kind() == reflect.Ptr && src.IsNil() {
		return reflect.New(src.Type()).Elem()
	}

	for _, filter := range x.filters {
		if filter.censor(fieldName, src.Interface(), tag) {
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
			println("f.Name", f.Name)
			srcValue := src.Field(i)
			dstValue := dst.Elem().Field(i)

			if !srcValue.CanInterface() {
				dstValue = reflect.NewAt(dstValue.Type(), unsafe.Pointer(dstValue.UnsafeAddr())).Elem()

				if !srcValue.CanAddr() {
					switch {
					case srcValue.CanInt():
						dstValue.SetInt(srcValue.Int())
					case srcValue.CanUint():
						dstValue.SetUint(srcValue.Uint())
					case srcValue.CanFloat():
						dstValue.SetFloat(srcValue.Float())
					case srcValue.CanComplex():
						dstValue.SetComplex(srcValue.Complex())
					case srcValue.Kind() == reflect.Bool:
						dstValue.SetBool(srcValue.Bool())
					}

					continue
				}

				srcValue = reflect.NewAt(srcValue.Type(), unsafe.Pointer(srcValue.UnsafeAddr())).Elem()
			} else if srcValue.Kind() == reflect.Func {
				println("func!")
				dstValue.Set(srcValue)
				continue
			}

			tagValue := f.Tag.Get(x.tagKey)
			copied := x.clone(ctx, f.Name, srcValue, tagValue)
			dstValue.Set(copied)
		}
		return dst.Elem()

	case reflect.Map:
		dst := reflect.MakeMap(src.Type())
		keys := src.MapKeys()
		for i := 0; i < src.Len(); i++ {
			mValue := src.MapIndex(keys[i])
			dst.SetMapIndex(keys[i], x.clone(ctx, keys[i].String(), mValue, ""))
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

		dst := reflect.New(src.Type()).Elem()
		for i := 0; i < src.Len(); i++ {
			dst.Index(i).Set(x.clone(ctx, fieldName, src.Index(i), ""))
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
