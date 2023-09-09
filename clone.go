package masq

import (
	"reflect"
	"unsafe"
)

func (x *masq) clone(fieldName string, src reflect.Value, tag string) reflect.Value {
	if _, ok := x.allowedTypes[src.Type()]; ok {
		return src
	}

	if src.Kind() == reflect.Ptr && src.IsNil() {
		return reflect.New(src.Type()).Elem()
	}

	if x.censors.ShouldRedact(fieldName, src.Interface(), tag) {
		dst := reflect.New(src.Type())
		switch src.Kind() {
		case reflect.String:
			dst.Elem().SetString(x.redactMessage)
		}

		if !dst.CanInterface() {
			return dst
		}
		return dst.Elem()
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
				if !srcValue.CanAddr() {
					continue
				}

				srcValue = reflect.NewAt(srcValue.Type(), unsafe.Pointer(srcValue.UnsafeAddr())).Elem()
				dstValue = reflect.NewAt(dstValue.Type(), unsafe.Pointer(dstValue.UnsafeAddr())).Elem()
			}

			tagValue := f.Tag.Get("masq")
			copied := x.clone(f.Name, srcValue, tagValue)
			dstValue.Set(copied)
		}
		return dst.Elem()

	case reflect.Map:
		dst := reflect.MakeMap(src.Type())
		keys := src.MapKeys()
		for i := 0; i < src.Len(); i++ {
			mValue := src.MapIndex(keys[i])
			dst.SetMapIndex(keys[i], x.clone(keys[i].String(), mValue, ""))
		}
		return dst

	case reflect.Slice:
		dst := reflect.MakeSlice(src.Type(), src.Len(), src.Cap())
		for i := 0; i < src.Len(); i++ {
			dst.Index(i).Set(x.clone(fieldName, src.Index(i), ""))
		}
		return dst

	case reflect.Array:
		if src.Len() == 0 {
			return src // can not access to src.Index(0)
		}

		arrType := reflect.ArrayOf(src.Len(), src.Index(0).Type())
		dst := reflect.New(arrType).Elem()
		for i := 0; i < src.Len(); i++ {
			dst.Index(i).Set(x.clone(fieldName, src.Index(i), ""))
		}
		return dst

	case reflect.Ptr:
		dst := reflect.New(src.Elem().Type())
		copied := x.clone(fieldName, src.Elem(), tag)
		dst.Elem().Set(copied)
		return dst

	default:
		dst := reflect.New(src.Type())
		dst.Elem().Set(src)
		return dst.Elem()
	}
}
