package masq

import (
	"reflect"
	"unsafe"
)

func (x *masq) clone(fieldName string, value reflect.Value, tag string) reflect.Value {
	if _, ok := x.allowedTypes[value.Type()]; ok {
		return value
	}

	adjustValue := func(ret reflect.Value) reflect.Value {
		switch value.Kind() {
		case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Array:
			return ret
		default:
			return ret.Elem()
		}
	}

	src := value
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return reflect.New(value.Type()).Elem()
		}
		src = value.Elem()
	}

	var dst reflect.Value
	if x.filters.ShouldRedact(fieldName, src.Interface(), tag) {
		dst = reflect.New(src.Type())
		switch src.Kind() {
		case reflect.String:
			dst.Elem().SetString(x.RedactMessage)
		case reflect.Array, reflect.Slice, reflect.Map:
			dst = dst.Elem()
		}
		return adjustValue(dst)
	}

	switch src.Kind() {
	case reflect.String:
		dst = reflect.New(src.Type())
		filtered := x.filters.ReplaceString(value.String())
		dst.Elem().SetString(filtered)

	case reflect.Struct:
		dst = reflect.New(src.Type())
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

			dstValue.Set(x.clone(f.Name, srcValue, f.Tag.Get("masq")))
		}

	case reflect.Map:
		dst = reflect.MakeMap(src.Type())
		keys := src.MapKeys()
		for i := 0; i < src.Len(); i++ {
			mValue := src.MapIndex(keys[i])
			dst.SetMapIndex(keys[i], x.clone(keys[i].String(), mValue, ""))
		}

	case reflect.Slice:
		dst = reflect.MakeSlice(src.Type(), src.Len(), src.Cap())
		for i := 0; i < src.Len(); i++ {
			dst.Index(i).Set(x.clone(fieldName, src.Index(i), ""))
		}

	case reflect.Array:
		if src.Len() == 0 {
			return src // can not access to src.Index(0)
		}

		arrType := reflect.ArrayOf(src.Len(), src.Index(0).Type())
		dst = reflect.New(arrType).Elem()
		for i := 0; i < src.Len(); i++ {
			dst.Index(i).Set(x.clone(fieldName, src.Index(i), ""))
		}

	default:
		dst = reflect.New(src.Type())
		dst.Elem().Set(src)
	}

	return adjustValue(dst)
}
