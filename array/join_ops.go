package array

import (
	"reflect"
)

// getABValType is a helper that saves LOCs
func getABValType(a, b interface{}) (reflect.Value, reflect.Type, reflect.Value, reflect.Type) {
	aVal := reflect.ValueOf(a)
	aType := aVal.Type()
	bVal := reflect.ValueOf(b)
	bType := bVal.Type()
	return aVal, aType, bVal, bType
}

// requires a to be of type reflect.Slice
func makeSliceMapInterface(a reflect.Value) reflect.Value {
	sliceLen := a.Len()
	itemMapT := reflect.MapOf(a.Type().Elem(), reflect.TypeOf(1))
	itemMap := reflect.MakeMapWithSize(itemMapT, sliceLen)
	for i := 0; i < sliceLen; i++ {
		itemMap.SetMapIndex(a.Index(i), reflect.ValueOf(1))
	}

	return itemMap
}

// Intersection takes two array/slices and finds the common values between the
// two arrays. The returned type will be of the first variable, and is
// gaurenteed to return no values if the two arrays have a dissimilar type.
//
// TODO(t94j0) Make equivalence of MapIndex() to invalid value better
func Intersection(a, b interface{}) interface{} {
	aVal, aType, bVal, bType := getABValType(a, b)

	if aType.Kind() != reflect.Slice || bType.Kind() != reflect.Slice {
		return reflect.Zero(aType)
	}

	bMap := makeSliceMapInterface(bVal)
	newSlice := reflect.MakeSlice(aType, 0, 0)

	for i := 0; i < aVal.Len(); i++ {
		sliceItem := aVal.Index(i)
		if bMap.MapIndex(sliceItem).Kind().String() != reflect.Invalid.String() {
			newSlice = reflect.Append(newSlice, sliceItem)
		}
	}

	return newSlice.Interface()
}

// Except takes two array/slices and finds values that are only in the first
// slice.
func Except(a, b interface{}) interface{} {
	aVal, aType, bVal, bType := getABValType(a, b)

	if aType.Kind() != reflect.Slice || bType.Kind() != reflect.Slice {
		return reflect.Zero(aType)
	}

	bMap := makeSliceMapInterface(bVal)
	newSlice := reflect.MakeSlice(aType, 0, 0)

	for i := 0; i < aVal.Len(); i++ {
		sliceItem := aVal.Index(i)
		if bMap.MapIndex(sliceItem).Kind().String() == reflect.Invalid.String() {
			newSlice = reflect.Append(newSlice, sliceItem)
		}
	}

	return newSlice.Interface()
}
