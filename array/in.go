package array

import (
	"reflect"
)

// In returns true when the first argument's value appears in the second
// argument's slice. Although the value of the slice and element can be
// dissimilar, it will always return false, so save your time and don't try
func In(item interface{}, slice interface{}) bool {
	if reflect.TypeOf(slice).Kind() != reflect.Slice {
		return false
	}

	sliceVal := reflect.ValueOf(slice)

	for i := 0; i < sliceVal.Len(); i++ {
		if reflect.DeepEqual(sliceVal.Index(i).Interface(), item) {
			return true
		}
	}

	return false
}
