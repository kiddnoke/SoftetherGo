package softetherApi

import (
	"reflect"
	"strconv"
)

func booltoint8(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}
func intToString(input []int) []interface{} {
	var output []interface{}
	for _, i := range input {
		output = append(output, strconv.Itoa(i))
	}
	return output
}
func getListType(list []interface{}) {
	first := list[0]
	reflect.TypeOf(first)
}
