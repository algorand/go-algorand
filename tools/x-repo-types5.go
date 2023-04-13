package main

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"
	// thePkg "github.com/algorand/go-stateproof-verification/stateproof" /* DIFFERS FROM LIVE */
)

var leaves2 []interface{}

// func _main() {
// 	/* DIFFERS FROM LIVE BEGIN */
// 	t := reflect.TypeOf(thePkg.StateProof{})
// 	instance := reflect.New(t).Elem().Interface()
// 	fmt.Printf("Walking type %T. Instance: %#v\n", instance, instance)

// 	leaves2 := make([]interface{}, 0)
// 	walk2(instance, 0, func(leaf interface{}) {
// 		leaves2 = append(leaves2, leaf)
// 	})
// 	/* DIFFERS FROM LIVE END */

// 	fmt.Println("Leaves:")
// 	leavesReport2(leaves2)
// }

func leafCollector2(leaf interface{}) {
	leaves2 = append(leaves2, leaf)
}

func walk2(u interface{}, depth int, leafAction ...func(interface{})) {
	val := reflect.Indirect(reflect.ValueOf(u))
	t := val.Type()
	k := val.Kind()
	tabs := strings.Repeat("\t", depth+1)
	fmt.Printf("%sValue is type %q (%s)\n", tabs, t, k)
	switch k {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !unicode.IsUpper(rune(field.Name[0])) {
				continue
			}
			fieldVal := val.Field(i)
			fieldType := field.Type
			fieldKind := fieldVal.Kind()

			tabs := strings.Repeat("\t", depth+2)

			fmt.Printf("%sField %q is type %q (%s)\n", tabs, field.Name, fieldType, fieldKind)
			walk2(getZeroval2(fieldType), depth+1, leafAction...)
		}
	case reflect.Slice, reflect.Array:
		tt := t.Elem()
		fmt.Printf("%sElements of type %q (%s)\n", tabs, tt, tt.Kind())
		walk2(getZeroval2(tt), depth+1, leafAction...)
	case reflect.Map:
		keyType, valueType := t.Key(), t.Elem()
		fmt.Printf("%sKeys are of type %q (%s) and values of type %q (%s)\n", tabs, keyType, keyType.Kind(), valueType, valueType.Kind())
		walk2(getZeroval2(keyType), depth+1, leafAction...)
		walk2(getZeroval2(valueType), depth+1, leafAction...)
	default:
		fmt.Printf("%s-------B I N G O: A LEAF---------->%q (%s)\n", tabs, t, k)
		if len(leafAction) > 0 {
			leafAction[0](fmt.Sprintf("%s/%s", t, k))
		}
	}
}

func getZeroval2(t reflect.Type) interface{} {
	if t.Kind() == reflect.Ptr {
		return reflect.New(t.Elem()).Elem().Interface()
	}
	return reflect.New(t).Elem().Interface()
}

func leavesReport2(leaves []interface{}) {
	report := make(map[interface{}]int)
	for _, leaf := range leaves {
		if _, ok := report[leaf]; !ok {
			report[leaf] = 0
		}
		report[leaf] += 1
	}
	// Print the report one line per leaf
	for leaf, count := range report {
		fmt.Printf("%s: %d\n", leaf, count)
	}
}
