package main

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"github.com/algorand/go-algorand/ledger/ledgercore"
)

var leaves []interface{}

func main() {
	fmt.Printf("Hello, world: %#v\n", ledgercore.StateDelta{})

	fmt.Println("Walking ledgercore.StateDelta{}:")

	leaves = make([]interface{}, 0)
	walk(ledgercore.StateDelta{}, 0, leafCollector)

	fmt.Printf("\n\n\nLeaves: %#v\n", leaves)
}

func getZeroval(t reflect.Type) interface{} {
	if t.Kind() == reflect.Ptr {
		return reflect.New(t.Elem()).Elem().Interface()
	}
	return reflect.New(t).Elem().Interface()
}

func leafCollector(leaf interface{}) {
	leaves = append(leaves, leaf)
}

func walk(u interface{}, depth int, leafAction ...func(interface{})) {
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
			walk(getZeroval(fieldType), depth+1, leafAction...)
		}
	case reflect.Slice, reflect.Array:
		tt := t.Elem()
		fmt.Printf("%sElements of type %q (%s)\n", tabs, tt, tt.Kind())
		walk(getZeroval(tt), depth+1, leafAction...)
	case reflect.Map:
		keyType, valueType := t.Key(), t.Elem()
		fmt.Printf("%sKeys are of type %q (%s) and values of type %q (%s)\n", tabs, keyType, keyType.Kind(), valueType, valueType.Kind())
		walk(getZeroval(keyType), depth+1, leafAction...)
		walk(getZeroval(valueType), depth+1, leafAction...)
	default:
		fmt.Printf("%s-------B I N G O: A LEAF---------->%q (%s)\n", tabs, t, k)
		if len(leafAction) > 0 {
			leafAction[0](fmt.Sprintf("%s/%s", t, k))
		}
	}

	// if val.Kind() == reflect.Struct {
	// 	for i := 0; i < t.NumField(); i++ {
	// 		field := t.Field(i)

	// 		// Skip unexported fields
	// 		if !unicode.IsUpper(rune(field.Name[0])) {
	// 			continue
	// 		}

	// 		fieldVal := val.Field(i)
	// 		fieldType := field.Type
	// 		fieldKind := fieldVal.Kind()

	// 		tabs := strings.Repeat("\t", depth+2)
	// 		fmt.Printf("%sField %q is type %q (%s)\n",
	// 			tabs, field.Name, fieldType, fieldKind)

	// 		switch fieldKind {
	// 		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
	// 			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
	// 			reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
	// 			reflect.String:
	// 			// Handle basic types here if needed
	// 		case reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
	// 			// Handle other types if needed
	// 		case reflect.Ptr:
	// 			elemType := fieldType.Elem()
	// 			zeroValue := reflect.New(elemType).Elem().Interface()
	// 			if elemType.Kind() == reflect.Struct {
	// 				walk(zeroValue, depth+1)
	// 			}
	// 		case reflect.Struct:
	// 			walk(fieldVal.Interface(), depth+1)
	// 		case reflect.Slice, reflect.Array:
	// 			elemType := fieldType.Elem()
	// 			if elemType.Kind() == reflect.Struct {
	// 				zeroValue := reflect.New(elemType).Elem().Interface()
	// 				walk(zeroValue, depth+1)
	// 			}
	// 		default:
	// 			fmt.Printf("%sUnknown type\n", tabs)
	// 		}
	// }
	// }
}

// func walk(u interface{}, depth int) {
// 	val := reflect.Indirect(reflect.ValueOf(u))
// 	t := val.Type()
// 	tabs := strings.Repeat("\t", depth+1)
// 	fmt.Printf("%sValue is type %q (%s)\n", tabs, t, val.Kind())
// 	if val.Kind() == reflect.Struct {
// 		for i := 0; i < t.NumField(); i++ {
// 			field := t.Field(i)

// 			// Skip unexported fields
// 			if !unicode.IsUpper(rune(field.Name[0])) {
// 				continue
// 			}

// 			fieldVal := val.Field(i)
// 			fieldType := field.Type
// 			fieldKind := fieldVal.Kind()

// 			tabs := strings.Repeat("\t", depth+2)
// 			fmt.Printf("%sField %q is type %q (%s)\n",
// 				tabs, field.Name, fieldType, fieldKind)

// 			switch fieldKind {
// 			case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
// 				reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
// 				reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
// 				reflect.String:
// 				// Handle basic types here if needed
// 			case reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
// 				// Handle other types if needed
// 			case reflect.Ptr:
// 				elemType := fieldType.Elem()
// 				zeroValue := reflect.New(elemType).Elem().Interface()
// 				if elemType.Kind() == reflect.Struct {
// 					walk(zeroValue, depth+1)
// 				}
// 			case reflect.Struct:
// 				walk(fieldVal.Interface(), depth+1)
// 			case reflect.Slice, reflect.Array:
// 				elemType := fieldType.Elem()
// 				if elemType.Kind() == reflect.Struct {
// 					zeroValue := reflect.New(elemType).Elem().Interface()
// 					walk(zeroValue, depth+1)
// 				}
// 			default:
// 				fmt.Printf("%sUnknown type\n", tabs)
// 			}
// 		}
// 	}
// }

/*
func walk(u interface{}, depth int) {
	val := reflect.Indirect(reflect.ValueOf(u))
	t := val.Type()
	tabs := strings.Repeat("\t", depth+1)
	fmt.Printf("%sValue is type %q (%s)\n", tabs, t, val.Kind())
	if val.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)

			// Skip unexported fields
			if !unicode.IsUpper(rune(field.Name[0])) {
				continue
			}

			fieldVal := val.Field(i)

			for field.Type.Kind() == reflect.Ptr || field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Array {
				field.Type = field.Type.Elem()
			}

			tabs := strings.Repeat("\t", depth+2)
			fmt.Printf("%sField %q is type %q (%s)\n",
				tabs, field.Name, field.Type, fieldKind)

			switch fieldKind {
			case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
				reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
				reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
				reflect.String:
				// Handle basic types here if needed
			case reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
				// Handle other types if needed
			case reflect.Ptr:
				elemType := field.Type.Elem()
				zeroValue := reflect.New(elemType).Elem().Interface()
				if elemType.Kind() == reflect.Struct {
					walk(zeroValue, depth+1)
				}
			case reflect.Struct:
				walk(fieldVal.Interface(), depth+1)
			case reflect.Slice, reflect.Array:
				elemType := field.Type.Elem()
				if elemType.Kind() == reflect.Struct {
					zeroValue := reflect.New(elemType).Elem().Interface()
					walk(zeroValue, depth+1)
				}
			default:
				fmt.Printf("%sUnknown type\n", tabs)
			}
		}
	}
}
*/

/*
func walk(u interface{}, depth int) {
	val := reflect.Indirect(reflect.ValueOf(u))
	t := val.Type()
	tabs := strings.Repeat("\t", depth+1)
	fmt.Printf("%sValue is type %q (%s)\n", tabs, t, val.Kind())
	if val.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)

			// Skip unexported fields
			if !unicode.IsUpper(rune(field.Name[0])) {
				continue
			}

			fieldVal := reflect.Indirect(val.Field(i))

			tabs := strings.Repeat("\t", depth+2)
			fmt.Printf("%sField %q is type %q (%s)\n",
				tabs, field.Name, field.Type, fieldKind)

			switch fieldKind {
			case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
				reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
				reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
				reflect.String:
				// Handle basic types here if needed
			case reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
				// Handle other types if needed
			case reflect.Ptr:
				// Handle pointers if needed
			case reflect.Struct:
				walk(fieldVal.Interface(), depth+1)
			case reflect.Slice, reflect.Array:
				elemType := field.Type.Elem()
				if elemType.Kind() == reflect.Struct {
					zeroValue := reflect.New(elemType).Elem().Interface()
					walk(zeroValue, depth+1)
				}
			default:
				fmt.Printf("%sUnknown type\n", tabs)
			}
		}
	}
}
*/

/*
func walk(u interface{}, depth int) {
	val := reflect.Indirect(reflect.ValueOf(u))
	t := val.Type()
	tabs := strings.Repeat("\t", depth+1)
	fmt.Printf("%sValue is type %q (%s)\n", tabs, t, val.Kind())
	if val.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)

			// Skip unexported fields
			if !unicode.IsUpper(rune(field.Name[0])) {
				continue
			}
			fieldVal := reflect.Indirect(val.Field(i))

			tabs := strings.Repeat("\t", depth+2)
			fmt.Printf("%sField %q is type %q (%s)\n",
				tabs, field.Name, field.Type, fieldKind)

			if fieldKind == reflect.Struct {
				walk(fieldVal.Interface(), depth+1)
			} else if fieldKind == reflect.Slice {
				sliceType := field.Type.Elem()
				if sliceType.Kind() == reflect.Struct {
					zeroValue := reflect.New(sliceType).Elem().Interface()
					walk(zeroValue, depth+1)
				}
			}
		}
	}
}
*/
