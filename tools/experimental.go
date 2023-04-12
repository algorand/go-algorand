package main

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode"

	// thePkg "{{.ModulePath}}/{{.PackagePath}}"  					/* TEMPLATE ONLY  */
	thePkg "github.com/algorand/go-algorand/ledger/ledgercore" //   /* GENERATOR ONLY */
)

func Main() { // replaced by main() in `make template4xrt`
	// t := reflect.TypeOf(thePkg.{{.TypeInstance}}{}) 			//	/* TEMPLATE ONLY  */
	t := reflect.TypeOf(thePkg.StateDelta{}) //						/* GENERATOR ONLY */
	instance := reflect.New(t).Elem().Interface()
	fmt.Printf("Walking type %T. Instance: %#v\n", instance, instance)

	leaves := make([]interface{}, 0)

	leafCollector := func(leaf interface{}) {
		leaves = append(leaves, leaf)
	}
	walk(instance, 0, leafCollector)

	fmt.Println("Leaves:")
	leavesReport(leaves)
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
}

func getZeroval(t reflect.Type) interface{} {
	if t.Kind() == reflect.Ptr {
		return reflect.New(t.Elem()).Elem().Interface()
	}
	return reflect.New(t).Elem().Interface()
}

func leavesReport(leaves []interface{}) {
	report := make(map[interface{}]int)
	for _, leaf := range leaves {
		if _, ok := report[leaf]; !ok {
			report[leaf] = 0
		}
		report[leaf] += 1
	}

	// Create a slice of struct containing leaf and its count
	type leafCount struct {
		leaf  interface{}
		count int
	}
	leafTotal := 0
	leafCounts := make([]leafCount, 0, len(report))
	for leaf, count := range report {
		leafCounts = append(leafCounts, leafCount{leaf, count})
		leafTotal += count
	}

	fmt.Printf("sorting...")
	// Sort the slice in descending order of count
	sort.Slice(leafCounts, func(i, j int) bool {
		return leafCounts[i].count > leafCounts[j].count
	})

	// Print the sorted slice one line per leaf
	for _, lc := range leafCounts {
		fmt.Printf("%s: %d\n", lc.leaf, lc.count)
	}
	fmt.Printf("Total leaves: %d\n", leafTotal)
}
