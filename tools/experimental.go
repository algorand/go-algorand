package main

// import (
// 	"fmt"
// 	"reflect"
// 	"regexp"
// 	"sort"
// 	"strings"
// 	"unicode"

// 	// thePkg "{{.ModulePath}}/{{.PackagePath}}"  					/* TEMPLATE ONLY  */
// 	thePkg "github.com/algorand/go-algorand/ledger/ledgercore" //   /* GENERATOR ONLY */
// )

// func _______main() { // replaced by main() in `make template4xrt`
// 	// t := reflect.TypeOf(thePkg.{{.TypeInstance}}{}) 			//	/* TEMPLATE ONLY  */
// 	t := reflect.TypeOf(thePkg.StateDelta{}) //						/* GENERATOR ONLY */
// 	// t := reflect.TypeOf(C{}) //						/* GENERATOR ONLY */
// 	instance := reflect.New(t).Elem().Interface()
// 	fmt.Printf("Walking type %T. Instance: %#v\n", instance, instance)

// 	leaves := make([]interface{}, 0)

// 	leafCollector := func(leaf interface{}) {
// 		leaves = append(leaves, leaf)
// 	}
// 	walk(instance, 0, leafCollector)

// 	fmt.Println("Leaves:")
// 	leavesReport(leaves)

// 	/*
// 		fmt.Println("\n\nBuild the Type Tree:")
// 		// val := reflect.Indirect(reflect.ValueOf(instance))
// 		// root := Type{Type: val.Type(), Kind: val.Kind()}
// 		root := Type{Type: t, Kind: t.Kind()}
// 		root.BuildTypeTree()
// 		root.Print()
// 	*/

// 	fmt.Println("\n\nBuild the Type Tree 2:")
// 	root := Type{Type: t, Kind: t.Kind()}
// 	root.BuildTypeTree2()
// 	root.Print()

// 	target := Target{Edge{Name: fmt.Sprintf("%T", instance)}, root}

// 	leaves2 := []Type{}
// 	leafCollector2 := func(tgt Target) {
// 		if tgt.Type.IsLeaf() {
// 			leaves2 = append(leaves2, tgt.Type)
// 		}
// 	}

// 	fmt.Println("\n\nCount the leaves:")
// 	target.Visit(leafCollector2)
// 	fmt.Printf("Found %d leaves\n", len(leaves2))

// 	stats := make(map[string]int)
// 	for _, leaf := range leaves2 {
// 		key := fmt.Sprintf("%s/%s", leaf.Type, leaf.Kind)
// 		if _, ok := stats[key]; !ok {
// 			stats[key] = 0
// 		}
// 		stats[key]++
// 	}

// 	printSortedStats2(stats)
// }

// type keyValue struct {
// 	Key   string
// 	Value int
// }

// func printSortedStats2(stats map[string]int) {
// 	// Create a slice of key-value pairs
// 	var kvSlice []keyValue
// 	for k, v := range stats {
// 		kvSlice = append(kvSlice, keyValue{k, v})
// 	}

// 	// Sort the slice by the count in descending order
// 	sort.Slice(kvSlice, func(i, j int) bool {
// 		return kvSlice[i].Value > kvSlice[j].Value
// 	})

// 	// Print the sorted slice
// 	for _, kv := range kvSlice {
// 		fmt.Printf("%s: %d\n", kv.Key, kv.Value)
// 	}
// }

// func walk(u interface{}, depth int, leafAction ...func(interface{})) {
// 	val := reflect.Indirect(reflect.ValueOf(u))
// 	t := val.Type()
// 	k := val.Kind()
// 	tabs := strings.Repeat("\t", depth+1)
// 	fmt.Printf("%s[depth=%d]. Value is type %q (%s)\n", tabs, depth, t, k)
// 	switch k {
// 	case reflect.Struct:
// 		for i := 0; i < t.NumField(); i++ {
// 			// Other fields to consider:
// 			// typeField.Anonymous -> might be useful for embedded structs
// 			// typeField.Index -> maybe this is the path to the field?
// 			// typeField.Tag -> Yep, we definitely need this
// 			// typeField.PkgPath -> can test if == "" to see if exported

// 			valField := val.Field(i)
// 			typeField := t.Field(i)
// 			if !unicode.IsUpper(rune(typeField.Name[0])) {
// 				continue
// 			}

// 			tabs := strings.Repeat("\t", depth+2)

// 			fmt.Printf("%sField %q is type %q (%s)\n", tabs, typeField.Name, typeField.Type, valField.Kind())
// 			fmt.Printf("%s###ADDITIONAL FIELD INFO: Tag=%s, Anonymous=%t, Index=%v\n", tabs, typeField.Tag, typeField.Anonymous, typeField.Index)
// 			walk(getZeroval(typeField.Type), depth+1, leafAction...)
// 		}
// 	case reflect.Slice, reflect.Array:
// 		tt := t.Elem()
// 		fmt.Printf("%sElements of type %q (%s)\n", tabs, tt, tt.Kind())
// 		walk(getZeroval(tt), depth+1, leafAction...)
// 	case reflect.Map:
// 		keyType, valueType := t.Key(), t.Elem()
// 		fmt.Printf("%sKeys are of type %q (%s) and values of type %q (%s)\n", tabs, keyType, keyType.Kind(), valueType, valueType.Kind())
// 		walk(getZeroval(keyType), depth+1, leafAction...)
// 		walk(getZeroval(valueType), depth+1, leafAction...)
// 	default:
// 		fmt.Printf("%s-------B I N G O: A LEAF---------->%q (%s)\n", tabs, t, k)
// 		if len(leafAction) > 0 {
// 			leafAction[0](fmt.Sprintf("%s/%s", t, k))
// 		}
// 	}
// }

// /*
// type A struct {
// 	X, Y int
// }

// type B struct {
// 	A
// 	Z float32
// }

// type C struct {
// 	A
// 	B
// 	B2 B
// }
// */

// func getZeroval(t reflect.Type) interface{} {
// 	if t.Kind() == reflect.Ptr {
// 		return reflect.New(t.Elem()).Elem().Interface()
// 	}
// 	return reflect.New(t).Elem().Interface()
// }

// func leavesReport(leaves []interface{}) {
// 	report := make(map[interface{}]int)
// 	for _, leaf := range leaves {
// 		if _, ok := report[leaf]; !ok {
// 			report[leaf] = 0
// 		}
// 		report[leaf] += 1
// 	}

// 	// Create a slice of struct containing leaf and its count
// 	type leafCount struct {
// 		leaf  interface{}
// 		count int
// 	}
// 	leafTotal := 0
// 	leafCounts := make([]leafCount, 0, len(report))
// 	for leaf, count := range report {
// 		leafCounts = append(leafCounts, leafCount{leaf, count})
// 		leafTotal += count
// 	}

// 	fmt.Printf("sorting...")
// 	// Sort the slice in descending order of count
// 	sort.Slice(leafCounts, func(i, j int) bool {
// 		return leafCounts[i].count > leafCounts[j].count
// 	})

// 	// Print the sorted slice one line per leaf
// 	for _, lc := range leafCounts {
// 		fmt.Printf("%s: %d\n", lc.leaf, lc.count)
// 	}
// 	fmt.Printf("Total leaves: %d\n", leafTotal)
// }

// /*** OOD ***/

// type Type struct {
// 	Depth    int
// 	Type     reflect.Type
// 	Kind     reflect.Kind
// 	Edges    []Edge
// 	children *Children
// }

// type Children map[string]Type

// type Edge struct {
// 	Name, Tag string
// }

// type Target struct {
// 	Edge
// 	Type Type
// }

// func (e Edge) String() string {
// 	return fmt.Sprintf("[%s](%s)", e.Name, e.Tag)
// }

// func EdgeFromLabel(s string) *Edge {
// 	re := regexp.MustCompile(`^\[(.+)\]\((.+)\)$`)
// 	matches := re.FindStringSubmatch(s)
// 	if len(matches) == 3 {
// 		return &Edge{Name: matches[1], Tag: matches[2]}
// 	}
// 	return nil
// }

// func (t *Type) Targets() []Target {
// 	targets := make([]Target, 0, len(t.Edges))
// 	for _, edge := range t.Edges {
// 		targets = append(targets, Target{edge, (*t.children)[edge.String()]})
// 	}
// 	return targets
// }

// func (t *Type) IsLeaf() bool {
// 	return t.children == nil
// }

// func (t *Type) BuildTypeTree2() {
// 	switch t.Kind {
// 	case reflect.Struct:
// 		t.buildStructChildren()
// 	case reflect.Slice, reflect.Array:
// 		t.buildListChild()
// 	case reflect.Map:
// 		t.buildMapChildren()
// 	case reflect.Ptr:
// 		t.buildPtrChild()
// 	}
// }

// func (t *Type) AppendChild(typeName, typeTag string, child Type) {
// 	edge := Edge{typeName, typeTag}
// 	t.Edges = append(t.Edges, edge)
// 	if t.children == nil {
// 		children := make(Children)
// 		t.children = &children
// 	}
// 	(*t.children)[edge.String()] = child
// }

// func (t *Type) buildStructChildren() {
// 	for i := 0; i < t.Type.NumField(); i++ {
// 		typeField := t.Type.Field(i)
// 		typeName := typeField.Name
// 		if typeName == "" || (!unicode.IsUpper(rune(typeName[0])) && typeName != "_struct") {
// 			continue
// 		}

// 		typeTag := string(typeField.Tag)
// 		child := Type{t.Depth + 1, typeField.Type, typeField.Type.Kind(), nil, nil}
// 		child.BuildTypeTree2()
// 		t.AppendChild(typeName, typeTag, child)
// 	}
// }

// func (t *Type) buildListChild() {
// 	tt := t.Type.Elem()
// 	child := Type{t.Depth + 1, tt, tt.Kind(), nil, nil}
// 	child.BuildTypeTree2()
// 	t.AppendChild("list element", "", child)
// }

// func (t *Type) buildMapChildren() {
// 	keyType, valueType := t.Type.Key(), t.Type.Elem()

// 	keyChild := Type{t.Depth + 1, keyType, keyType.Kind(), nil, nil}
// 	keyChild.BuildTypeTree2()
// 	t.AppendChild("map key", "", keyChild)

// 	valChild := Type{t.Depth + 1, valueType, valueType.Kind(), nil, nil}
// 	valChild.BuildTypeTree2()
// 	t.AppendChild("map value", "", valChild)
// }

// func (t *Type) buildPtrChild() {
// 	tt := t.Type.Elem()
// 	child := Type{t.Depth + 1, tt, tt.Kind(), nil, nil}
// 	child.BuildTypeTree2()
// 	t.AppendChild("ptr element", "", child)
// }

// func (tgt Target) Visit(actions ...func(Target)) {
// 	if len(actions) > 0 {
// 		for _, action := range actions {
// 			action(tgt)
// 		}
// 		for _, target := range tgt.Type.Targets() {
// 			target.Visit(actions...)
// 		}
// 	}
// }

// func (t *Type) Print() {
// 	tabs := strings.Repeat("\t", t.Depth)
// 	fmt.Printf("%s[depth=%d]. Value is type %q (%s)\n", tabs, t.Depth, t.Type, t.Kind)

// 	if t.IsLeaf() {
// 		fmt.Printf("%s-------B I N G O: A LEAF---------->%q (%s)\n", tabs, t.Type, t.Kind)
// 		return
// 	}

// 	for label, child := range *t.children {
// 		fmt.Printf("%s=====EDGE: %s=====>\n", tabs, label)
// 		child.Print()
// 	}

// }

// /*
// func (t *Type) BuildTypeTree() {
// 	t.Children = t.getChildren()

// 	if t.Children != nil {
// 		fmt.Printf("We have %d children at depth %d\n", len(*t.Children), t.Depth)
// 		for edge, child := range *t.Children {
// 			fmt.Printf("Edge: %s\n", edge)
// 			child.BuildTypeTree()
// 		}
// 		fmt.Printf("We STILL have %d children at depth %d\n", len(*t.Children), t.Depth)
// 	} else {
// 		fmt.Printf("Leaf: %s\n", t.Type)
// 	}
// }

// func (t *Type) getChildren() *Children {
// 	switch t.Kind {
// 	case reflect.Struct:
// 		return t.relevantChildrenOfStruct()
// 	case reflect.Slice, reflect.Array:
// 		return t.childOfList()
// 	case reflect.Map:
// 		return t.childrenOfMap()
// 	}
// 	return nil
// }

// func (t *Type) relevantChildrenOfStruct() *Children {
// 	children := make(Children)
// 	for i := 0; i < t.Type.NumField(); i++ {
// 		typeField := t.Type.Field(i)
// 		// valField :=
// 		typeName := typeField.Name
// 		if typeName == "" || (!unicode.IsUpper(rune(typeName[0])) && typeName != "_struct") {
// 			continue
// 		}

// 		typeTag := string(typeField.Tag)
// 		children[Edge{typeName, typeTag}.String()] = Type{t.Depth + 1, typeField.Type, typeField.Type.Kind(), nil}
// 	}
// 	return &children
// }

// func (t *Type) childOfList() *Children {
// 	tt := t.Type.Elem()
// 	return &Children{"list element": Type{t.Depth + 1, tt, tt.Kind(), nil}}
// }

// func (t *Type) childrenOfMap() *Children {
// 	keyType, valueType := t.Type.Key(), t.Type.Elem()
// 	return &Children{
// 		"map key":   Type{t.Depth + 1, keyType, keyType.Kind(), nil},
// 		"map value": Type{t.Depth + 1, valueType, valueType.Kind(), nil},
// 	}
// }
// */
