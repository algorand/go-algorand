package parse

import (
	"testing"

	"github.com/algorand/msgp/gen"
)

const (
	testStructName = "TestStruct"
	testFuncName   = "callback"
)

func TestPostunmarshalcheck(t *testing.T) {
	st := gen.Struct{
		Fields:  nil,
		AsTuple: false,
	}

	fl := FileSet{
		Identities: map[string]gen.Elem{testStructName: &st},
		Directives: []string{"postunmarshalcheck"}, // raw preprocessor directives
	}
	if err := postunmarshalcheck([]string{"postunmarshalcheck", testStructName, testFuncName}, &fl); err != nil {
		t.Fatal()
	}
	if testFuncName != st.GetCallbacks()[0].GetName() {
		t.Fatal()
	}
	if !st.GetCallbacks()[0].IsUnmarshallCallback() {
		t.Fatal()
	}
}

func TestPostunmarshalcheckFailures(t *testing.T) {

	st := gen.Struct{
		Fields:  nil,
		AsTuple: false,
	}

	fl := FileSet{
		Identities: map[string]gen.Elem{testStructName: &st},
		Directives: []string{"postunmarshalcheck"}, // raw preprocessor directives
	}
	if err := postunmarshalcheck([]string{"postunmarshalcheck", testFuncName}, &fl); err == nil {
		t.Fatal()
	}

	if err := postunmarshalcheck([]string{"postunmarshalcheck", "non-existing-type", testFuncName}, &fl); err == nil {
		t.Fatal()
	}
}
