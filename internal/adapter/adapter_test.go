package adapter

import (
	"reflect"
	"testing"
)

type stub struct {
	name string
	typ  ImportType
}

func (s stub) Name() string     { return s.name }
func (s stub) Type() ImportType { return s.typ }
func (s stub) Command(src, out string, env map[string]string) ([]string, bool) {
	return []string{"true"}, false
}
func (s stub) SuccessExitCodes() []int { return []int{0} }

func TestRegistryGetAndSortedNames(t *testing.T) {
	Register(stub{"zz-test", TypeSAST})
	Register(stub{"aa-test", TypeSecret})
	a, ok := Get("zz-test")
	if !ok || a.Name() != "zz-test" || a.Type() != TypeSAST {
		t.Fatalf("Get(zz-test) = %v, %v", a, ok)
	}
	if _, ok := Get("missing"); ok {
		t.Fatal("Get(missing) found an adapter")
	}
	names := Names()
	var ours []string
	for _, n := range names {
		if n == "aa-test" || n == "zz-test" {
			ours = append(ours, n)
		}
	}
	if !reflect.DeepEqual(ours, []string{"aa-test", "zz-test"}) {
		t.Fatalf("Names() = %v, not sorted", names)
	}
}

func TestRegisterRefusesDuplicatesEmptyNamesAndUnknownTypes(t *testing.T) {
	Register(stub{"dup-test", TypeIaC})
	for name, a := range map[string]Adapter{
		"duplicate":    stub{"dup-test", TypeIaC},
		"empty name":   stub{"", TypeIaC},
		"unknown type": stub{"bad-type-test", ImportType("dast")},
		"nil":          nil,
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: Register did not panic", name)
				}
			}()
			Register(a)
		}()
	}
}

func TestImportTypesAreTheContractsSix(t *testing.T) {
	got := []ImportType{TypeSAST, TypeIaC, TypeSecret, TypeCICD, TypeSCA, TypeContainer}
	want := []ImportType{"sast", "iac", "secret", "cicd", "sca", "container"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("types = %v", got)
	}
	for _, ty := range want {
		if !ty.Valid() {
			t.Errorf("%s is not valid", ty)
		}
	}
	if ImportType("dast").Valid() {
		t.Error("dast is valid")
	}
}
