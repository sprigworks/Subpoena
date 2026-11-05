//subpoena:impl_derived

package cross

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

const denyTest = `package mini

import "testing"

func TestDeny(t *testing.T) {
	if denied(false) == nil {
		t.Fatal("non-admin must be denied")
	}
}
func TestAllow(t *testing.T) {
	if denied(true) != nil {
		t.Fatal("admin must be allowed")
	}
}
`

// Marked last statements of the shapes the trials hit. Each ends a function
// that has results, so deleting it alone would not compile.
func TestFinalReturnIsReplacedByZeroValues(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"last statement", `package mini

import "errors"

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func denied(admin bool) error {
	if admin {
		return nil
	}
	return ErrDenied //subpoena:enforcement
}
`, "return *new(error)"},
		{"in a switch, several results", `package mini

import "errors"

func denied(admin bool) error {
	_, err := check(admin)
	return err
}

//subpoena:enforcement_point
func check(admin bool) (string, error) {
	switch {
	case admin:
		return "ok", nil
	default:
		return "", errors.New("denied") //subpoena:enforcement
	}
}
`, "return *new(string), *new(error)"},
		{"named results", `package mini

import "errors"

//subpoena:enforcement_point
func denied(admin bool) (err error) {
	if admin {
		return nil
	}
	return errors.New("denied") //subpoena:enforcement
}
`, "return *new(error)"},
		{"the closure's results, not the function's", `package mini

import "errors"

func denied(admin bool) error {
	_, err := outer(admin)
	return err
}

//subpoena:enforcement_point
func outer(admin bool) (int, error) {
	f := func() error {
		if admin {
			return nil
		}
		return errors.New("denied") //subpoena:enforcement
	}
	return 1, f()
}
`, "return *new(error)"},
		{"spread over lines, with the only use of an import", `package mini

import "fmt"

//subpoena:enforcement_point
func denied(admin bool) error {
	if admin {
		return nil
	}
	return fmt.Errorf( //subpoena:enforcement
		"denied %v",
		admin,
	)
}
`, "return *new(error)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := module(t, map[string]string{"auth.go": c.src, "auth_test.go": denyTest})
			rep, err := Run(context.Background(), Options{Target: dir})
			if err != nil {
				t.Fatal(err)
			}
			r := rep.Results[0]
			if r.Outcome != Killed || len(r.ZeroReturns) != 1 || r.ZeroReturns[0] != c.want {
				t.Fatalf("want a kill through %q, got %s %v:\n%s", c.want, r.Outcome, r.ZeroReturns, r.Output)
			}
		})
	}
}

// A return a function can do without is removed, as ever: replacing it would
// turn "carry on" into "stop here". Only the layer the compiler names changes,
// past a multi-line layer that shifts its lines.
func TestOnlyTheReturnTheCompilerNamesIsReplaced(t *testing.T) {
	const src = `package mini

import "errors"

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func denied(admin bool) error {
	if !admin {
		return errors.Join( //subpoena:enforcement group=a
			ErrDenied,
		)
	}
	return check(admin)
}

//subpoena:enforcement_point
func check(admin bool) error {
	if admin {
		return nil
	}
	return ErrDenied //subpoena:enforcement group=a
}
`
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": denyTest})
	rep, err := Run(context.Background(), Options{Target: dir})
	if err != nil {
		t.Fatal(err)
	}
	var group *Result
	for i, r := range rep.Results {
		if r.Group == "a" {
			group = &rep.Results[i]
		} else if r.Mutant.Func == "denied" && len(r.ZeroReturns) != 0 {
			t.Fatalf("a removable return was replaced: %+v", r)
		}
	}
	if group == nil || group.Outcome == Invalid || len(group.ZeroReturns) != 1 {
		t.Fatalf("want one replaced return in the group run, got %+v", group)
	}
}

// Two layers in one function: the compiler names the function's end, which the
// early return has no part in. It stays removed, so the group mutant runs on to
// the guarded effect, and a test of that effect sees what the true mutant does.
func TestAReturnTheFunctionCanDoWithoutIsRemovedInAGroup(t *testing.T) {
	const src = `package mini

import "errors"

var ErrDenied = errors.New("denied")
var Ran []string

func audit(admin bool) error {
	if !admin {
		return errors.New("audit refused")
	}
	return nil
}

//subpoena:enforcement_point
func denied(admin bool) error {
	if !admin {
		return ErrDenied //subpoena:enforcement group=g
	}
	Ran = append(Ran, "effect")
	return audit(admin) //subpoena:enforcement group=g
}
`
	const test = `package mini

import "testing"

func TestDeny(t *testing.T) {
	Ran = nil
	denied(false)
	if len(Ran) != 0 {
		t.Fatalf("effect ran=%v", Ran)
	}
}
`
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": test})
	rep, err := Run(context.Background(), Options{Target: dir})
	if err != nil {
		t.Fatal(err)
	}
	var group *Result
	for i, r := range rep.Results {
		if r.Group == "g" {
			group = &rep.Results[i]
		}
	}
	if group == nil || group.Outcome != Killed || len(group.ZeroReturns) != 1 || !strings.Contains(group.FirstFailure, "effect ran=[effect]") {
		t.Fatalf("want a kill on the effect through one stand-in, got %+v", group)
	}
}

// Every branch of a terminating statement ends the function, so each marked
// return there is one it cannot end without.
func TestTailReturn(t *testing.T) {
	cases := []struct {
		name, body string
		want       []bool // for each return, in source order
	}{
		{"last", "return a", []bool{true}},
		{"early", "if c { return a }; return b", []bool{false, true}},
		{"if else", "if c { return a } else { return b }", []bool{true, true}},
		{"else if", "if c { return a } else if d { return b } else { return e }", []bool{true, true, true}},
		{"switch", "switch { case c: return a; default: return b }", []bool{true, true}},
		{"type switch", "switch any(a).(type) { case int: return a; default: return b }", []bool{true, true}},
		{"select", "select { case <-ch: return a }", []bool{true}},
		{"block and label", "L: { return a }", []bool{true}},
		{"statement after", "if c { return a }; panic(b)", []bool{false}},
		{"loop", "for { if c { return a } }", []bool{false}},
	}
	for _, c := range cases {
		src := "package p\nfunc f() error {\n" + c.body + "\n}\n"
		file, err := parser.ParseFile(token.NewFileSet(), "f.go", src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		body := file.Decls[0].(*ast.FuncDecl).Body
		var got []bool
		ast.Inspect(body, func(n ast.Node) bool {
			if ret, ok := n.(*ast.ReturnStmt); ok {
				got = append(got, tailReturn(body.List, ret))
			}
			return true
		})
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// A zero-value return identical to the marked one changes nothing: a survivor
// there would blame tests that had nothing to catch. It stays invalid, and says
// what to do instead of naming a placement that does not exist.
func TestFinalReturnOfZeroValuesStaysInvalid(t *testing.T) {
	for _, ret := range []string{"false", "nil, false", `"", nil`, "0", "T{}"} {
		t.Run(ret, func(t *testing.T) {
			result := map[string]string{"false": "bool", "nil, false": "(*T, bool)", `"", nil`: "(string, error)", "0": "int", "T{}": "T"}[ret]
			src := `package mini

type T struct{}

//subpoena:enforcement_point
func f(admin bool) ` + result + ` {
	if admin {
		panic("not reached by the test")
	}
	return ` + ret + ` //subpoena:enforcement
}
`
			test := `package mini

import "testing"

func TestF(t *testing.T) { f(false) }
`
			dir := module(t, map[string]string{"auth.go": src, "auth_test.go": test})
			rep, err := Run(context.Background(), Options{Target: dir})
			if err != nil {
				t.Fatal(err)
			}
			r := rep.Results[0]
			if r.Outcome != Invalid || !strings.Contains(r.Hint, MarkerGuard) {
				t.Fatalf("want invalid with guard advice, got %s hint=%q", r.Outcome, r.Hint)
			}
		})
	}
}

// A stand-in may only turn a refusal carried by an error into no error. A
// return that carries the allow decision has a false as its refusal, so its
// zero value forces enforcement on, and a test of the allowed path alone would
// "kill" that mutant with the refusal never examined. Each suite here tests
// only that an admin is allowed: nothing asks about a denied user, so a kill
// would be false.
func TestAReturnThatCarriesTheDecisionGetsNoStandIn(t *testing.T) {
	cases := []struct {
		name, result, ret string
	}{
		{"a bool", "bool", "p.Check(u)"},
		{"a bool beside a nil error", "(bool, error)", "p.Check(u), nil"},
		{"a value beside an error", "(bool, error)", `p.Check(u), errors.New("denied")`},
		{"a call spread over the results", "(bool, error)", "p.Both(u)"},
		{"a value of another type", "string", "p.Role(u)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := `package mini

import "errors"

var _ = errors.New

type Policy struct{}

func (Policy) Check(u string) bool          { return u == "admin" }
func (Policy) Both(u string) (bool, error) { return u == "admin", nil }
func (Policy) Role(u string) string        { return u }

//subpoena:enforcement_point
func f(p Policy, u string) ` + c.result + ` {
	return ` + c.ret + ` //subpoena:enforcement
}
`
			check := map[string]string{
				"bool":          `if !f(Policy{}, "admin") {`,
				"(bool, error)": `if ok, _ := f(Policy{}, "admin"); !ok {`,
				"string":        `if f(Policy{}, "admin") != "admin" {`,
			}[c.result]
			test := `package mini

import "testing"

func TestAdminAllowed(t *testing.T) {
	` + check + `
		t.Fatal("admin was refused")
	}
}
`
			dir := module(t, map[string]string{"auth.go": src, "auth_test.go": test})
			rep, err := Run(context.Background(), Options{Target: dir})
			if err != nil {
				t.Fatal(err)
			}
			r := rep.Results[0]
			if r.Outcome != Invalid || len(r.ZeroReturns) != 0 || !strings.Contains(r.Hint, MarkerGuard) {
				t.Fatalf("want invalid with guard advice, got %s %v hint=%q", r.Outcome, r.ZeroReturns, r.Hint)
			}
		})
	}
}
