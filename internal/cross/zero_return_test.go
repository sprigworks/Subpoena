//subpoena:impl_derived

package cross

import (
	"context"
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
