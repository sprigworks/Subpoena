//subpoena:impl_derived

package cross

import (
	"strconv"
	"strings"
	"testing"
)

// goesAgain is what the log says when a green run goes again without -test.failfast.
const goesAgain = "running without -test.failfast"

// quietMain throws a first m.Run's output away, then calls m.Run again.
const quietMain = `func TestMain(m *testing.M) {
	out := os.Stdout
	os.Stdout, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	m.Run()
	os.Stdout = out
	os.Exit(m.Run())
}
`

// lookOnly runs the mutated line and looks at nothing: the mutant survives.
const lookOnly = `func TestLooks(t *testing.T) { _ = Check("mallory") }
`

// Review 13, H3. A green run in which the tests ran goes no further, so a flake in
// the two runs after it has no way to read as a kill. nth 1 is the baseline, 2 the
// mutant's run. An extra run would be 3, and its repeat 4.
func TestAGreenRunWhoseTestsRanGoesNoFurther(t *testing.T) {
	t.Parallel()
	var log strings.Builder
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import "testing"

` + lookOnly + `func TestUpstream(t *testing.T) { if nth == 3 || nth == 4 { t.Fatal("upstream returned 503") } }
`})
	if r := killOf(t, Options{Target: dir, Log: &log}); r.Outcome != Survived {
		t.Fatalf("got %+v", r)
	}
	if strings.Contains(log.String(), goesAgain) {
		t.Fatalf("a survivor went again:\n%s", log.String())
	}
}

// A package that ran nothing because it has nothing to run reads, in a mutant's run,
// the same as one a quiet m.Run left empty. The baseline tells them apart.
func TestAPackageWithNoTestsDoesNotLookQuiet(t *testing.T) {
	t.Parallel()
	for name, extra := range map[string]map[string]string{
		"no test files": {"other/o.go": "package other\n"},
		"helpers only": {"other/o.go": "package other\n",
			"other/o_test.go": "package other\n\nfunc helper() int { return 1 }\n"},
		"benchmarks only": {"other/o.go": "package other\n",
			"other/o_test.go": "package other\n\nimport \"testing\"\n\nfunc BenchmarkA(b *testing.B) {}\n"},
		"TestMain only": {"other/o.go": "package other\n",
			"other/o_test.go": "package other\n\nimport (\"os\"; \"testing\")\n\nfunc TestMain(m *testing.M) { os.Exit(m.Run()) }\n"},
		"examples only": {"other/o.go": "package other\n",
			"other/o_test.go": "package other\n\nimport \"fmt\"\n\nfunc Example() {\n\tfmt.Println(1)\n\t// Output: 1\n}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var log strings.Builder
			files := map[string]string{"gate.go": gate3, "gate_test.go": "package mini\n\nimport \"testing\"\n\n" + lookOnly}
			for k, v := range extra {
				files[k] = v
			}
			if r := killOf(t, Options{Target: module(t, files), Log: &log}); r.Outcome != Survived {
				t.Fatalf("got %+v", r)
			}
			if strings.Contains(log.String(), goesAgain) {
				t.Fatalf("a survivor went again:\n%s", log.String())
			}
		})
	}
}

// What the signature has to see. Package testing runs Examples under -test.failfast
// after a failure, so a second m.Run can show run events with no Test among them.
// Fuzz seeds stop as Tests do. A quiet package beside one that ran is still quiet.
func TestAQuietPackageIsSeenWhatEverRanBesideIt(t *testing.T) {
	t.Parallel()
	const refused = `func TestRefused(t *testing.T) { if Check("mallory") == nil { t.Fatal("mallory let in") } }
`
	head := "package mini\n\nimport (\"fmt\"; \"os\"; \"testing\")\n\nvar _ = fmt.Sprint\n\n"
	for name, files := range map[string]map[string]string{
		"an Example":  {"gate_test.go": head + refused + quietMain + "func Example() {\n\tfmt.Println(1)\n\t// Output: 1\n}\n"},
		"a Fuzz seed": {"gate_test.go": head + refused + quietMain + "func FuzzA(f *testing.F) { f.Add(1); f.Fuzz(func(t *testing.T, i int) {}) }\n"},
		"another package": {"gate_test.go": head + refused + quietMain,
			"other/o.go":      "package other\n",
			"other/o_test.go": "package other\n\nimport \"testing\"\n\nfunc TestFine(t *testing.T) {}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			files["gate.go"] = gate3
			if r := killOf(t, Options{Target: module(t, files)}); r.Outcome != Killed {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

// Under -select a package with no selected test ran none, and reads as quiet. The
// selected run does not go again for it, and the whole-suite run that follows every
// mutant selection did not kill is where a quiet package is looked for.
func TestASelectedRunLeavesQuietPackagesToTheWholeSuite(t *testing.T) {
	t.Parallel()
	t.Run("a survivor pays nothing", func(t *testing.T) {
		t.Parallel()
		var log strings.Builder
		dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": "package mini\n\nimport \"testing\"\n\n" + lookOnly,
			"other/o.go":      "package other\n",
			"other/o_test.go": "package other\n\nimport \"testing\"\n\nfunc TestFine(t *testing.T) {}\n"})
		if r := killOf(t, Options{Target: dir, Select: true, Log: &log}); r.Outcome != Survived {
			t.Fatalf("got %+v", r)
		}
		if strings.Contains(log.String(), goesAgain) {
			t.Fatalf("a survivor went again:\n%s", log.String())
		}
	})
	t.Run("a quiet kill still reads killed", func(t *testing.T) {
		t.Parallel()
		dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": "package mini\n\nimport (\"os\"; \"testing\")\n\n" +
			`func TestRefused(t *testing.T) { if Check("mallory") == nil { t.Fatal("mallory let in") } }
` + quietMain})
		if r := killOf(t, Options{Target: dir, Select: true}); r.Outcome != Killed {
			t.Fatalf("got %+v", r)
		}
	})
}

// routeTable is parallel subtests by the two names, the first catching the mutant with
// a recovered panic. Its line can land on the second, which passes.
func routeTable(first, second, par string) string {
	return `func TestRoutes(t *testing.T) {
	for _, tc := range []struct{ name, user string; wait time.Duration }{{"` + first + `", "mallory", 100 * time.Millisecond}, {"` + second + `", "admin", 400 * time.Millisecond}} {
		t.Run(tc.name, func(t *testing.T) {
			` + par + `
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "panic: %v\n", r)
					t.Fatal("handler died")
				}
			}()
			time.Sleep(tc.wait)
			if tc.user != "admin" && Check(tc.user) == nil { var m map[string]int; m["x"] = 1 }
		})
	}
}
`
}

// Review 13, H1. Go keeps a slash in a subtest's name, so cutting names on "/" looked
// for tests that do not exist, or took a sibling for a parent. What ran says what holds
// what. A real subtest is held, so its sequential neighbours keep the log-line rule.
func TestSlashesInSubtestNamesDoNotHideACrash(t *testing.T) {
	t.Parallel()
	const logs = `fmt.Println("panic: recovered and logged")`
	const refused = `if Check("mallory") == nil { t.Fatal("mallory let in") }`
	for name, tc := range map[string]struct {
		tests string
		want  Outcome
	}{
		"route names":         {routeTable("GET /admin as mallory", "POST /users as admin", "t.Parallel()"), Crashed},
		"one name holds next": {routeTable("read", "read/all", "t.Parallel()"), Crashed},
		"the other way round": {routeTable("read/all", "read", "t.Parallel()"), Crashed},
		"no slash":            {routeTable("mallory", "admin", "t.Parallel()"), Crashed},
		"in turn, route names": {`func TestRoutes(t *testing.T) {
	t.Run("GET /logs", func(t *testing.T) { ` + logs + ` })
	t.Run("GET /refused", func(t *testing.T) { ` + refused + ` })
}
`, Killed},
		"in turn, one name holds next": {`func TestRoutes(t *testing.T) {
	t.Run("read/all", func(t *testing.T) { ` + logs + ` })
	t.Run("read", func(t *testing.T) { ` + refused + ` })
}
`, Killed},
		"a real subtest": {`func TestRoutes(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		t.Run("logs", func(t *testing.T) { ` + logs + ` })
		t.Run("refused", func(t *testing.T) { ` + refused + ` })
	})
}
`, Killed},
		"a real subtest of a parallel test": {`func TestRoutes(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		t.Parallel()
		t.Run("logs", func(t *testing.T) { ` + logs + ` })
		t.Run("refused", func(t *testing.T) { ` + refused + ` })
	})
}
`, Killed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("fmt"; "os"; "testing"; "time")

var _, _, _ = fmt.Sprint, os.Stdout, time.Now

` + tc.tests})
			if r := killOf(t, Options{Target: dir}); r.Outcome != tc.want {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

// goTable is routeTable's subtests started from goroutines: concurrent, with no pause
// or cont. second waits long enough, or not, to end after the first.
func goTable(first, second string, wait int) string {
	return `func TestRoutes(t *testing.T) {
	var wg sync.WaitGroup
	for _, tc := range []struct{ name, user string; wait time.Duration }{{"` + first + `", "mallory", 300 * time.Millisecond}, {"` + second + `", "admin", ` + strconv.Itoa(wait) + ` * time.Millisecond}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.Run(tc.name, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "panic: %v\n", r)
						t.Fatal("handler died")
					}
				}()
				time.Sleep(tc.wait)
				if tc.user != "admin" && Check(tc.user) == nil { var m map[string]int; m["x"] = 1 }
			})
		}()
		time.Sleep(100 * time.Millisecond)
	}
	wg.Wait()
}
`
}

// Review 13, H2. Subtests started from goroutines run at once with no pause or cont, so
// overlap is read from run to end. A paused test is doing nothing, so one that paused
// counts from cont: a sequential test around it did not run beside it. Every shape
// here that is not concurrent keeps the log-line rule.
func TestOverlapIsReadFromRunToEnd(t *testing.T) {
	t.Parallel()
	const logs = `fmt.Println("panic: recovered and logged")`
	const refused = `if Check("mallory") == nil { t.Fatal("mallory let in") }`
	for name, tc := range map[string]struct {
		tests string
		want  Outcome
	}{
		"from goroutines":               {goTable("mallory", "admin", 800), Crashed},
		"from goroutines, slashes":      {goTable("GET /admin", "POST /users", 800), Crashed},
		"from goroutines, name in name": {goTable("read", "read/all", 800), Crashed},
		"parallel":                      {routeTable("mallory", "admin", "t.Parallel()"), Crashed},
		// A line lands on the test that printed last. read/all has every sign of read's
		// subtest but one: it failed, and read did not.
		"a sibling that looks held": {`func TestRoutes(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		t.Run("read", func(t *testing.T) { time.Sleep(200 * time.Millisecond); t.Log("tick"); time.Sleep(800 * time.Millisecond) })
	}()
	time.Sleep(100 * time.Millisecond)
	go func() {
		defer wg.Done()
		t.Run("read/all", func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "panic: %v\n", r)
					t.Fatal("handler died")
				}
			}()
			time.Sleep(400 * time.Millisecond)
			if Check("mallory") == nil { var m map[string]int; m["x"] = 1 }
		})
	}()
	wg.Wait()
}
`, Crashed},
		"sequential subtests": {`func TestRoutes(t *testing.T) {
	t.Run("logs", func(t *testing.T) { ` + logs + ` })
	t.Run("refused", func(t *testing.T) { ` + refused + ` })
}
`, Killed},
		"sequential tests": {`func TestLogs(t *testing.T) { ` + logs + ` }

func TestRefused(t *testing.T) { ` + refused + ` }
`, Killed},
		"a sequential test before a parallel one": {`func TestLogs(t *testing.T) { t.Parallel(); ` + logs + ` }

func TestRefused(t *testing.T) { ` + refused + ` }
`, Killed},
		"a sequential subtest beside a paused one": {`func TestRoutes(t *testing.T) {
	t.Run("logs", func(t *testing.T) { t.Parallel(); ` + logs + ` })
	t.Run("refused", func(t *testing.T) { ` + refused + ` })
}
`, Killed},
		"subtests in turn in a parallel test": {`func TestRoutes(t *testing.T) {
	t.Parallel()
	t.Run("logs", func(t *testing.T) { ` + logs + ` })
	t.Run("refused", func(t *testing.T) { ` + refused + ` })
}

func TestOther(t *testing.T) { t.Parallel() }
`, Killed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("fmt"; "os"; "sync"; "testing"; "time")

var _, _, _, _ = fmt.Sprint, os.Stdout, time.Now, sync.Mutex{}

` + tc.tests})
			if r := killOf(t, Options{Target: dir}); r.Outcome != tc.want {
				t.Fatalf("got %+v", r)
			}
		})
	}
}
