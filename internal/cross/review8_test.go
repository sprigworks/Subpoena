//subpoena:impl_derived

package cross

import (
	"testing"
	"time"
)

// Review 8, M3. The test that caught the mutant needs an earlier test, and a later
// one crashes or hangs on the mutant, so the repeat with no -failfast stops short.
// The first run's failed tests alone then pass, so the first run's command must
// go again before them. The command, not its tests, is what caught the mutant.
func TestAKillThatNeedsAnEarlierTestHoldsWhenTheRepeatStopsShort(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"crash": `panic("the mutant broke this too")`,
		"hang":  `time.Sleep(time.Hour)`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("testing"; "time")

var _ = time.Now

var ready bool

func TestSetup(t *testing.T) { ready = true }
func TestRefused(t *testing.T) {
	if ready && Check("mallory") == nil { t.Fatal("mallory let in") }
}
func TestLater(t *testing.T) {
	if Check("mallory") == nil { ` + body + ` }
}
`})
			if r := killOf(t, Options{Target: dir, Timeout: 30 * time.Second}); r.Outcome != Killed {
				t.Fatalf("a real kill was lost: %+v", r)
			}
		})
	}
}

// A red that the first command cannot repeat is still no kill: the fallback is one
// more chance for the same test, not a pass for any run that stopped short.
func TestAFlakeIsNoKillOnTheFallback(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import "testing"

func TestFlaky(t *testing.T) {
	if nth == 2 { t.Fatal("timing flake") }
}
func TestLater(t *testing.T) {
	if Check("mallory") == nil { panic("the mutant broke this") }
}
`})
	if r := killOf(t, Options{Target: dir, Timeout: 30 * time.Second}); r.Outcome != Unconfirmed {
		t.Fatalf("got %+v", r)
	}
}
