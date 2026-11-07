//subpoena:spec_derived
//subpoena:pure_logic

package crossmark

import "testing"

func TestSignedLineVerifiesUnderItsKeyOnly(t *testing.T) {
	line := Sign("k", "witness: refused command ran")
	if !Verify("k", line) {
		t.Fatalf("%q does not verify", line)
	}
	if Verify("other", line) || Verify("", line) {
		t.Fatalf("%q verifies under another key", line)
	}
	if got := Strip(line); got != "witness: refused command ran" {
		t.Fatalf("Strip = %q", got)
	}
}

func TestAnUnsignedOrAlteredLineDoesNotVerify(t *testing.T) {
	line := Sign("k", "witness: refused command ran")
	for _, bad := range []string{"witness: refused command ran", "x" + line, "witness: printed by the app [subpoena-cross:00000000000000000000000000000000]"} {
		if Verify("k", bad) {
			t.Fatalf("%q verifies", bad)
		}
	}
}

func TestOnlyTheFirstLineIsSigned(t *testing.T) {
	got := Sign("k", "witness: a\nb")
	if !Verify("k", got[:len(got)-2]) || got[len(got)-2:] != "\nb" {
		t.Fatalf("got %q", got)
	}
}
