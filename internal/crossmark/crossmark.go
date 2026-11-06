// Package crossmark is the mark that tells cross a witness failure came from
// the harness. The output of go test carries a test's failure messages and
// whatever the code under test prints in one stream, in the same shape, so a tag
// alone proves nothing. Under cross, the harness signs its witness failures
// with a key cross makes for the run. The key reaches the harness in the
// environment, and the harness takes it out of there as it loads.
//
// This raises the bar only. The key is reachable: /proc/<pid>/environ keeps it
// after the harness unsets it, so the code under test, and any process it starts
// or any other process of the same user, can read it and forge a mark. It stops
// a line printed in the ordinary way, which is what a system's own account of
// itself is. It does not stop code set on forging one.
package crossmark

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
)

// Env names the variable that hands the key to the test binary.
const Env = "SUBPOENA_CROSS_WITNESS_KEY"

// Active reports whether this process is a test binary cross started. It is read
// here, before the harness takes the key out of the environment. It is for a
// suite to leave out what must not run once per mutant, never for a verdict.
var Active = os.Getenv(Env) != ""

var markRE = regexp.MustCompile(` \[subpoena-cross:[0-9a-f]{32}\]`)

func mark(key, line string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(line))
	return " [subpoena-cross:" + hex.EncodeToString(h.Sum(nil))[:32] + "]"
}

// Sign marks the first line of msg, the only line cross reads a tag from. The
// mark goes at the end of it, so the message still starts with its tag.
func Sign(key, msg string) string {
	first, rest, more := strings.Cut(msg, "\n")
	first += mark(key, first)
	if more {
		return first + "\n" + rest
	}
	return first
}

// Verify reports whether line ends with the mark of the rest of it under key.
// An empty key verifies nothing.
func Verify(key, line string) bool {
	at := strings.LastIndex(line, " [subpoena-cross:")
	return key != "" && at >= 0 && hmac.Equal([]byte(line[at:]), []byte(mark(key, line[:at])))
}

// Strip removes marks from text meant for a reader.
func Strip(text string) string { return markRE.ReplaceAllString(text, "") }
