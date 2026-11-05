// Package crossmark is the mark that tells cross a witness failure came from
// the harness. The output of go test carries a test's failure messages and
// whatever the code under test prints in one stream, in the same shape, so a tag
// alone proves nothing. Under cross, the harness signs its witness failures
// with a key cross makes for the run. The key reaches the harness in the
// environment, and the harness takes it out of there as it loads.
//
// This raises the bar only. The code under test shares the test's process and
// can read the key if it goes looking, as it can forge anything else there. It
// stops a line printed in the ordinary way, which is what a system's own
// account of itself is.
package crossmark

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Env names the variable that hands the key to the test binary.
const Env = "SUBPOENA_CROSS_WITNESS_KEY"

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
