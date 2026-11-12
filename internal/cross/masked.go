// Accepted masked layers (cross-masked.txt).

package cross

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// acceptMasked marks masked layers listed in the masked-layer file as
// accepted, and records entries that match no masked layer as stale. A
// missing file accepts nothing.
//
//subpoena:enforcement_point
func acceptMasked(rep *Report, path string, elsewhere map[string]bool) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	reasons := map[string]string{}
	var order []string
	bad := 0 // first malformed line; the verdict is kept apart from the return, as in Run
	ambiguous := ""
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.SplitN(line, " | ", 5)
		if len(f) != 5 || !strings.HasPrefix(strings.TrimSpace(f[2]), "group=") || strings.TrimSpace(f[4]) == "" {
			bad = i + 1
			break
		}
		key := maskedKey(strings.TrimSpace(f[0]), strings.TrimSpace(f[1]), strings.TrimPrefix(strings.TrimSpace(f[2]), "group="), f[3])
		if _, dup := reasons[key]; dup {
			bad = i + 1
			break
		}
		reasons[key] = strings.TrimSpace(f[4])
		if !elsewhere[strings.TrimPrefix(strings.TrimSpace(f[2]), "group=")] {
			order = append(order, key) // another shard's group is that shard's to match
		}
	}
	if bad > 0 {
		return fmt.Errorf("cross: %s:%d: want <file> | <func> | group=<group> | <removed text> | <reason>, each layer listed once", MaskedFile, bad) //subpoena:enforcement
	}
	// One entry accepts one layer. Two masked layers with the same key (the
	// same text twice in one function) cannot be told apart, so neither is.
	layers := map[string]int{}
	for _, r := range rep.Results {
		if r.Outcome == Masked {
			layers[maskedKey(r.Mutant.File, r.Mutant.Func, r.Mutant.Group, r.Mutant.Removed)]++
		}
	}
	for key := range reasons {
		if layers[key] > 1 {
			delete(reasons, key)
			ambiguous = key
		}
	}
	if ambiguous != "" {
		return fmt.Errorf("cross: %s: %q matches %d masked layers; an entry accepts one layer, so make the removed text unique", MaskedFile, ambiguous, layers[ambiguous]) //subpoena:enforcement
	}
	used := map[string]bool{}
	for i, r := range rep.Results {
		if r.Outcome != Masked {
			continue
		}
		key := maskedKey(r.Mutant.File, r.Mutant.Func, r.Mutant.Group, r.Mutant.Removed)
		if reason, ok := reasons[key]; ok {
			rep.Results[i].Accepted = reason
			used[key] = true
		}
	}
	for _, key := range order {
		if !used[key] {
			rep.StaleAccepted = append(rep.StaleAccepted, key)
		}
	}
	return nil
}

func maskedKey(file, fn, group, removed string) string {
	return file + " | " + fn + " | group=" + group + " | " + oneLine(removed)
}
