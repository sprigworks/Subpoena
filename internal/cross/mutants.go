// Finding mutants from the markers, and applying them to source.

package cross

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// groupsOf collects the layer groups. A group needs at least two layers (one
// is a typo that would silently drop the group run) and at most maxGroup.
//
//subpoena:enforcement_point
func groupsOf(mutants []Mutant) (map[string][]Mutant, error) {
	groups := map[string][]Mutant{}
	for _, m := range mutants {
		if m.Group != "" {
			groups[m.Group] = append(groups[m.Group], m)
		}
	}
	for g, ms := range groups {
		if len(ms) < 2 {
			return nil, fmt.Errorf("cross: group=%s has one layer (%s); a group needs at least two", g, ms[0].Name()) //subpoena:enforcement
		}
		if len(ms) > maxGroup {
			return nil, fmt.Errorf("cross: group=%s has %d layers; at most %d", g, len(ms), maxGroup) //subpoena:enforcement
		}
	}
	return groups, nil
}

// applyMutant applies one mutant to the snapshot bytes. Run does not use this
// to detect copy drift: it compares the copy to m.src and refuses before
// calling here. This check remains so a direct caller cannot slice different
// bytes silently.
func applyMutant(src []byte, m Mutant) ([]byte, error) {
	return applyMutants(src, []Mutant{m})
}

// applyMutants applies several mutants of one file, from the end backwards so
// earlier offsets stay valid. Overlapping mutants are refused.
func applyMutants(src []byte, ms []Mutant) ([]byte, error) {
	sorted := append([]Mutant(nil), ms...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].start > sorted[j].start })
	out := append([]byte{}, src...)
	for i, m := range sorted {
		if m.src != nil && !bytes.Equal(src, m.src) {
			return nil, fmt.Errorf("source drift: bytes are not the discovery snapshot")
		}
		if m.start < 0 || m.end < m.start || m.end > len(src) {
			return nil, fmt.Errorf("source drift: offsets %d:%d outside %d-byte snapshot", m.start, m.end, len(src))
		}
		if string(src[m.start:m.end]) != m.Removed {
			return nil, fmt.Errorf("source drift: offsets no longer match %q", oneLine(m.Removed))
		}
		if i > 0 && m.end > sorted[i-1].start {
			return nil, fmt.Errorf("mutants overlap: %s and %s", m.Name(), sorted[i-1].Name())
		}
		out = append(append(append([]byte{}, out[:m.start]...), []byte(m.replacement())...), out[m.end:]...)
	}
	return out, nil
}

func snapshotOf(mutants []Mutant) []SourceFile {
	seen := map[string][]byte{}
	var files []string
	for _, m := range mutants {
		if _, ok := seen[m.File]; ok {
			continue
		}
		seen[m.File] = m.src
		files = append(files, m.File)
	}
	sort.Strings(files)
	out := make([]SourceFile, 0, len(files))
	for _, file := range files {
		sum := sha256.Sum256(seen[file])
		out = append(out, SourceFile{Path: file, SHA256: hex.EncodeToString(sum[:])})
	}
	return out
}

// FindMutants locates every //subpoena:enforcement statement inside a function
// marked as an enforcement point (MarkerEnforcementPoint), in non-test files
// under target. Its doc names the marker by constant: the marker text in a
// doc comment, even in prose, makes a function an enforcement point.
func FindMutants(root, target string) ([]Mutant, error) {
	var out []Mutant
	err := filepath.WalkDir(target, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != target && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		ms, err := mutantsInFile(root, p)
		out = append(out, ms...)
		return err
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, err
}

//subpoena:enforcement_point
func mutantsInFile(root, path string) ([]Mutant, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	rel, _ := filepath.Rel(root, path)
	var out []Mutant
	// placed holds the marker comments that took effect: statement and guard
	// markers inside an enforcement point, and point markers on a function.
	placed := map[*ast.Comment]bool{}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Doc != nil {
			for _, c := range fd.Doc.List {
				if pointRE.MatchString(c.Text) {
					placed[c] = true
				}
			}
		}
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || fd.Doc == nil || !hasPointMarker(fd.Doc) {
			continue
		}
		found := 0
		// Marker lines inside this function. The markers share a prefix, so
		// parseMarker matches the exact comment word.
		lines := map[int]marker{}
		for _, g := range f.Comments {
			for _, c := range g.List {
				if c.Pos() <= fd.Body.Lbrace || c.End() >= fd.Body.Rbrace {
					continue
				}
				mk, ok, err := parseMarker(markerText(src, fset.Position(c.Pos()).Offset, c.Text))
				if err != nil {
					return nil, fmt.Errorf("cross: %s:%d: %w", rel, fset.Position(c.Pos()).Line, err) //subpoena:enforcement
				}
				if ok {
					lines[fset.Position(c.Pos()).Line] = mk
					placed[c] = true
				}
			}
		}
		offIf := map[int]bool{} // guard lines whose outermost statement is not an if
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			st, ok := n.(ast.Stmt)
			if !ok {
				return true
			}
			if _, isBlock := st.(*ast.BlockStmt); isBlock {
				return true
			}
			line := fset.Position(st.Pos()).Line
			mk, marked := lines[line]
			if !marked || offIf[line] {
				return true
			}
			// Take the outermost statement that starts on the marked line. A
			// guard marker takes the if and forces its condition. A statement
			// marker on `if cond { return x }` would remove the whole if, so
			// only simple statements are accepted.
			var node ast.Node = st
			if mk.guard {
				ifs, isIf := st.(*ast.IfStmt)
				if !isIf {
					// An if further in (in a closure on this line) is not
					// the statement the marker sits on: leave the line
					// unplaced, which is an error below.
					offIf[line] = true //subpoena:enforcement
					return true
				}
				node = ifs.Cond
			} else {
				switch st.(type) {
				case *ast.ReturnStmt, *ast.ExprStmt, *ast.AssignStmt, *ast.BranchStmt, *ast.IncDecStmt:
				default:
					return true
				}
			}
			delete(lines, line)
			found++
			s, e := fset.Position(node.Pos()).Offset, fset.Position(node.End()).Offset
			m := Mutant{
				Func: fd.Name.Name, File: filepath.ToSlash(rel), Line: line, Upstream: upstreamLine(src, line),
				Removed: string(src[s:e]), Bypass: mk.bypass, Group: mk.group,
				start: s, end: e, point: fset.Position(fd.Pos()).Offset, src: src,
			}
			if ret, ok := st.(*ast.ReturnStmt); ok && !mk.guard {
				m.zero, m.fnEnd = zeroReturn(src, fset, fd, ret)
			}
			out = append(out, m)
			return true
		})
		if len(lines) > 0 {
			left := make([]int, 0, len(lines))
			for line := range lines {
				left = append(left, line)
			}
			sort.Ints(left)
			return nil, fmt.Errorf("cross: %s:%d: %s", rel, left[0], misplaced(lines[left[0]], fd.Name.Name)) //subpoena:enforcement
		}
		// An enforcement point with nothing to remove would never be
		// cross-examined, and the run would still go green.
		if found == 0 {
			return nil, fmt.Errorf("cross: %s: %s is marked //%s but has no //%s statement, so it cannot be cross-examined", rel, fd.Name.Name, MarkerEnforcementPoint, MarkerEnforcement) //subpoena:enforcement
		}
	}
	// A marker that took no effect would leave its statement unexamined while
	// the run stays green: one outside an enforcement point, or a misspelt one.
	var stray error
	for _, g := range f.Comments {
		for _, c := range g.List {
			if strayMarker(src, fset.Position(c.Pos()).Offset, c.Text) && !placed[c] && stray == nil {
				stray = fmt.Errorf("cross: %s:%d: %q is not a marker cross applies: statement and guard markers belong inside a //%s function, and the point marker on a function's doc comment; %s", rel, fset.Position(c.Pos()).Line, c.Text, MarkerEnforcementPoint, proseHint)
			}
		}
	}
	if stray != nil {
		return nil, stray //subpoena:enforcement
	}
	return out, nil
}

// zeroReturn returns the statement that can stand in for ret where the
// function cannot end without a return, and the offset of that function's
// closing brace. *new(T) is T's zero value for any T, so no type needs
// resolving. Only a refusal carried by an error has a stand-in (see
// errorRefusal). Zero is not "enforcement gone" for any other return: false can
// be the refusal, and then the stand-in forces enforcement on, and the value is
// cross's own choice, with no review behind it as a guard's bypass value has.
//
//subpoena:enforcement_point
func zeroReturn(src []byte, fset *token.FileSet, fd *ast.FuncDecl, ret *ast.ReturnStmt) (string, int) {
	typ, body := fd.Type, fd.Body
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.FuncLit); ok && lit.Body.Pos() <= ret.Pos() && ret.Pos() < lit.Body.End() {
			typ, body = lit.Type, lit.Body
		}
		return true
	})
	end := fset.Position(body.Rbrace).Offset
	if typ.Results == nil {
		return "", end
	}
	var zeros []string
	var isError []bool
	for _, field := range typ.Results.List {
		text := string(src[fset.Position(field.Type.Pos()).Offset:fset.Position(field.Type.End()).Offset])
		if strings.Contains(text, "\n") {
			return "", end // one line only: the line numbers of a retried build depend on it
		}
		for range max(1, len(field.Names)) {
			zeros = append(zeros, "*new("+text+")")
			isError = append(isError, text == "error")
		}
	}
	if !errorRefusal(ret.Results, isError) {
		return "", end //subpoena:enforcement
	}
	if !tailReturn(body.List, ret) {
		return "", end //subpoena:enforcement
	}
	return "return " + strings.Join(zeros, ", "), end
}

// tailReturn reports whether ret is one the function cannot end without: it
// ends list, or a branch of the statement that ends list, by the language's
// rule for a terminating statement. Any other return can go. In a group with one
// that cannot, the compiler names the same function end for both, and a stand-in
// here would stop the mutant where it must carry on.
func tailReturn(list []ast.Stmt, ret *ast.ReturnStmt) bool {
	if len(list) == 0 {
		return false
	}
	clauses := func(body *ast.BlockStmt) bool {
		return slices.ContainsFunc(body.List, func(s ast.Stmt) bool {
			switch c := s.(type) {
			case *ast.CaseClause:
				return tailReturn(c.Body, ret)
			case *ast.CommClause:
				return tailReturn(c.Body, ret)
			}
			return false
		})
	}
	switch s := list[len(list)-1].(type) {
	case *ast.ReturnStmt:
		return s == ret
	case *ast.BlockStmt:
		return tailReturn(s.List, ret)
	case *ast.LabeledStmt:
		return tailReturn([]ast.Stmt{s.Stmt}, ret)
	case *ast.IfStmt:
		return tailReturn(s.Body.List, ret) || s.Else != nil && tailReturn([]ast.Stmt{s.Else}, ret)
	case *ast.SwitchStmt:
		return clauses(s.Body)
	case *ast.TypeSwitchStmt:
		return clauses(s.Body)
	case *ast.SelectStmt:
		return clauses(s.Body)
	}
	return false
}

// errorRefusal reports whether a return's only news is an error, so that its
// zero values turn a possible refusal into nil and change nothing else. Every
// other result must already be plainly zero: a value beside the error can carry
// the decision. A call in the error can be the work itself (return
// s.Authorize(admins) opens the session), so the stand-in would drop what the
// allowed path needs. Cross cannot see what a call does, so that holds for
// fmt.Errorf too. A bare return, and one call spread over the results, say
// nothing about which result is which.
func errorRefusal(results []ast.Expr, isError []bool) bool {
	if len(results) != len(isError) {
		return false
	}
	refusal := false
	for i, e := range results {
		if isZeroValue(e) {
			continue
		}
		if !isError[i] || doesWork(e) {
			return false
		}
		refusal = true
	}
	return refusal
}

// doesWork reports whether evaluating e can do anything: a call, or a receive.
func doesWork(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			found = true
		case *ast.UnaryExpr:
			found = found || x.Op == token.ARROW
		}
		return !found
	})
	return found
}

// isZeroValue reports whether e is plainly a zero value. A named constant that
// happens to be zero is not seen here.
func isZeroValue(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "nil" || x.Name == "false"
	case *ast.BasicLit:
		return x.Value == "0" || x.Value == `""` || x.Value == "``"
	case *ast.CompositeLit:
		return len(x.Elts) == 0
	}
	return false
}

// misplaced says why a marker matched no statement.
func misplaced(mk marker, fn string) string {
	if mk.guard {
		return fmt.Sprintf("//%s in %s is not on an if line", MarkerGuard, fn)
	}
	return fmt.Sprintf("//%s in %s is not on a simple statement line", MarkerEnforcement, fn)
}

// marker is a parsed //subpoena:enforcement or //subpoena:enforcement_guard.
type marker struct {
	guard  bool
	bypass string // guard only: "true" or "false"
	group  string
}

var (
	enforcementRE = regexp.MustCompile(`^//\s*` + regexp.QuoteMeta(MarkerEnforcement) + `(\s|$)`)
	guardRE       = regexp.MustCompile(`^//\s*` + regexp.QuoteMeta(MarkerGuard) + `(\s|$)`)
	groupRE       = regexp.MustCompile(`^group=([A-Za-z0-9_.-]+)$`)
	pointRE       = regexp.MustCompile(`^//\s*` + regexp.QuoteMeta(MarkerEnforcementPoint) + `(\s|$)`)
	anyMarkerRE   = regexp.MustCompile(`^//\s*subpoena\s*:\s*enforc`)
	// ownMarkerRE is anyMarkerRE for a comment on a line of its own, where a space
	// by the colon says prose: subpoena: enforcement points are listed in docs.
	ownMarkerRE = regexp.MustCompile(`^//\s*subpoena:enforc`)
	// nearMarkerRE reads a comment in a marker's shape: two words about a colon,
	// and arguments that nearMarker checks. A comment that goes on is prose.
	nearMarkerRE = regexp.MustCompile(`^//\s*([A-Za-z]+)\s*:\s*([A-Za-z_]+)((?:\s+\S+)*)\s*$`)
	// trailingRE finds a marker after an upstream comment on a line of code, as
	// loosely as anyMarkerRE, so a misspelt one there is an error too:
	// return nil // why //subpoena:enforcement
	trailingRE = regexp.MustCompile(`//\s*subpoena\s*:\s*enforc`)
	// onlyMarkerRE reads source lines: the lines marking added.
	onlyMarkerRE = regexp.MustCompile(`^\s*//\s*subpoena:enforcement`)
	// directiveRE is go/ast's form of a directive, as //go:noinline.
	directiveRE = regexp.MustCompile(`^//[a-z0-9]+:[a-z0-9]`)
)

// proseHint ends a marker error, since cross cannot tell the two apart.
const proseHint = "a comment that starts with a marker, or names one on a line of code, reads as one, so if this is prose, reword it"

// markerText is a comment's marker, or its text if it has none. On a line of
// code that is the end of the comment when a marker follows upstream's text, so
// marking a line removes none of it. Arguments stay, so a bad one is an error. A
// comment on a line of its own that mentions a marker is prose, and so is one that
// names the point marker, which no line of code can carry.
func markerText(src []byte, offset int, text string) string {
	if ownLine(src, offset) || !strings.HasPrefix(text, "//") {
		return text
	}
	for _, loc := range trailingRE.FindAllStringIndex(text, -1) {
		if found := strings.TrimSpace(text[loc[0]:]); !pointRE.MatchString(found) {
			return found
		}
	}
	for i := range text {
		if strings.HasPrefix(text[i:], "//") && nearMarker(text[i:]) && !pointRE.MatchString(text[i:]) {
			return text[i:]
		}
	}
	return text
}

// ownLine reports whether nothing comes before offset on its line.
func ownLine(src []byte, offset int) bool {
	start := bytes.LastIndexByte(src[:offset], '\n') + 1
	return len(bytes.TrimSpace(src[start:offset])) == 0
}

// strayMarker reports whether a comment reads as a marker. One that took no
// effect is an error, so this must not catch prose where it can tell: on a line
// of its own a comment is one only if it is written as a marker is, or nearMarker
// says it is. On a line of code the words alone are enough, since a mark goes after
// upstream's text there.
func strayMarker(src []byte, offset int, text string) bool {
	text = markerText(src, offset, text)
	if nearMarker(text) {
		return true
	}
	if ownLine(src, offset) {
		return ownMarkerRE.MatchString(text)
	}
	return anyMarkerRE.MatchString(text)
}

// nearMarker reports whether text is a marker with its words in the wrong case or
// with two letters swapped, in a marker's shape and with nothing but a marker's
// arguments after them, so a sentence that opens with those words is no match.
func nearMarker(text string) bool {
	m := nearMarkerRE.FindStringSubmatch(text)
	if m == nil {
		return false
	}
	for _, arg := range strings.Fields(m[3]) {
		if arg != "true" && arg != "false" && !strings.HasPrefix(arg, "group=") {
			return false
		}
	}
	return swapped(strings.ToLower(m[1]), func(s string) bool { return s == "subpoena" }) &&
		swapped(strings.ToLower(m[2]), func(s string) bool { return strings.HasPrefix(s, "enforc") })
}

// swapped reports whether s, or s with two neighbouring letters swapped, is ok.
func swapped(s string, ok func(string) bool) bool {
	if ok(s) {
		return true
	}
	b := []byte(s)
	for i := 0; i+1 < len(b); i++ {
		b[i], b[i+1] = b[i+1], b[i]
		if ok(string(b)) {
			return true
		}
		b[i], b[i+1] = b[i+1], b[i]
	}
	return false
}

// upstreamLine is line with the lines marking added above it taken out: a
// marker-only line, and the empty // gofmt puts before one in a doc comment. That
// // stays if a directive follows the marker: gofmt wants it there anyway.
func upstreamLine(src []byte, line int) int {
	up := line
	lines := bytes.Split(src, []byte("\n"))
	for i := 0; i < line-1 && i < len(lines); i++ {
		if !onlyMarkerRE.Match(lines[i]) {
			continue
		}
		up--
		if i > 0 && string(bytes.TrimSpace(lines[i-1])) == "//" && !beforeDirective(lines, i) {
			up--
		}
	}
	return up
}

// beforeDirective reports whether the first line after the marker-only lines from
// line i on is a directive.
func beforeDirective(lines [][]byte, i int) bool {
	for i < len(lines) && onlyMarkerRE.Match(lines[i]) {
		i++
	}
	return i < len(lines) && directiveRE.Match(bytes.TrimSpace(lines[i]))
}

// markerCount counts the statement and guard markers in the comments of the
// mutated files, and names those that made no mutant. A marker that took no effect
// is an error where cross can tell; this is for what it cannot. The parser says
// what a comment is: a block comment or a string that shows a marker holds none.
func markerCount(ms []Mutant) (int, []string) {
	lines := map[string]map[int]bool{}
	src := map[string][]byte{}
	for _, m := range ms {
		if lines[m.File] == nil {
			lines[m.File], src[m.File] = map[int]bool{}, m.src
		}
		lines[m.File][m.Line] = true
	}
	n := 0
	var unplaced []string
	for _, file := range slices.Sorted(maps.Keys(src)) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, src[file], parser.ParseComments)
		if err != nil {
			continue // discovery parsed these bytes
		}
		for _, g := range f.Comments {
			for _, c := range g.List {
				at := fset.Position(c.Pos())
				text := markerText(src[file], at.Offset, c.Text)
				if enforcementRE.MatchString(text) || guardRE.MatchString(text) {
					n++
					if !lines[file][at.Line] {
						unplaced = append(unplaced, fmt.Sprintf("%s:%d", file, at.Line))
					}
				}
			}
		}
	}
	return n, unplaced
}

func isEnforcementComment(text string) bool { return enforcementRE.MatchString(text) }

// parseMarker reads a statement or guard marker. ok is false for any other
// comment. Arguments it does not understand are an error, not ignored: a
// misspelt group would otherwise drop the layer from its group silently.
//
//subpoena:enforcement_point
func parseMarker(text string) (mk marker, ok bool, err error) {
	var args []string
	switch {
	case guardRE.MatchString(text):
		args = strings.Fields(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(text, "//")), MarkerGuard))
		mk.guard = true
		if len(args) > 0 {
			mk.bypass, args = args[0], args[1:]
		}
		if mk.bypass != "true" && mk.bypass != "false" {
			return mk, false, fmt.Errorf("//%s needs the bypass value first: true or false", MarkerGuard) //subpoena:enforcement
		}
	case enforcementRE.MatchString(text):
		args = strings.Fields(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(text, "//")), MarkerEnforcement))
	default:
		return mk, false, nil
	}
	for _, a := range args {
		name := ""
		if g := groupRE.FindStringSubmatch(a); g != nil {
			name = g[1]
		}
		if name == "" || mk.group != "" {
			return mk, false, fmt.Errorf("marker argument %q: want at most one group=<name>; %s", a, proseHint) //subpoena:enforcement
		}
		mk.group = name
	}
	return mk, true, nil
}

// hasPointMarker reports whether a doc comment mentions the enforcement-point
// marker anywhere, as subpoena-lint does (internal/lint commentHas). Matching
// loosely fails closed: anything lint treats as an enforcement point must have
// a statement to cross-examine.
func hasPointMarker(g *ast.CommentGroup) bool {
	for _, c := range g.List {
		if strings.Contains(c.Text, MarkerEnforcementPoint) {
			return true
		}
	}
	return false
}

// absoluteReplaces rewrites the copy's go.mod so that a replace pointing at a
// relative directory (replace example.com/x => ../x, common while developing
// against a local checkout) still points at that directory from the temp
// copy, where the relative path would resolve to nothing.
func absoluteReplaces(ctx context.Context, root, tmp string) error {
	out, err := goCmd(ctx, time.Minute, root, "mod", "edit", "-json")
	if err != nil {
		return fmt.Errorf("cross: read go.mod: %s", tail(out, 10))
	}
	var mod struct {
		Replace []struct {
			Old, New struct{ Path, Version string }
		}
	}
	if err := json.Unmarshal([]byte(out), &mod); err != nil {
		return fmt.Errorf("cross: read go.mod: %w", err)
	}
	for _, r := range mod.Replace {
		if r.New.Version != "" || !(strings.HasPrefix(r.New.Path, "./") || strings.HasPrefix(r.New.Path, "../")) {
			continue
		}
		old := r.Old.Path
		if r.Old.Version != "" {
			old += "@" + r.Old.Version
		}
		abs := filepath.Join(root, filepath.FromSlash(r.New.Path))
		if out, err := goCmd(ctx, time.Minute, tmp, "mod", "edit", "-replace="+old+"="+abs); err != nil {
			return fmt.Errorf("cross: rewrite replace %s: %s", old, tail(out, 10))
		}
	}
	return nil
}

var missingReturnRE = regexp.MustCompile(`(?m)^(?:\./)?(\S+\.go):(\d+):\d+: missing return$`)

// finalReturnHint is the advice for a return with no stand-in.
const finalReturnHint = "the function cannot end without this return, and cross replaces one only where that plainly turns an error to nil, so no mutant can stand in for it; " +
	"mark the if that reaches it with //" + MarkerGuard + ", or move the decision into an if that can carry the marker"

// zeroMissingReturns turns on the zero-value return of each mutant whose
// function the compiler reports as missing a return, and reports whether it
// turned on any. A return the function can do without stays removed: a stand-in
// there would end the function where the mutant must carry on.
func zeroMissingReturns(ms []Mutant, file, buildOut string) ([]Mutant, bool) {
	lines := map[int]bool{}
	for _, m := range missingReturnRE.FindAllStringSubmatch(buildOut, -1) {
		if reportedFile(m[1], file) {
			var n int
			fmt.Sscan(m[2], &n)
			lines[n] = true
		}
	}
	out := slices.Clone(ms)
	changed := false
	for i, m := range out {
		if m.zero != "" && lines[lineAfterRemovals(m.fnEnd, ms)] {
			out[i].useZero, changed = true, true
		}
	}
	return out, changed
}

// lineAfterRemovals is the line of a snapshot offset once ms are applied: a
// removed statement leaves one line however many it spanned.
func lineAfterRemovals(offset int, ms []Mutant) int {
	src := ms[0].src
	line := 1 + bytes.Count(src[:offset], []byte("\n"))
	for _, m := range ms {
		if m.Bypass == "" && m.end <= offset {
			line -= bytes.Count(src[m.start:m.end], []byte("\n"))
		}
	}
	return line
}

// reportedFile reports whether a path in compiler output is file, a
// module-relative path.
func reportedFile(reported, file string) bool {
	r, f := filepath.ToSlash(filepath.Clean(reported)), filepath.ToSlash(filepath.Clean(file))
	return r == f || strings.HasSuffix(f, "/"+r)
}

var unusedImportRE = regexp.MustCompile(`(?m)^(?:\./)?(\S+\.go):(\d+):\d+: "[^"]+" imported (?:as \S+ )?and not used`)

// pruneUnusedImports removes from src (the mutated file, at module-relative
// path file) the import lines the compiler output reports as unused, and
// reports whether it removed any. Only lines in the mutated file are touched,
// and only import specs on a line of their own.
func pruneUnusedImports(src []byte, file, buildOut string) ([]byte, bool) {
	drop := map[int]bool{}
	for _, m := range unusedImportRE.FindAllStringSubmatch(buildOut, -1) {
		if !reportedFile(m[1], file) {
			continue
		}
		var n int
		fmt.Sscan(m[2], &n)
		drop[n] = true
	}
	if len(drop) == 0 {
		return nil, false
	}
	lines := strings.SplitAfter(string(src), "\n")
	var b strings.Builder
	removed := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if drop[i+1] && (strings.HasPrefix(t, `"`) || strings.HasPrefix(t, "import ") || (len(t) > 0 && strings.Contains(t, ` "`))) {
			removed = true
			continue
		}
		b.WriteString(l)
	}
	return []byte(b.String()), removed
}
