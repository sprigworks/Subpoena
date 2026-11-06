//subpoena:impl_derived

package cross

import (
	"flag"
	"os"
	"runtime"
	"strconv"
	"testing"
)

// maxParallel bounds this package's parallel tests. Each runs go test on a fixture,
// which builds and links with every CPU it can get, and the tests that hang a fixture
// give those commands a fixed Options.Timeout that a build has to fit in. Left at
// GOMAXPROCS the suite started some 70 of them at once on a 72-core host, per copy, so
// under make cross-self's -j each copy starved the others past those deadlines: the
// suite failed by itself, with no mutant, and a kill read unconfirmed.
const maxParallel = 8

// TestMain bounds -parallel, unless the command line set it.
func TestMain(m *testing.M) {
	flag.Parse()
	set := false
	flag.Visit(func(f *flag.Flag) { set = set || f.Name == "test.parallel" })
	if !set {
		flag.Set("test.parallel", strconv.Itoa(min(maxParallel, runtime.GOMAXPROCS(0))))
	}
	os.Exit(m.Run())
}
