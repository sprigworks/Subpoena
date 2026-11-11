//subpoena:impl_derived

package cross

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func shardFixture() []Mutant {
	var ms []Mutant
	for i := range 7 {
		ms = append(ms, Mutant{Func: fmt.Sprintf("F%d", i), File: "a.go", Line: i + 1})
		if i == 2 || i == 5 {
			for j := range 3 {
				ms = append(ms, Mutant{Func: fmt.Sprintf("G%d", i), File: "b.go", Line: 10*i + j, Group: fmt.Sprintf("g%d", i)})
			}
		}
	}
	return ms
}

func TestShardsJudgeEachMutantOnce(t *testing.T) {
	all := shardFixture() // 7 single mutants and 2 groups of 3: 9 units
	for n := 1; n <= 9; n++ {
		seen := map[string]int{}
		groupShard := map[string]int{}
		for k := 1; k <= n; k++ {
			mine, elsewhere, err := shardOf(all, k, n)
			if err != nil {
				t.Fatalf("%d/%d: %v", k, n, err)
			}
			for _, m := range mine {
				seen[m.Name()]++
				if m.Group == "" {
					continue
				}
				if s, ok := groupShard[m.Group]; ok && s != k {
					t.Fatalf("%d/%d: group %s split across shards %d and %d", k, n, m.Group, s, k)
				}
				groupShard[m.Group] = k
				if elsewhere[m.Group] {
					t.Fatalf("%d/%d: group %s judged here but listed as elsewhere", k, n, m.Group)
				}
			}
			for g := range elsewhere {
				if groupShard[g] == k {
					t.Fatalf("%d/%d: elsewhere names this shard's group %s", k, n, g)
				}
			}
		}
		if len(seen) != len(all) {
			t.Fatalf("%d shards judged %d of %d mutants", n, len(seen), len(all))
		}
		for name, c := range seen {
			if c != 1 {
				t.Fatalf("%d shards judged %s %d times", n, name, c)
			}
		}
	}
}

func TestShardOutOfRangeIsRefused(t *testing.T) {
	for _, c := range [][2]int{{0, 2}, {3, 2}, {1, 0}, {-1, 3}} {
		if _, _, err := shardOf(shardFixture(), c[0], c[1]); err == nil || !strings.Contains(err.Error(), "want 1 <= shard <= shards") {
			t.Fatalf("shard %d/%d: want a range refusal, got %v", c[0], c[1], err)
		}
	}
}

// A shard past the last unit would judge nothing; that must not read as a pass.
func TestEmptyShardIsRefused(t *testing.T) {
	if _, _, err := shardOf(shardFixture(), 10, 10); err == nil || !strings.Contains(err.Error(), "use at most 9 shards") {
		t.Fatalf("want an empty-shard refusal, got %v", err)
	}
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	rep, err := Run(context.Background(), Options{Target: dir, Shard: 2, Shards: 2})
	if err == nil || !strings.Contains(err.Error(), "has no mutant") {
		t.Fatalf("an empty shard must refuse, got %v %+v", err, rep)
	}
}

// Each shard matches only its own groups' entries in MaskedFile: another
// shard's entries are not stale here, and its own still are.
func TestShardedRunMatchesOnlyItsOwnMaskedEntries(t *testing.T) {
	files := func(masked string) map[string]string {
		return map[string]string{
			"auth.go": authOK, "auth_test.go": strongTest,
			"exec.go": layeredSrc, "exec_test.go": layeredTest,
			MaskedFile: masked,
		}
	}
	dir := module(t, files(maskedList))
	judged := 0
	for k := 1; k <= 2; k++ {
		rep, err := Run(context.Background(), Options{Target: dir, Shard: k, Shards: 2})
		if err != nil {
			t.Fatalf("shard %d/2: %v", k, err)
		}
		if rep.Total != 3 || rep.Shard != k || rep.Shards != 2 {
			t.Fatalf("shard %d/2: total %d, shard %d/%d", k, rep.Total, rep.Shard, rep.Shards)
		}
		if rep.Failed() || len(rep.StaleAccepted) != 0 {
			t.Fatalf("shard %d/2 must pass with no stale entry: %+v stale=%v", k, rep.Results, rep.StaleAccepted)
		}
		for _, r := range rep.Results {
			if r.Group == "" {
				judged++
			}
		}
	}
	if judged != 3 {
		t.Fatalf("the two shards judged %d mutants alone, want 3", judged)
	}

	// A stale entry for the group's own shard still fails that shard.
	stale := maskedList + "exec.go | Exec | group=revoke | return nil | no such masked layer\n"
	dir = module(t, files(stale))
	failed := 0
	for k := 1; k <= 2; k++ {
		rep, err := Run(context.Background(), Options{Target: dir, Shard: k, Shards: 2})
		if err != nil {
			t.Fatalf("shard %d/2: %v", k, err)
		}
		if len(rep.StaleAccepted) > 0 && rep.Failed() {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("the stale entry failed %d shards, want exactly the group's own", failed)
	}
}
