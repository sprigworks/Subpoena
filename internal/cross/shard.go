package cross

import "fmt"

// shardOf keeps shard k of n (1-based) of the mutants, so that n runs of one
// snapshot, each on its own host, judge every mutant once between them.
//
// The mutants are split by unit, in discovery order: a unit is a mutant with
// no group, or a whole group. Unit i goes to shard i mod n + 1. A group stays
// in one shard because its run, its pairs and its masked layers read the
// single results of all its layers. Discovery order is fixed by the snapshot,
// so every shard of one commit computes the same split.
//
// elsewhere names the groups that other shards judge: their entries in
// MaskedFile are not this shard's to match, so they are not stale here.
//
// A shard with no mutant refuses rather than report nothing: a run that judged
// nothing must not read as a pass.
//
//subpoena:enforcement_point
func shardOf(mutants []Mutant, k, n int) (mine []Mutant, elsewhere map[string]bool, err error) {
	if n < 1 || k < 1 || k > n {
		return nil, nil, fmt.Errorf("cross: shard %d/%d: want 1 <= shard <= shards", k, n) //subpoena:enforcement
	}
	unit := map[string]int{} // group -> its unit
	units := 0
	elsewhere = map[string]bool{}
	for _, m := range mutants {
		u, seen := unit[m.Group]
		if m.Group == "" || !seen {
			u = units
			units++
			if m.Group != "" {
				unit[m.Group] = u
			}
		}
		if u%n != k-1 {
			if m.Group != "" {
				elsewhere[m.Group] = true
			}
			continue
		}
		mine = append(mine, m)
	}
	if len(mine) == 0 {
		return nil, nil, fmt.Errorf("cross: shard %d/%d has no mutant: %d mutant(s) make %d unit(s), so use at most %d shards", k, n, len(mutants), units, units) //subpoena:enforcement
	}
	return mine, elsewhere, nil
}
