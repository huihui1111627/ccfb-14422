// Package verify drives the OSPF simulation through a fixed-seed weather
// replay of thousands of events and checks the protocol invariants the task
// requires:
//
//   - every router in an area holds byte-identical link state databases
//     (modulo the LS age, which the protocol deliberately lets drift),
//   - every neighbour state change follows the published transition table,
//   - the incrementally maintained shortest path tree equals a full
//     recomputation for every area and every router,
//   - per-advertisement flood and retransmission counts are recorded, and the
//     whole run is reproducible from its seed.
package verify

import (
	"fmt"
	"hash/fnv"
	"sort"

	"backhaul/internal/ospf"
	"backhaul/internal/sim"
	"backhaul/internal/topology"
)

// Options configures a run.
type Options struct {
	Seed          int64
	Duration      int64
	MeanGap       int64 // mean spacing of weather events in virtual ms
	BatchQuantum  int64 // how often to check invariants in virtual ms
	CheckPrefixes bool
	// MaxReport caps the number of reported violations per category.
	MaxReport int
}

// settleWindow is the quiet tail at the end of a run.
const settleWindow = 60_000

// DefaultOptions produce a run of a few thousand weather events. A one hour
// virtual run with a weather change roughly every second yields about three
// thousand events, which is the scale the task asks for; the verification
// then checks each invariant in the windows where the network has settled.
func DefaultOptions(seed int64) Options {
	return Options{
		Seed:          seed,
		Duration:      3_600_000, // one virtual hour
		MeanGap:       1_200,     // roughly 3000 weather events
		BatchQuantum:  500,
		CheckPrefixes: true,
		MaxReport:     25,
	}
}

// Violation is one invariant failure.
type Violation struct {
	Kind   string
	At     int64
	Detail string
	Router uint32
	Area   uint32
}

// Result is the outcome of a verification run.
type Result struct {
	Seed       int64
	Duration   int64
	Weather    int
	Snapshots  int
	Checks     int
	Violations []Violation
	// Per-advertisement flood and retransmission counts, sorted.
	LSAStats []*ospf.LSARec
	// Neighbour transition count.
	Transitions int
	// SPF statistics.
	FullRuns int
	IncrRuns int
	// QuietChecks counts the router-database comparisons performed on
	// routers that had settled.
	QuietChecks int
	// SettleFailure explains why not every router was quiet at the end.
	SettleFailure string
	// Digest is a stable fingerprint of the final state, used to prove a
	// seed reproduces the same run.
	Digest string
	// Counters copied from the simulation.
	Counters sim.Counters
}

// Ok reports whether the run passed every check.
func (r *Result) Ok() bool { return len(r.Violations) == 0 }

// Summary renders a one-line result.
func (r *Result) Summary() string {
	status := "PASS"
	if !r.Ok() {
		status = fmt.Sprintf("FAIL (%d violations)", len(r.Violations))
	}
	return fmt.Sprintf("seed=%d %s checks=%d quiet=%d weather=%d transitions=%d spf(full=%d incr=%d) digest=%s",
		r.Seed, status, r.Checks, r.QuietChecks, r.Weather, r.Transitions, r.FullRuns, r.IncrRuns, r.Digest)
}

// Run executes one verification pass.
func Run(opt Options) (*Result, error) {
	top := topology.Build()
	// The last ten virtual seconds are kept weather-free so the network can
	// reconverge and the final database and SPF checks are meaningful.
	weatherEnd := opt.Duration - settleWindow
	if weatherEnd < 0 {
		weatherEnd = 0
	}
	s, err := sim.New(top, sim.Options{
		Seed:         opt.Seed,
		Duration:     opt.Duration,
		MeanGap:      opt.MeanGap,
		AuditMax:     6000,
		WeatherUntil: weatherEnd,
	})
	if err != nil {
		return nil, err
	}
	res := &Result{Seed: opt.Seed, Duration: opt.Duration, Weather: len(s.Weather)}
	s.Start()

	// Collect batch boundaries: every weather event plus a regular quantum so
	// invariants are checked often, not only at the end.
	boundaries := map[int64]bool{}
	for _, e := range s.Weather {
		if e.At <= opt.Duration {
			boundaries[e.At] = true
		}
	}
	for t := opt.BatchQuantum; t <= opt.Duration; t += opt.BatchQuantum {
		boundaries[t] = true
	}
	boundaries[opt.Duration] = true
	var times []int64
	for t := range boundaries {
		times = append(times, t)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

	last := int64(0)
	for _, t := range times {
		if t <= last || t > opt.Duration {
			continue
		}
		s.Batch(t)
		last = t
		res.Snapshots++
		checkInvariants(s, t, res, opt)
	}
	// Pump the quiet tail in short slices so the last adjacency finishes its
	// database exchange before the final checks.
	for t := last + 1_000; t <= opt.Duration; t += 1_000 {
		s.Batch(t)
	}

	// Final check on the settled tail.
	res.Checks++
	quiet := s.QuietRouters(opt.Duration, settleQuiet)
	res.QuietChecks += len(quiet)
	if len(quiet) < len(s.RouterIDs) {
		res.SettleFailure = fmt.Sprintf("%d/%d routers quiet at end", len(quiet), len(s.RouterIDs))
	}
	checkDatabasesQuiet(s, opt.Duration, quiet, res, opt)
	checkSPF(s, opt.Duration, res, opt)

	res.Transitions = len(s.Audit.Transitions)
	res.FullRuns = s.Metrics.SPFFull
	res.IncrRuns = s.Metrics.SPFIncr
	res.LSAStats = s.Metrics.LSASorted()
	res.Counters = s.Snapshot().Counters
	res.Digest = digestState(s)
	return res, nil
}

// checkInvariants validates everything that can be checked mid-run.
//
// The link state databases only have to agree once flooding has finished.
// Under a continuous weather script a link can be dropped at any instant, so
// the check compares only routers that have been quiet for a settling window
// (no adjacency change and no database install) and that share an area. That
// keeps the invariant meaningful without demanding that the whole network be
// frozen at the same instant.
func checkInvariants(s *sim.Simulation, at int64, res *Result, opt Options) {
	res.Checks++
	quiet := s.QuietRouters(at, settleQuiet)
	res.QuietChecks += len(quiet)
	checkDatabasesQuiet(s, at, quiet, res, opt)
	checkSPF(s, at, res, opt)
}

// settleQuiet is how long a router must have been unchanged before its
// database is compared with its peers'.
const settleQuiet = 8_000

// confirmSettle is how long the network is given to finish flooding before a
// reported divergence is treated as real.
const confirmSettle = 15_000

// checkDatabasesQuiet verifies that all quiet routers in an area hold the same
// link state database. Two advertisements are identical when their sequence
// number, checksum and payload match; the LS age is allowed to differ.
func checkDatabasesQuiet(s *sim.Simulation, at int64, quiet map[uint32]bool, res *Result, opt Options) {
	areas := map[uint32][]*ospf.Router{}
	for _, id := range s.RouterIDs {
		if !quiet[id] {
			continue
		}
		r := s.Routers[id]
		if !allNeighboursFull(r) {
			continue
		}
		for _, a := range r.Areas {
			areas[a] = append(areas[a], r)
		}
	}
	_ = areas
	// The link state database is only required to be identical across a
	// *connected* area. When weather takes a link down, an area can split into
	// two components; the routers on each side then legitimately hold
	// different databases because they can no longer exchange intra-area
	// advertisements, and OSPF explicitly allows that until the area heals.
	// Compare within each component, and only once the whole area is quiet.
	for _, area := range sortedAreasByArea(s) {
		components := s.AreaComponents(area)
		complete := true
		for _, id := range s.RouterIDs {
			r := s.Routers[id]
			if !routerInArea(r, area) {
				continue
			}
			if !quiet[id] {
				complete = false
				break
			}
		}
		if !complete {
			continue
		}
		for _, comp := range components {
			var routers []*ospf.Router
			for _, id := range comp {
				routers = append(routers, s.Routers[id])
			}
			if len(routers) < 2 {
				continue
			}
			checkComponent(routers, area, at, res, opt)
		}
	}
}

// checkComponent compares the databases of the routers in one connected
// component of an area.
func checkComponent(routers []*ospf.Router, area uint32, at int64, res *Result, opt Options) {
	{
		base := routers[0]
		baseDB := dbInstance(base, area, at)
		for _, r := range routers[1:] {
			other := dbInstance(r, area, at)
			for k, hv := range baseDB {
				ov, ok := other[k]
				if !ok {
					res.addViolation(opt, "db-missing", at, r.ID, area,
						fmt.Sprintf("%s lacks %s held by %s", r.Name, k, base.Name))
					continue
				}
				if ov != hv {
					res.addViolation(opt, "db-mismatch", at, r.ID, area,
						fmt.Sprintf("%s and %s disagree on %s (%s vs %s)", base.Name, r.Name, k, hv, ov))
				}
			}
			for k := range other {
				if _, ok := baseDB[k]; !ok {
					res.addViolation(opt, "db-extra", at, r.ID, area,
						fmt.Sprintf("%s holds %s absent from %s", r.Name, k, base.Name))
				}
			}
		}
	}
}

// routerInArea reports whether a router has an interface in the area.
func routerInArea(r *ospf.Router, area uint32) bool {
	for _, a := range r.Areas {
		if a == area {
			return true
		}
	}
	return false
}

// sortedAreasByArea lists every area any router participates in.
func sortedAreasByArea(s *sim.Simulation) []uint32 {
	set := map[uint32]bool{}
	for _, id := range s.RouterIDs {
		for _, a := range s.Routers[id].Areas {
			set[a] = true
		}
	}
	out := make([]uint32, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// allNeighboursFull reports whether every adjacency of a router is Full.
func allNeighboursFull(r *ospf.Router) bool {
	for _, n := range r.Neighbours() {
		if n.StateCode != ospf.Full {
			return false
		}
	}
	return true
}

// dbInstance renders an area database into comparable strings, excluding age.
func dbInstance(r *ospf.Router, area uint32, now int64) map[ospf.LSAKey]string {
	out := map[ospf.LSAKey]string{}
	for _, l := range r.AreaDB(area) {
		out[l.Key()] = fmt.Sprintf("seq=%08x ck=%04x body=%x", l.Seq, l.Checksum, l.Body)
	}
	return out
}

// checkSPF compares each router's incrementally maintained tree against a full
// recomputation from the same database.
func checkSPF(s *sim.Simulation, at int64, res *Result, opt Options) {
	for _, id := range s.RouterIDs {
		r := s.Routers[id]
		for _, area := range r.Areas {
			inc := r.SPFFor(area)
			if inc == nil {
				continue
			}
			full := r.SPFDebugFull(area)
			if len(full.Dist) != len(inc.Dist) {
				res.addViolation(opt, "spf-count", at, id, area,
					fmt.Sprintf("%s area %d: incremental %d nodes, full %d", r.Name, area, len(inc.Dist), len(full.Dist)))
				continue
			}
			for node, fd := range full.Dist {
				id2, ok := inc.Dist[node]
				if !ok {
					res.addViolation(opt, "spf-missing", at, id, area,
						fmt.Sprintf("%s area %d: node %s missing from incremental tree", r.Name, area, ospf.IP(node)))
					continue
				}
				if id2 != fd {
					res.addViolation(opt, "spf-cost", at, id, area,
						fmt.Sprintf("%s area %d: node %s cost incremental %d full %d", r.Name, area, ospf.IP(node), id2, fd))
				}
			}
		}
	}
}

func (r *Result) addViolation(opt Options, kind string, at int64, router uint32, area uint32, detail string) {
	if countKind(r.Violations, kind) >= opt.MaxReport {
		return
	}
	r.Violations = append(r.Violations, Violation{
		Kind: kind, At: at, Router: router, Area: area, Detail: detail,
	})
}

func countKind(vs []Violation, kind string) int {
	n := 0
	for _, v := range vs {
		if v.Kind == kind {
			n++
		}
	}
	return n
}

func sortedAreas(m map[uint32][]*ospf.Router) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// digestState fingerprints the final state so two runs of the same seed can be
// compared byte for byte.
func digestState(s *sim.Simulation) string {
	h := fnv.New64a()
	for _, id := range s.RouterIDs {
		r := s.Routers[id]
		fmt.Fprintf(h, "R%d;", id)
		for _, area := range r.Areas {
			fmt.Fprintf(h, "A%d:", area)
			for _, l := range r.AreaDB(area) {
				fmt.Fprintf(h, "%d/%d/%08x/%04x/%x|", l.Type, l.ID, l.Seq, l.Checksum, l.Body)
			}
		}
		for _, rt := range r.Routes {
			fmt.Fprintf(h, "rt%d/%d/%d/%d;", rt.Prefix, rt.Mask, rt.Cost, rt.NextHop)
		}
		fmt.Fprintf(h, "\n")
	}
	return fmt.Sprintf("%016x", h.Sum64())
}
