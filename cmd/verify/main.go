package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"ospfsim/core"
)

// verify runs the large-scale randomized convergence trial: random multi-area
// topology, thousands of link events, and after each event every router's RIB
// is compared against a from-scratch Dijkstra computation over the global
// topology. iSPF is cross-checked against full SPF inside the routers.
func main() {
	seed := flag.Int64("seed", 1, "base random seed")
	seeds := flag.Int("seeds", 5, "number of seeds to try")
	ops := flag.Int("ops", 1000, "link operations per seed")
	flag.Parse()

	fail := false
	for s := int64(0); s < int64(*seeds); s++ {
		sd := *seed + s
		start := time.Now()
		stats, err := core.RunConvergenceTrial(sd, *ops)
		el := time.Since(start)
		if err != nil {
			fmt.Printf("seed %d: FAIL after %d ops: %v\n", sd, len(stats), err)
			fail = true
			continue
		}
		var totEv, totTicks, maxEv, maxTicks int64
		for _, st := range stats {
			totEv += st.Events
			totTicks += st.Ticks
			if st.Events > maxEv {
				maxEv = st.Events
			}
			if st.Ticks > maxTicks {
				maxTicks = st.Ticks
			}
		}
		n := int64(len(stats))
		fmt.Printf("seed %d: %d ops OK in %v | events/op avg=%d max=%d | ticks/op avg=%d max=%d\n",
			sd, len(stats), el.Round(time.Millisecond),
			totEv/n, maxEv, totTicks/n, maxTicks)
	}
	// reproducibility: same seed twice must give identical statistics
	st1, err1 := core.RunConvergenceTrial(*seed, 200)
	st2, err2 := core.RunConvergenceTrial(*seed, 200)
	if err1 != nil || err2 != nil {
		fmt.Printf("reproducibility run failed: %v %v\n", err1, err2)
		fail = true
	} else {
		for i := range st1 {
			if st1[i] != st2[i] {
				fmt.Printf("REPRODUCIBILITY FAIL at op %d: %+v vs %+v\n", i, st1[i], st2[i])
				fail = true
				break
			}
		}
		if !fail {
			fmt.Println("reproducibility: identical results for same seed")
		}
	}
	if fail {
		os.Exit(1)
	}
	fmt.Println("ALL OK")
}
