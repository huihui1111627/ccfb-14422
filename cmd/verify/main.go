// Command verify replays a fixed-seed weather script through the OSPF
// simulation and reports whether every protocol invariant holds, along with
// per-advertisement flooding statistics and a final-state digest that proves
// the run is reproducible.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"backhaul/internal/verify"
)

func main() {
	var (
		seed      = flag.Int64("seed", 42, "random seed for the weather replay")
		seeds     = flag.String("seeds", "", "comma separated list of seeds to run")
		duration  = flag.Int64("duration", 3_600_000, "virtual run length in milliseconds")
		meanGap   = flag.Int64("gap", 1_200, "mean spacing of weather events in milliseconds")
		quantum   = flag.Int64("quantum", 500, "invariant check quantum in milliseconds")
		jsonOut   = flag.Bool("json", false, "emit the result as JSON")
		statsOut  = flag.String("stats", "", "write per-LSA flood statistics to this file")
		maxReport = flag.Int("max", 25, "maximum violations reported per category")
	)
	flag.Parse()

	seedsToRun := []int64{*seed}
	if *seeds != "" {
		seedsToRun = parseSeeds(*seeds)
	}

	overallOK := true
	var results []*verify.Result
	for _, sd := range seedsToRun {
		opt := verify.Options{
			Seed: sd, Duration: *duration, MeanGap: *meanGap,
			BatchQuantum: *quantum, MaxReport: *maxReport,
		}
		res, err := verify.Run(opt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seed %d: %v\n", sd, err)
			os.Exit(2)
		}
		results = append(results, res)
		overallOK = overallOK && res.Ok()
		if !*jsonOut {
			fmt.Println(res.Summary())
			for _, v := range res.Violations {
				fmt.Printf("  %-12s t=%d area=%d %s\n", v.Kind, v.At, v.Area, v.Detail)
			}
			if res.SettleFailure != "" {
				fmt.Printf("  note: %s\n", res.SettleFailure)
			}
		}
	}

	if *statsOut != "" && len(results) > 0 {
		if err := writeStats(*statsOut, results[0]); err != nil {
			fmt.Fprintf(os.Stderr, "stats: %v\n", err)
			os.Exit(2)
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
	}
	if !overallOK {
		os.Exit(1)
	}
	fmt.Printf("all %d seed(s) passed\n", len(results))
}

func parseSeeds(s string) []int64 {
	var out []int64
	var cur int64
	have := false
	for _, r := range s {
		switch {
		case r == ',':
			out = append(out, cur)
			cur, have = 0, false
		case r >= '0' && r <= '9':
			cur = cur*10 + int64(r-'0')
			have = true
		}
	}
	if have {
		out = append(out, cur)
	}
	return out
}

type statsFile struct {
	Seed     int64           `json:"seed"`
	Digest   string          `json:"digest"`
	Counters interface{}     `json:"counters"`
	LSAs     []*statLSAEntry `json:"lsas"`
}

type statLSAEntry struct {
	Type          string `json:"type"`
	LinkID        string `json:"link_id"`
	AdvRtr        string `json:"adv_rtr"`
	Originated    int    `json:"originated"`
	Flooded       int    `json:"flooded"`
	Retransmitted int    `json:"retransmitted"`
	Received      int    `json:"received"`
}

func writeStats(path string, res *verify.Result) error {
	var entries []*statLSAEntry
	for _, r := range res.LSAStats {
		entries = append(entries, &statLSAEntry{
			Type: r.Type.String(), LinkID: ip(r.Key.ID), AdvRtr: ip(r.AdvRtr),
			Originated: r.Originated, Flooded: r.Flooded,
			Retransmitted: r.Retransmitted, Received: r.Received,
		})
	}
	f := statsFile{Seed: res.Seed, Digest: res.Digest, Counters: res.Counters, LSAs: entries}
	b, _ := json.MarshalIndent(f, "", "  ")
	return os.WriteFile(path, b, 0o644)
}

func ip(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
