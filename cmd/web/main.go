// Command web serves the live topology, neighbour, link state database and
// routing table views for the simulated lighthouse network.
package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"backhaul/internal/sim"
	"backhaul/internal/topology"
)

type server struct {
	mu    sync.Mutex
	sim   *sim.Simulation
	seed  int64
	dur   int64
	gap   int64
	step  int64 // virtual ms advanced per advance call
	until int64
	done  bool
}

func main() {
	var (
		addr = flag.String("addr", "127.0.0.1:8099", "listen address")
		seed = flag.Int64("seed", 42, "weather seed")
		dur  = flag.Int64("duration", 3_600_000, "virtual run length in ms")
		gap  = flag.Int64("gap", 20_000, "mean weather event spacing in ms")
		step = flag.Int64("step", 20_000, "virtual ms advanced per tick")
	)
	flag.Parse()

	s, err := sim.New(topology.Build(), sim.Options{
		Seed: *seed, Duration: *dur, MeanGap: *gap, AuditMax: 4000,
	})
	if err != nil {
		log.Fatal(err)
	}
	s.Start()

	srv := &server{sim: s, seed: *seed, dur: *dur, gap: *gap, step: *step}
	// Converge the network before serving so the first view is meaningful.
	for t := int64(0); t < 400_000 && t < *dur; t += 5_000 {
		s.Batch(t)
	}
	srv.until = 400_000

	http.HandleFunc("/", srv.handleIndex)
	http.HandleFunc("/api/state", srv.handleState)
	http.HandleFunc("/api/advance", srv.handleAdvance)
	http.HandleFunc("/api/reset", srv.handleReset)
	log.Printf("serving on http://%s (seed %d)", *addr, *seed)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

func (s *server) handleState(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	snap := s.sim.Snapshot()
	seed, until, dur := s.seed, s.until, s.dur
	done := until >= dur
	s.mu.Unlock()
	out := map[string]any{
		"snapshot": snap,
		"seed":     seed,
		"until":    until,
		"duration": dur,
		"done":     done,
	}
	writeJSON(w, out)
}

func (s *server) handleAdvance(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.until < s.dur {
		next := s.until + s.step
		if next > s.dur {
			next = s.dur
		}
		s.sim.Batch(next)
		s.until = next
	}
	until := s.until
	s.mu.Unlock()
	writeJSON(w, map[string]any{"until": until, "duration": s.dur})
}

func (s *server) handleReset(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	seed := s.seed
	if v := q.Get("seed"); v != "" {
		fmt.Sscanf(v, "%d", &seed)
	}
	gap := s.gap
	if v := q.Get("gap"); v != "" {
		fmt.Sscanf(v, "%d", &gap)
	}
	ns, err := sim.New(topology.Build(), sim.Options{
		Seed: seed, Duration: s.dur, MeanGap: gap, AuditMax: 4000,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ns.Start()
	s.mu.Lock()
	s.sim = ns
	s.seed = seed
	s.gap = gap
	s.until = 0
	for t := int64(0); t < 400_000 && t < s.dur; t += 5_000 {
		ns.Batch(t)
	}
	s.until = 400_000
	s.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "seed": seed, "until": s.until})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

//go:embed index.html
var indexHTML string

var _ = time.Now
