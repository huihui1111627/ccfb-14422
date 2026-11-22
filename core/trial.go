package core

import "fmt"

// RunConvergenceTrial builds the random topology for a seed, applies ops
// random link changes, and after each checks every router's RIB against the
// reference model. It returns per-op convergence statistics.
type ConvStat struct {
	Events int64
	Ticks  int64
}

func RunConvergenceTrial(seed int64, ops int) ([]ConvStat, error) {
	cfg := DefaultConfig()
	cfg.Verify = true // iSPF cross-checked against full SPF on every run
	w := NewWorld(seed, cfg)
	BuildRandomTopology(w, DefaultTopoSpec())
	w.Boot()
	if _, conv := w.RunQuiescent(); conv < 0 {
		return nil, fmt.Errorf("initial convergence failed")
	}
	if diff := w.CompareRIBs(); diff != "" {
		return nil, fmt.Errorf("initial RIB mismatch:\n%s", diff)
	}
	stats := make([]ConvStat, 0, ops)
	for i := 0; i < ops; i++ {
		op := w.RandomLinkOp()
		ev, conv := w.RunQuiescent()
		stats = append(stats, ConvStat{Events: ev, Ticks: conv})
		if diff := w.CompareRIBs(); diff != "" {
			return stats, fmt.Errorf("op %d (%s) RIB mismatch:\n%s", i, op, diff)
		}
		if diff := w.CheckExternalFlooding(); diff != "" {
			return stats, fmt.Errorf("op %d (%s) external flooding:\n%s", i, op, diff)
		}
	}
	return stats, nil
}
