package core

import (
	"fmt"
	"sort"
	"strings"
)

// SortedLSAKeys exports sorted LSA keys for the UI.
func SortedLSAKeys(m map[LSAKey]*LSA) []LSAKey { return sortedKeys(m) }

// SortedRIBKeys exports sorted RIB prefixes for the UI.
func SortedRIBKeys(m map[Prefix]*Route) []Prefix { return sortedPrefixes(m) }

// LSADescribe renders a short human-readable summary of an LSA.
func LSADescribe(l *LSA) string {
	switch b := l.Body.(type) {
	case *RouterLSABody:
		var parts []string
		for _, lk := range b.Links {
			switch lk.Type {
			case LinkP2P:
				parts = append(parts, fmt.Sprintf("p2p→%s c%d", ipStr(lk.ID), lk.Metric))
			case LinkStub:
				parts = append(parts, fmt.Sprintf("stub %s", ipStr(lk.ID)))
			case LinkVirtual:
				parts = append(parts, fmt.Sprintf("vlink→%s c%d", ipStr(lk.ID), lk.Metric))
			}
		}
		return strings.Join(parts, "; ")
	case *SummaryLSABody:
		return fmt.Sprintf("summary %s metric %d", b.Prefix, b.Metric)
	case *ExternalLSABody:
		return fmt.Sprintf("external %s metric %d (E2)", b.Prefix, b.Metric)
	}
	return ""
}

// DebugVL reports whether the router's end of the virtual link is up.
func (r *Router) DebugVL(vl *VLink) bool {
	n := r.vlNeighbor(vl)
	return n != nil && n.VLUp
}

// SortedLinkIDs is a helper for deterministic UI output.
func SortedLinkIDs(links []*Link) []int {
	ids := make([]int, len(links))
	for i, l := range links {
		ids[i] = l.ID
	}
	sort.Ints(ids)
	return ids
}
