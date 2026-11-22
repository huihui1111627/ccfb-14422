package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	_ "embed"
	"ospfsim/core"
)

//go:embed index.html
var indexHTML []byte

// Server wraps a World with a mutex for concurrent web access.
type Server struct {
	mu      sync.RWMutex
	w       *core.World
	weather bool
}

func main() {
	addr := ":8080"
	seed := int64(20240520)
	cfg := core.DefaultConfig()
	cfg.Verify = false
	w := core.NewWorld(seed, cfg)
	core.BuildRandomTopology(w, core.DefaultTopoSpec())
	s := &Server{w: w, weather: true}
	w.Boot()

	// real-time event loop: 1 world tick = 20ms
	go func() {
		tick := time.NewTicker(20 * time.Millisecond)
		weather := time.NewTicker(2500 * time.Millisecond)
		for {
			select {
			case <-tick.C:
				s.mu.Lock()
				target := w.Now + 1
				for t := w.PeekTime(); t >= 0 && t <= target; t = w.PeekTime() {
					w.Step()
				}
				if w.Now < target {
					w.Now = target
				}
				s.mu.Unlock()
			case <-weather.C:
				s.mu.Lock()
				if s.weather {
					op := w.RandomLinkOp()
					_ = op
				}
				s.mu.Unlock()
			}
		}
	}()

	http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write(indexHTML)
	})
	http.HandleFunc("/api/state", s.handleState)
	http.HandleFunc("/api/link/", s.handleLink)
	http.HandleFunc("/api/weather", s.handleWeather)
	log.Printf("OSPF 模拟器运行中: http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

type nbrView struct {
	Peer  string `json:"peer"`
	State string `json:"state"`
	Stuck string `json:"stuck,omitempty"`
	VL    bool   `json:"vl,omitempty"`
	Area  int    `json:"area"`
}

type lsaView struct {
	Key  string `json:"key"`
	Seq  uint32 `json:"seq"`
	Age  int64  `json:"age"`
	Self bool   `json:"self,omitempty"`
	Desc string `json:"desc"`
}

type routeView struct {
	Prefix string   `json:"prefix"`
	Type   string   `json:"type"`
	Cost   int      `json:"cost"`
	Via    []string `json:"via"`
}

type routerView struct {
	ID    string      `json:"id"`
	Areas []int       `json:"areas"`
	ABR   bool        `json:"abr"`
	ASBR  bool        `json:"asbr"`
	Nbrs  []nbrView   `json:"nbrs"`
	LSDB  []lsaView   `json:"lsdb"`
	RIB   []routeView `json:"rib"`
}

type linkView struct {
	ID   int    `json:"id"`
	A    string `json:"a"`
	B    string `json:"b"`
	Area int    `json:"area"`
	Cost int    `json:"cost"`
	Up   bool   `json:"up"`
	MTUA int    `json:"mtuA"`
	MTUB int    `json:"mtuB"`
}

func (s *Server) handleState(rw http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w := s.w
	out := map[string]interface{}{}
	out["now"] = w.Now
	var links []linkView
	for _, l := range w.Links {
		links = append(links, linkView{
			ID: l.ID, A: core.IDStr(l.A.R.ID), B: core.IDStr(l.B.R.ID),
			Area: int(l.A.Area), Cost: l.Cost, Up: l.Up,
			MTUA: l.A.MTU, MTUB: l.B.MTU,
		})
	}
	out["links"] = links
	var vls []map[string]interface{}
	for _, vl := range w.VLs {
		na := w.Routers[vl.A].DebugVL(vl)
		nb := w.Routers[vl.B].DebugVL(vl)
		vls = append(vls, map[string]interface{}{
			"a": core.IDStr(vl.A), "b": core.IDStr(vl.B), "transit": int(vl.Transit),
			"upA": na, "upB": nb,
		})
	}
	out["vlinks"] = vls
	areas := map[int]map[string]bool{}
	for a, ac := range w.Areas {
		areas[int(a)] = map[string]bool{"stub": ac.Stub, "totallyStub": ac.TotallyStub}
	}
	out["areas"] = areas
	var routers []routerView
	for _, r := range w.SortedRouters() {
		rv := routerView{ID: core.IDStr(r.ID), ABR: r.IsABR(), ASBR: r.ASBR}
		for _, a := range r.SortedAreas() {
			rv.Areas = append(rv.Areas, int(a))
		}
		for _, n := range r.AllNeighbors() {
			rv.Nbrs = append(rv.Nbrs, nbrView{
				Peer: core.IDStr(n.RtrID), State: n.State.String(),
				Stuck: n.StuckReason, VL: n.VL != nil, Area: int(n.Area()),
			})
		}
		for _, area := range r.SortedAreas() {
			for _, k := range core.SortedLSAKeys(r.LSDB[area]) {
				l := r.LSDB[area][k]
				rv.LSDB = append(rv.LSDB, lsaView{
					Key: fmt.Sprintf("area%d %s", area, k),
					Seq: l.Seq, Age: l.Age(w.Now), Self: l.Self,
					Desc: core.LSADescribe(l),
				})
			}
		}
		for _, k := range core.SortedLSAKeys(r.ExtDB) {
			l := r.ExtDB[k]
			rv.LSDB = append(rv.LSDB, lsaView{
				Key: "ext " + k.String(), Seq: l.Seq, Age: l.Age(w.Now),
				Self: l.Self, Desc: core.LSADescribe(l),
			})
		}
		for _, p := range core.SortedRIBKeys(r.RIB) {
			rt := r.RIB[p]
			var via []string
			for _, nh := range rt.NextHops {
				via = append(via, core.IDStr(nh))
			}
			rv.RIB = append(rv.RIB, routeView{
				Prefix: p.String(), Type: rt.Type.String(), Cost: rt.Cost, Via: via,
			})
		}
		routers = append(routers, rv)
	}
	out["routers"] = routers
	var log2 []string
	if n := len(w.ChangeLog); n > 30 {
		log2 = w.ChangeLog[n-30:]
	} else {
		log2 = w.ChangeLog
	}
	out["changelog"] = log2
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(out)
}

func (s *Server) handleLink(rw http.ResponseWriter, r *http.Request) {
	// /api/link/{id}/toggle or /api/link/{id}/cost?c=N
	s.mu.Lock()
	defer s.mu.Unlock()
	var id int
	var action string
	fmt.Sscanf(r.URL.Path, "/api/link/%d/%s", &id, &action)
	if id < 0 || id >= len(s.w.Links) {
		http.Error(rw, "bad link", 400)
		return
	}
	l := s.w.Links[id]
	switch action {
	case "toggle":
		s.w.SetLinkUp(l, !l.Up)
	case "cost":
		c, _ := strconv.Atoi(r.URL.Query().Get("c"))
		if c <= 0 || c > 10000 {
			http.Error(rw, "bad cost", 400)
			return
		}
		s.w.SetLinkCost(l, c)
	}
	rw.WriteHeader(204)
}

func (s *Server) handleWeather(rw http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.weather = r.URL.Query().Get("on") == "1"
	json.NewEncoder(rw).Encode(map[string]bool{"weather": s.weather})
}
