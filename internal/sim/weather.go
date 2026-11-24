package sim

import (
	"math"
	"math/rand"
)

// LinkState is the weather-driven condition of one physical link.
type LinkState struct {
	ID string
	// Up is false when the link is completely down.
	Up bool
	// Cost is the OSPF cost currently advertised.
	Cost uint16
	// BaseCost is the clear-weather cost.
	BaseCost uint16
	// LossPct is the modelled packet loss percentage.
	Loss float64
	// DelayMs is the one-way propagation delay.
	DelayMs int64
	// Since is the virtual time of the last change.
	Since int64
	// Events counts weather events applied to this link.
	Events int
	// LastWeather names the most recent weather event.
	LastWeather string
}

// LinkStateName renders a compact weather description for the page.
func (s *LinkState) Name() string {
	switch {
	case !s.Up:
		return "down"
	case s.Loss >= 25:
		return "storm"
	case s.Loss >= 10:
		return "degraded"
	case s.Loss > 0:
		return "light-loss"
	default:
		return "clear"
	}
}

// WeatherEvent is one entry of the pre-generated weather script.
type WeatherEvent struct {
	At     int64   `json:"at"`
	Link   string  `json:"link"`
	Kind   string  `json:"kind"`
	Delay  int64   `json:"delay"`
	Loss   float64 `json:"loss"`
	Cost   uint16  `json:"cost"`
	Up     bool    `json:"up"`
	Reason string  `json:"reason"`
}

var weatherKinds = []string{
	"clear", "light-loss", "degraded", "storm", "outage",
}

// GenerateWeather builds a deterministic script of weather events. The same
// seed and topology always produce the same script, which is what makes the
// replay reproducible.
func GenerateWeather(seed int64, links []string, start, duration int64, meanGap int64) []WeatherEvent {
	rng := rand.New(rand.NewSource(seed))
	var out []WeatherEvent
	at := start
	for at < start+duration {
		at += int64(float64(meanGap) * (0.4 + 0.9*rng.Float64()))
		link := links[rng.Intn(len(links))]
		kind := weatherKinds[rng.Intn(len(weatherKinds))]
		ev := WeatherEvent{At: at, Link: link, Kind: kind}
		switch kind {
		case "clear":
			ev.Delay = 10 + int64(rng.Intn(20))
			ev.Loss = 0
			ev.Cost = 10
			ev.Up = true
			ev.Reason = "window lifted"
		case "light-loss":
			ev.Delay = 30 + int64(rng.Intn(60))
			ev.Loss = 1 + rng.Float64()*8
			ev.Cost = 20 + uint16(rng.Intn(40))
			ev.Up = true
			ev.Reason = "fog and humidity"
		case "degraded":
			ev.Delay = 100 + int64(rng.Intn(250))
			ev.Loss = 5 + rng.Float64()*8
			ev.Cost = 60 + uint16(rng.Intn(120))
			ev.Up = true
			ev.Reason = "rain fade"
		case "storm":
			ev.Delay = 400 + int64(rng.Intn(600))
			ev.Loss = 12 + rng.Float64()*13
			ev.Cost = 200 + uint16(rng.Intn(200))
			ev.Up = true
			ev.Reason = "heavy sea state"
		case "outage":
			ev.Delay = 0
			ev.Loss = 100
			ev.Cost = 0
			ev.Up = false
			ev.Reason = "link failure"
		}
		out = append(out, ev)
	}
	return out
}

// ApplyWeather mutates a link state from an event.
func (s *LinkState) Apply(e WeatherEvent, now int64) {
	s.Up = e.Up
	if e.Up {
		s.Cost = e.Cost
		if s.Cost == 0 {
			s.Cost = s.BaseCost
		}
		s.Loss = math.Min(e.Loss, 99)
		s.DelayMs = e.Delay
		if s.DelayMs <= 0 {
			s.DelayMs = 10
		}
	} else {
		s.Cost = s.BaseCost
		s.Loss = 100
		s.DelayMs = 0
	}
	s.Since = now
	s.Events++
	s.LastWeather = e.Kind
}
