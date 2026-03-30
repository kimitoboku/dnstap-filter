package stats

import "time"

// window accumulates statistics for a single time interval.
type window struct {
	start       time.Time
	domains     map[string]uint64
	qtypes      map[uint16]uint64
	rcodes      map[int]uint64
	clientIPs   map[string]uint64
	totalFrames uint64
}

func newWindow(start time.Time) *window {
	return &window{
		start:     start,
		domains:   make(map[string]uint64),
		qtypes:    make(map[uint16]uint64),
		rcodes:    make(map[int]uint64),
		clientIPs: make(map[string]uint64),
	}
}

// snapshot converts the window into a frozen Snapshot, truncating
// distributions to topN entries where appropriate.
func (w *window) snapshot(end time.Time, topN int) *Snapshot {
	s := &Snapshot{
		Start:       w.start,
		End:         end,
		TotalFrames: w.totalFrames,
		QtypeDist:   rankAll(w.qtypes, func(k uint16) string { return qtypeString(k) }),
		RcodeDist:   rankAll(w.rcodes, func(k int) string { return rcodeString(k) }),
		TopDomains:  rankTopN(w.domains, topN),
		ClientIPs:   rankTopN(w.clientIPs, topN),
	}
	return s
}
