package stats

import (
	"encoding/json"
	"io"
)

// statsReport is the top-level JSON structure for a stats report.
type statsReport struct {
	Windows []*Snapshot `json:"windows"`
	AllTime *Snapshot   `json:"all_time"`
}

// RenderJSON writes the stats report as JSON to w.
func RenderJSON(w io.Writer, windows []*Snapshot, allTime *Snapshot) error {
	report := statsReport{
		Windows: windows,
		AllTime: allTime,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
