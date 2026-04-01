package transport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kimitoboku/dnstap-filter/internal/stats"
)

func TestParseStatsFormat(t *testing.T) {
	tests := []struct {
		address string
		wantFmt statsFormat
		wantErr bool
	}{
		{"-", statsFormatJSON, false},
		{"report.html", statsFormatHTML, false},
		{"report.htm", statsFormatHTML, false},
		{"report.json", statsFormatJSON, false},
		{"report.xml", statsFormatXML, false},
		{"report.md", statsFormatMarkdown, false},
		{"report.markdown", statsFormatMarkdown, false},
		{"report.txt", 0, true},
		{"report", 0, true},
		{"/path/to/REPORT.HTML", statsFormatHTML, false},
	}
	for _, tt := range tests {
		f, err := parseStatsFormat(tt.address)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseStatsFormat(%q): expected error", tt.address)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseStatsFormat(%q): unexpected error: %v", tt.address, err)
			continue
		}
		if f != tt.wantFmt {
			t.Errorf("parseStatsFormat(%q): got %v, want %v", tt.address, f, tt.wantFmt)
		}
	}
}

func TestNewStatsOutput_Valid(t *testing.T) {
	c := stats.NewCollector(stats.CollectorOptions{TopN: 5})
	so, err := NewStatsOutput(c, "report.json", 60*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if so == nil {
		t.Fatal("expected non-nil StatsOutput")
	}
	if so.windowInterval != 60*time.Second {
		t.Errorf("expected 60s, got %v", so.windowInterval)
	}
}

func TestNewStatsOutput_DefaultInterval(t *testing.T) {
	c := stats.NewCollector(stats.CollectorOptions{TopN: 5})
	so, err := NewStatsOutput(c, "report.json", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if so.windowInterval != 60*time.Second {
		t.Errorf("expected default 60s, got %v", so.windowInterval)
	}
}

func TestNewStatsOutput_InvalidFormat(t *testing.T) {
	c := stats.NewCollector(stats.CollectorOptions{TopN: 5})
	_, err := NewStatsOutput(c, "report.txt", 60*time.Second)
	if err == nil {
		t.Fatal("expected error for unsupported extension")
	}
}

func TestStatsOutput_GetOutputChannel(t *testing.T) {
	c := stats.NewCollector(stats.CollectorOptions{TopN: 5})
	so, _ := NewStatsOutput(c, "report.json", 60*time.Second)
	ch := so.GetOutputChannel()
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}
}

func runStatsOutputAndCheck(t *testing.T, ext string, validate func([]byte)) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "report"+ext)

	c := stats.NewCollector(stats.CollectorOptions{TopN: 5})
	so, err := NewStatsOutput(c, path, 60*time.Second)
	if err != nil {
		t.Fatalf("NewStatsOutput: %v", err)
	}

	go so.RunOutputLoop()
	so.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("report file not created: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("report file is empty")
	}
	if validate != nil {
		validate(data)
	}
}

func TestStatsOutput_WriteReport_JSON(t *testing.T) {
	runStatsOutputAndCheck(t, ".json", func(data []byte) {
		var v map[string]interface{}
		if err := json.Unmarshal(data, &v); err != nil {
			t.Errorf("invalid JSON output: %v", err)
		}
	})
}

func TestStatsOutput_WriteReport_HTML(t *testing.T) {
	runStatsOutputAndCheck(t, ".html", func(data []byte) {
		if !strings.Contains(string(data), "<!DOCTYPE html>") {
			t.Error("expected HTML output with DOCTYPE")
		}
	})
}

func TestStatsOutput_WriteReport_XML(t *testing.T) {
	runStatsOutputAndCheck(t, ".xml", func(data []byte) {
		if !strings.Contains(string(data), "<dnstap-filter-stats>") {
			t.Error("expected XML output with root element")
		}
	})
}

func TestStatsOutput_WriteReport_Markdown(t *testing.T) {
	runStatsOutputAndCheck(t, ".md", func(data []byte) {
		if !strings.Contains(string(data), "# dnstap-filter") {
			t.Error("expected Markdown heading")
		}
	})
}

func TestStatsOutput_WriteReport_Stdout(t *testing.T) {
	// path="-" writes to stdout; just verify the loop runs cleanly
	c := stats.NewCollector(stats.CollectorOptions{TopN: 5})
	so, err := NewStatsOutput(c, "-", 60*time.Second)
	if err != nil {
		t.Fatalf("NewStatsOutput: %v", err)
	}
	go so.RunOutputLoop()
	so.Close()
}

func TestStatsOutput_DropsFrames(t *testing.T) {
	// Frames sent to StatsOutput should be silently discarded.
	dir := t.TempDir()
	c := stats.NewCollector(stats.CollectorOptions{TopN: 5})
	so, _ := NewStatsOutput(c, filepath.Join(dir, "r.json"), 60*time.Second)

	go so.RunOutputLoop()
	so.GetOutputChannel() <- []byte("frame1")
	so.GetOutputChannel() <- []byte("frame2")
	so.Close()
}

func TestStatsOutput_TickerRotates(t *testing.T) {
	dir := t.TempDir()
	c := stats.NewCollector(stats.CollectorOptions{TopN: 5})
	// Use a very short window to trigger rotation quickly.
	so, err := NewStatsOutput(c, filepath.Join(dir, "r.json"), 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewStatsOutput: %v", err)
	}

	go so.RunOutputLoop()
	// Wait for at least one tick to fire.
	time.Sleep(60 * time.Millisecond)
	so.Close()

	// Should have rotated at least once → history has entries.
	hist := c.History()
	if len(hist) < 1 {
		t.Error("expected at least 1 completed window after ticker fires")
	}
}

// Verify that writeReport handles a non-writable path gracefully (no panic).
func TestStatsOutput_WriteReport_BadPath(t *testing.T) {
	c := stats.NewCollector(stats.CollectorOptions{TopN: 5})
	so := &StatsOutput{
		collector:      c,
		path:           "/nonexistent-dir/report.json",
		format:         statsFormatJSON,
		windowInterval: 60 * time.Second,
		ch:             make(chan []byte, 1),
		done:           make(chan struct{}),
	}
	// writeReport should log to stderr and return without panic.
	so.writeReport()
}

// suppress unused import
var _ = bytes.NewBuffer
