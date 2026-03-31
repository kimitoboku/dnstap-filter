package transport

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kimitoboku/dnstap-filter/internal/stats"
)

type statsFormat int

const (
	statsFormatJSON statsFormat = iota
	statsFormatHTML
	statsFormatXML
	statsFormatMarkdown
)

// StatsOutput implements dnstap.Output. It manages the rotation ticker
// and writes the final report on Close. The actual statistics recording
// is done upstream in the filter goroutine via collector.Record().
type StatsOutput struct {
	collector *stats.Collector
	path      string
	format    statsFormat
	ch        chan []byte
	done      chan struct{}
}

// NewStatsOutput creates a new StatsOutput. The address is the output path;
// the format is determined by file extension (.html, .xml, .json).
// Use "-" for stdout (JSON format).
func NewStatsOutput(collector *stats.Collector, address string) (*StatsOutput, error) {
	format, err := parseStatsFormat(address)
	if err != nil {
		return nil, err
	}
	return &StatsOutput{
		collector: collector,
		path:      address,
		format:    format,
		ch:        make(chan []byte, 32),
		done:      make(chan struct{}),
	}, nil
}

func parseStatsFormat(address string) (statsFormat, error) {
	if address == "-" {
		return statsFormatJSON, nil
	}
	ext := strings.ToLower(filepath.Ext(address))
	switch ext {
	case ".html", ".htm":
		return statsFormatHTML, nil
	case ".json":
		return statsFormatJSON, nil
	case ".xml":
		return statsFormatXML, nil
	case ".md", ".markdown":
		return statsFormatMarkdown, nil
	default:
		return 0, fmt.Errorf("unsupported stats output extension %q (use .html, .json, .xml, or .md)", ext)
	}
}

func (s *StatsOutput) GetOutputChannel() chan []byte {
	return s.ch
}

func (s *StatsOutput) RunOutputLoop() {
	defer close(s.done)

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case _, ok := <-s.ch:
			if !ok {
				// Channel closed: final rotate and write report.
				s.collector.Rotate()
				s.writeReport()
				return
			}
			// Frame received; discard it since recording happens upstream.
		case <-ticker.C:
			s.collector.Rotate()
		}
	}
}

func (s *StatsOutput) Close() {
	close(s.ch)
	<-s.done
}

func (s *StatsOutput) writeReport() {
	windows := s.collector.History()
	allTime := s.collector.AllTimeSnapshot()

	var w *os.File
	var err error
	if s.path == "-" {
		w = os.Stdout
	} else {
		w, err = os.Create(s.path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stats: failed to create %s: %v\n", s.path, err)
			return
		}
		defer w.Close()
	}

	switch s.format {
	case statsFormatJSON:
		err = stats.RenderJSON(w, windows, allTime)
	case statsFormatHTML:
		err = stats.RenderHTML(w, windows, allTime)
	case statsFormatXML:
		err = stats.RenderXML(w, windows, allTime)
	case statsFormatMarkdown:
		err = stats.RenderMarkdown(w, windows, allTime)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats: failed to write report: %v\n", err)
	}
}
