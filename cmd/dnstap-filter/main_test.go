package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"google.golang.org/protobuf/proto"

	"github.com/kimitoboku/dnstap-filter/internal/expression"
	"github.com/kimitoboku/dnstap-filter/internal/stats"
)

// emptyPcapFile creates a temp file with a minimal pcap global header
// (magic number only) so that NewPcapInput's stat check passes.
// ReadInto will fail to parse it and return gracefully.
func emptyPcapFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")
	// pcap global header magic: 0xd4c3b2a1 (little-endian)
	if err := os.WriteFile(path, []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseCLIArgs_Success(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap", "--filter", "ip=1.1.1.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.inputSpec != "in.dnstap" {
		t.Fatalf("unexpected input spec: %s", cfg.inputSpec)
	}
	if len(cfg.outputSpecs) != 1 || cfg.outputSpecs[0] != "out.dnstap" {
		t.Fatalf("unexpected output specs: %v", cfg.outputSpecs)
	}
	if cfg.filterExpr != "ip=1.1.1.1" {
		t.Fatalf("unexpected filter expr: %s", cfg.filterExpr)
	}
	if cfg.printFilterTree {
		t.Fatalf("expected printFilterTree to be false")
	}
	if cfg.countLimit != 0 {
		t.Fatalf("unexpected default countLimit: %d", cfg.countLimit)
	}
}

func TestParseCLIArgs_FilterOptional(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap"})
	if err != nil {
		t.Fatalf("unexpected error when --filter is omitted: %v", err)
	}
	if cfg.filterExpr != "" {
		t.Fatalf("expected empty filterExpr, got: %s", cfg.filterExpr)
	}
}

func TestParseCLIArgs_PrintFilterTreeOnly(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"--filter", "ip=1.1.1.1", "--print-filter-tree"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.printFilterTree {
		t.Fatalf("expected printFilterTree to be true")
	}
}

func TestParseCLIArgs_CountOption(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap", "--filter", "ip=1.1.1.1", "--cout", "10"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.countLimit != 10 {
		t.Fatalf("expected countLimit to be 10, got: %d", cfg.countLimit)
	}
}

func TestParseCLIArgs_CountOptionShorthand(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap", "--filter", "ip=1.1.1.1", "-c", "7"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.countLimit != 7 {
		t.Fatalf("expected countLimit to be 7, got: %d", cfg.countLimit)
	}
}

func TestParseCLIArgs_CountOptionNegative(t *testing.T) {
	_, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap", "--filter", "ip=1.1.1.1", "--cout", "-1"})
	if err == nil {
		t.Fatalf("expected error for negative --cout")
	}
}

func TestParseCLIArgs_RequireInWithoutPrintMode(t *testing.T) {
	_, err := parseCLIArgs([]string{"--filter", "ip=1.1.1.1"})
	if err == nil {
		t.Fatalf("expected error when --in is missing in normal mode")
	}
}

func TestParseCLIArgs_OutOptional(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"--in", "in.dnstap", "--filter", "ip=1.1.1.1"})
	if err != nil {
		t.Fatalf("unexpected error when --out is omitted: %v", err)
	}
	if len(cfg.outputSpecs) != 0 {
		t.Fatalf("expected empty outputSpecs when --out is omitted, got: %v", cfg.outputSpecs)
	}
}

func TestParseCLIArgs_NoPositionalArgs(t *testing.T) {
	_, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap", "--filter", "ip=1.1.1.1", "legacy"})
	if err == nil {
		t.Fatalf("expected error when positional args are present")
	}
}

func TestParseCLIArgs_URISchemes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{"file scheme", "file:in.dnstap", "file:out.dnstap"},
		{"unix scheme", "unix:/var/run/named/dnstap.sock", "unix:/var/run/collector.sock"},
		{"tcp scheme", "tcp:0.0.0.0:6000", "tcp:127.0.0.1:6001"},
		{"yaml out", "file:in.dnstap", "yaml:-"},
		{"yaml file out", "file:in.dnstap", "yaml:/tmp/out.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseCLIArgs([]string{"--in", tt.in, "--out", tt.out, "--filter", "ip=1.1.1.1"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.inputSpec != tt.in {
				t.Fatalf("expected inputSpec %q, got %q", tt.in, cfg.inputSpec)
			}
			if len(cfg.outputSpecs) != 1 || cfg.outputSpecs[0] != tt.out {
				t.Fatalf("expected outputSpecs [%q], got %v", tt.out, cfg.outputSpecs)
			}
		})
	}
}

func TestParseCLIArgs_MultipleOuts(t *testing.T) {
	cfg, err := parseCLIArgs([]string{
		"--in", "in.dnstap",
		"--out", "file:a.dnstap",
		"--out", "yaml:-",
		"--out", "stdout:time,name",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.outputSpecs) != 3 {
		t.Fatalf("expected 3 output specs, got %d: %v", len(cfg.outputSpecs), cfg.outputSpecs)
	}
	expected := []string{"file:a.dnstap", "yaml:-", "stdout:time,name"}
	for i, want := range expected {
		if cfg.outputSpecs[i] != want {
			t.Fatalf("outputSpecs[%d]: expected %q, got %q", i, want, cfg.outputSpecs[i])
		}
	}
}

func TestRun_PrintFilterTree(t *testing.T) {
	err := run([]string{"--print-filter-tree"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_InvalidFilter(t *testing.T) {
	err := run([]string{"--in", "x", "--filter", "xyz=unknown"})
	if err == nil {
		t.Fatal("expected error for invalid filter expression")
	}
}

func TestRun_BadInputScheme(t *testing.T) {
	err := run([]string{"--in", "ftp:bad"})
	if err == nil {
		t.Fatal("expected error for bad input scheme")
	}
}

func TestRun_BadOutputScheme(t *testing.T) {
	pcap := emptyPcapFile(t)
	err := run([]string{"--in", "pcap:" + pcap, "--out", "ftp:bad"})
	if err == nil {
		t.Fatal("expected error for bad output scheme")
	}
}

func TestRun_BadStatsExt(t *testing.T) {
	pcap := emptyPcapFile(t)
	err := run([]string{"--in", "pcap:" + pcap, "--out", "stats:report.txt"})
	if err == nil {
		t.Fatal("expected error for unsupported stats extension")
	}
}

func TestRun_PcapEOF(t *testing.T) {
	// pcap input with unparseable file: ReadInto fails immediately, run returns nil.
	pcap := emptyPcapFile(t)
	err := run([]string{"--in", "pcap:" + pcap})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_MultipleOutputs(t *testing.T) {
	// Two outputs → MultiOutput path in run().
	pcap := emptyPcapFile(t)
	err := run([]string{"--in", "pcap:" + pcap, "--out", "stats:-", "--out", "stdout:"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_MultipleStatsOutputs(t *testing.T) {
	// Two stats outputs: second reuses the same collector.
	pcap := emptyPcapFile(t)
	err := run([]string{"--in", "pcap:" + pcap, "--out", "stats:-", "--out", "stats:-"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func buildTestFrame(t *testing.T) []byte {
	t.Helper()
	dtType := dnstap.Dnstap_MESSAGE
	msgType := dnstap.Message_CLIENT_QUERY
	sec := uint64(1704067200)
	dt := &dnstap.Dnstap{
		Type: &dtType,
		Message: &dnstap.Message{
			Type:         &msgType,
			QueryTimeSec: &sec,
		},
	}
	frame, err := proto.Marshal(dt)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestDnstapFilter_Basic(t *testing.T) {
	outputCh := make(chan []byte, 10)
	root, err := expression.ParseFilterExpression("")
	if err != nil {
		t.Fatal(err)
	}

	inputCh, done := dnstapFilter(outputCh, root, 0, 0, nil)
	inputCh <- buildTestFrame(t)

	select {
	case got := <-outputCh:
		if len(got) == 0 {
			t.Error("expected non-empty output frame")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for output frame")
	}

	close(inputCh)
	<-done
}

func TestDnstapFilter_CountLimit(t *testing.T) {
	outputCh := make(chan []byte, 10)
	root, _ := expression.ParseFilterExpression("")
	inputCh, done := dnstapFilter(outputCh, root, 1, 0, nil)

	frame := buildTestFrame(t)
	inputCh <- frame
	inputCh <- frame // should be discarded due to count limit

	select {
	case <-outputCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first frame")
	}

	close(inputCh)
	<-done

	select {
	case <-outputCh:
		t.Error("expected no second frame with count limit 1")
	default:
	}
}

func TestDnstapFilter_WithCollector(t *testing.T) {
	outputCh := make(chan []byte, 10)
	root, _ := expression.ParseFilterExpression("")
	collector := stats.NewCollector(stats.CollectorOptions{TopN: 5})
	inputCh, done := dnstapFilter(outputCh, root, 0, 0, collector)

	inputCh <- buildTestFrame(t)

	select {
	case <-outputCh:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	close(inputCh)
	<-done
}

func TestDnstapFilter_InvalidFrame(t *testing.T) {
	outputCh := make(chan []byte, 10)
	root, _ := expression.ParseFilterExpression("")
	inputCh, done := dnstapFilter(outputCh, root, 0, 0, nil)

	inputCh <- []byte("not valid protobuf")

	close(inputCh)
	<-done
}
