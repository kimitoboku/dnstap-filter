package main

import "testing"

func TestParseCLIArgs_Success(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap", "--filter", "ip=1.1.1.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.inputFileName != "in.dnstap" {
		t.Fatalf("unexpected input file: %s", cfg.inputFileName)
	}
	if cfg.outputFileName != "out.dnstap" {
		t.Fatalf("unexpected output file: %s", cfg.outputFileName)
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

func TestParseCLIArgs_RequiredFlags(t *testing.T) {
	_, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap"})
	if err == nil {
		t.Fatalf("expected error when --filter is missing")
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

func TestParseCLIArgs_RequireInOutWithoutPrintMode(t *testing.T) {
	_, err := parseCLIArgs([]string{"--filter", "ip=1.1.1.1"})
	if err == nil {
		t.Fatalf("expected error when --in/--out are missing in normal mode")
	}
}

func TestParseCLIArgs_NoPositionalArgs(t *testing.T) {
	_, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap", "--filter", "ip=1.1.1.1", "legacy"})
	if err == nil {
		t.Fatalf("expected error when positional args are present")
	}
}
