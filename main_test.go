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
}

func TestParseCLIArgs_RequiredFlags(t *testing.T) {
	_, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap"})
	if err == nil {
		t.Fatalf("expected error when --filter is missing")
	}
}

func TestParseCLIArgs_NoPositionalArgs(t *testing.T) {
	_, err := parseCLIArgs([]string{"--in", "in.dnstap", "--out", "out.dnstap", "--filter", "ip=1.1.1.1", "legacy"})
	if err == nil {
		t.Fatalf("expected error when positional args are present")
	}
}
