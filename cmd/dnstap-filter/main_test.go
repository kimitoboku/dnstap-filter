package main

import "testing"

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
