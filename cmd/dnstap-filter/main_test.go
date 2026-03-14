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
	if cfg.outputSpec != "out.dnstap" {
		t.Fatalf("unexpected output spec: %s", cfg.outputSpec)
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
	if cfg.outputSpec != "" {
		t.Fatalf("expected empty outputSpec when --out is omitted, got: %s", cfg.outputSpec)
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
			if cfg.outputSpec != tt.out {
				t.Fatalf("expected outputSpec %q, got %q", tt.out, cfg.outputSpec)
			}
		})
	}
}

func TestParseTransportURI_File(t *testing.T) {
	tests := []struct {
		spec    string
		wantAddr string
	}{
		{"in.dnstap", "in.dnstap"},
		{"file:in.dnstap", "in.dnstap"},
		{"file:/var/log/dns.tap", "/var/log/dns.tap"},
	}
	for _, tt := range tests {
		uri, err := parseTransportURI(tt.spec)
		if err != nil {
			t.Fatalf("parseTransportURI(%q) error: %v", tt.spec, err)
		}
		if uri.scheme != schemeFile {
			t.Fatalf("parseTransportURI(%q): expected scheme file, got %q", tt.spec, uri.scheme)
		}
		if uri.address != tt.wantAddr {
			t.Fatalf("parseTransportURI(%q): expected address %q, got %q", tt.spec, tt.wantAddr, uri.address)
		}
	}
}

func TestParseTransportURI_Unix(t *testing.T) {
	uri, err := parseTransportURI("unix:/var/run/named/dnstap.sock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.scheme != schemeUnix {
		t.Fatalf("expected scheme unix, got %q", uri.scheme)
	}
	if uri.address != "/var/run/named/dnstap.sock" {
		t.Fatalf("expected address /var/run/named/dnstap.sock, got %q", uri.address)
	}
}

func TestParseTransportURI_TCP(t *testing.T) {
	uri, err := parseTransportURI("tcp:127.0.0.1:6000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.scheme != schemeTCP {
		t.Fatalf("expected scheme tcp, got %q", uri.scheme)
	}
	if uri.address != "127.0.0.1:6000" {
		t.Fatalf("expected address 127.0.0.1:6000, got %q", uri.address)
	}
}

func TestParseTransportURI_YAML(t *testing.T) {
	tests := []struct {
		spec    string
		wantAddr string
	}{
		{"yaml:-", "-"},
		{"yaml:/tmp/out.yaml", "/tmp/out.yaml"},
	}
	for _, tt := range tests {
		uri, err := parseTransportURI(tt.spec)
		if err != nil {
			t.Fatalf("parseTransportURI(%q) error: %v", tt.spec, err)
		}
		if uri.scheme != schemeYAML {
			t.Fatalf("parseTransportURI(%q): expected scheme yaml, got %q", tt.spec, uri.scheme)
		}
		if uri.address != tt.wantAddr {
			t.Fatalf("parseTransportURI(%q): expected address %q, got %q", tt.spec, tt.wantAddr, uri.address)
		}
	}
}

func TestParseTransportURI_UnknownScheme(t *testing.T) {
	_, err := parseTransportURI("ftp:some.server")
	if err == nil {
		t.Fatalf("expected error for unknown scheme")
	}
}
