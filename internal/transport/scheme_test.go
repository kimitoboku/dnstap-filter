package transport

import "testing"

func TestParseURI_File(t *testing.T) {
	tests := []struct {
		spec     string
		wantAddr string
	}{
		{"in.dnstap", "in.dnstap"},
		{"file:in.dnstap", "in.dnstap"},
		{"file:/var/log/dns.tap", "/var/log/dns.tap"},
	}
	for _, tt := range tests {
		u, err := parseURI(tt.spec)
		if err != nil {
			t.Fatalf("parseURI(%q) error: %v", tt.spec, err)
		}
		if u.scheme != schemeFile {
			t.Fatalf("parseURI(%q): expected scheme file, got %q", tt.spec, u.scheme)
		}
		if u.address != tt.wantAddr {
			t.Fatalf("parseURI(%q): expected address %q, got %q", tt.spec, tt.wantAddr, u.address)
		}
	}
}

func TestParseURI_Unix(t *testing.T) {
	u, err := parseURI("unix:/var/run/named/dnstap.sock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.scheme != schemeUnix {
		t.Fatalf("expected scheme unix, got %q", u.scheme)
	}
	if u.address != "/var/run/named/dnstap.sock" {
		t.Fatalf("expected address /var/run/named/dnstap.sock, got %q", u.address)
	}
}

func TestParseURI_TCP(t *testing.T) {
	u, err := parseURI("tcp:127.0.0.1:6000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.scheme != schemeTCP {
		t.Fatalf("expected scheme tcp, got %q", u.scheme)
	}
	if u.address != "127.0.0.1:6000" {
		t.Fatalf("expected address 127.0.0.1:6000, got %q", u.address)
	}
}

func TestParseURI_YAML(t *testing.T) {
	tests := []struct {
		spec     string
		wantAddr string
	}{
		{"yaml:-", "-"},
		{"yaml:/tmp/out.yaml", "/tmp/out.yaml"},
	}
	for _, tt := range tests {
		u, err := parseURI(tt.spec)
		if err != nil {
			t.Fatalf("parseURI(%q) error: %v", tt.spec, err)
		}
		if u.scheme != schemeYAML {
			t.Fatalf("parseURI(%q): expected scheme yaml, got %q", tt.spec, u.scheme)
		}
		if u.address != tt.wantAddr {
			t.Fatalf("parseURI(%q): expected address %q, got %q", tt.spec, tt.wantAddr, u.address)
		}
	}
}

func TestParseURI_Stdout(t *testing.T) {
	tests := []struct {
		spec     string
		wantAddr string
	}{
		{"stdout:", ""},
		{"stdout:time,name,type", "time,name,type"},
		{"stdout:time,qr,name,type,rcode,ip", "time,qr,name,type,rcode,ip"},
	}
	for _, tt := range tests {
		u, err := parseURI(tt.spec)
		if err != nil {
			t.Fatalf("parseURI(%q) error: %v", tt.spec, err)
		}
		if u.scheme != schemeStdout {
			t.Fatalf("parseURI(%q): expected scheme stdout, got %q", tt.spec, u.scheme)
		}
		if u.address != tt.wantAddr {
			t.Fatalf("parseURI(%q): expected address %q, got %q", tt.spec, tt.wantAddr, u.address)
		}
	}
}

func TestParseURI_UnknownScheme(t *testing.T) {
	_, err := parseURI("ftp:some.server")
	if err == nil {
		t.Fatalf("expected error for unknown scheme")
	}
}

func TestIsStatsSpec(t *testing.T) {
	cases := []struct {
		spec string
		want bool
	}{
		{"stats:report.html", true},
		{"stats:-", true},
		{"stats:report.json", true},
		{"stdout:time", false},
		{"file:out.dnstap", false},
		{"ftp:bad", false},
	}
	for _, tt := range cases {
		got := IsStatsSpec(tt.spec)
		if got != tt.want {
			t.Errorf("IsStatsSpec(%q) = %v, want %v", tt.spec, got, tt.want)
		}
	}
}

func TestStatsAddress(t *testing.T) {
	addr, err := StatsAddress("stats:report.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "report.json" {
		t.Errorf("expected 'report.json', got %q", addr)
	}

	addr, err = StatsAddress("stats:-")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "-" {
		t.Errorf("expected '-', got %q", addr)
	}

	_, err = StatsAddress("stdout:time")
	if err == nil {
		t.Fatal("expected error for non-stats spec")
	}

	_, err = StatsAddress("ftp:bad")
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}
