package transport

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type scheme string

const (
	schemeFile   scheme = "file"
	schemeUnix   scheme = "unix"
	schemeTCP    scheme = "tcp"
	schemeYAML   scheme = "yaml"
	schemePcap   scheme = "pcap"
	schemeDevice scheme = "device"
	schemeStdout scheme = "stdout"
	schemeJSONL  scheme = "jsonl"
	schemeDNS    scheme = "dns"
	schemeStats  scheme = "stats"
)

var knownSchemes = map[scheme]bool{
	schemeFile:   true,
	schemeUnix:   true,
	schemeTCP:    true,
	schemeYAML:   true,
	schemePcap:   true,
	schemeDevice: true,
	schemeStdout: true,
	schemeJSONL:  true,
	schemeDNS:    true,
	schemeStats:  true,
}

type uri struct {
	scheme  scheme
	address string
}

// IsStatsSpec returns true if the spec starts with "stats:" scheme.
func IsStatsSpec(spec string) bool {
	u, err := parseURI(spec)
	if err != nil {
		return false
	}
	return u.scheme == schemeStats
}

// StatsAddress returns the address part of a stats spec.
// It returns an error if the spec is not a stats scheme.
func StatsAddress(spec string) (string, error) {
	u, err := parseURI(spec)
	if err != nil {
		return "", err
	}
	if u.scheme != schemeStats {
		return "", fmt.Errorf("not a stats spec: %q", spec)
	}
	return u.address, nil
}

// IsListenAddr returns true if address looks like a network listen address
// (e.g. ":9090", "localhost:9090", "0.0.0.0:9090") rather than a file path.
func IsListenAddr(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	// Port must be a valid number.
	if _, err := strconv.Atoi(port); err != nil {
		return false
	}
	// If host is empty (":9090") or a valid IP / hostname, it's a listen addr.
	if host == "" || host == "localhost" || net.ParseIP(host) != nil {
		return true
	}
	return false
}

// parseURI parses a transport spec of the form "scheme:address".
// If the spec contains no colon or the scheme is not recognized, the entire
// spec is treated as a file path (backward compatibility).
func parseURI(spec string) (uri, error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) == 2 {
		s := scheme(strings.ToLower(parts[0]))
		if knownSchemes[s] {
			return uri{scheme: s, address: parts[1]}, nil
		}
		return uri{}, fmt.Errorf("unknown transport scheme %q (valid: file, unix, tcp, yaml, jsonl, pcap, device, stdout, dns, stats)", parts[0])
	}
	// No colon: treat as file path (backward compatibility).
	return uri{scheme: schemeFile, address: spec}, nil
}
