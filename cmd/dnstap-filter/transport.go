package main

import (
	"fmt"
	"strings"
)

type transportScheme string

const (
	schemeFile transportScheme = "file"
	schemeUnix transportScheme = "unix"
	schemeTCP  transportScheme = "tcp"
	schemeYAML transportScheme = "yaml"
)

var knownSchemes = map[transportScheme]bool{
	schemeFile: true,
	schemeUnix: true,
	schemeTCP:  true,
	schemeYAML: true,
}

type transportURI struct {
	scheme  transportScheme
	address string
}

// parseTransportURI parses a transport spec of the form "scheme:address".
// If the spec contains no colon or the scheme is not recognized, the entire
// spec is treated as a file path (backward compatibility).
func parseTransportURI(spec string) (transportURI, error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) == 2 {
		scheme := transportScheme(strings.ToLower(parts[0]))
		if knownSchemes[scheme] {
			return transportURI{scheme: scheme, address: parts[1]}, nil
		}
		// Unknown scheme with colon: could be a Windows-style path or typo.
		// Treat as file for forward compatibility on Unix (colons invalid in filenames).
		return transportURI{}, fmt.Errorf("unknown transport scheme %q (valid: file, unix, tcp, yaml)", parts[0])
	}
	// No colon: treat as file path (backward compatibility).
	return transportURI{scheme: schemeFile, address: spec}, nil
}
