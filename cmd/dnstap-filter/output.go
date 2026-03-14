package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

const defaultTimeFormat = "2006-01-02 15:04:05"

// parseOutput parses a transport spec and returns a dnstap.Output.
//
// Supported schemes:
//   - (empty)           - default: print "<time> <name> <type>" to stdout
//   - file:<path>       - dnstap frame stream file (with SIGHUP log rotation)
//   - unix:<path>       - Unix domain socket client (connects to a collector)
//   - tcp:<host:port>   - TCP client (connects to a collector)
//   - yaml:<path>|yaml:- - human-readable YAML format (- means stdout)
//
// Bare paths without a scheme are treated as file: (backward compatibility).
func parseOutput(spec string) (dnstap.Output, error) {
	if spec == "" {
		return dnstap.NewTextOutput(os.Stdout, defaultQueryFormat), nil
	}

	uri, err := parseTransportURI(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid output spec %q: %w", spec, err)
	}

	switch uri.scheme {
	case schemeFile:
		return newFileOutput(uri.address)
	case schemeUnix:
		addr, err := net.ResolveUnixAddr("unix", uri.address)
		if err != nil {
			return nil, fmt.Errorf("unix output: invalid path %q: %w", uri.address, err)
		}
		return dnstap.NewFrameStreamSockOutput(addr)
	case schemeTCP:
		addr, err := net.ResolveTCPAddr("tcp", uri.address)
		if err != nil {
			return nil, fmt.Errorf("tcp output: invalid address %q: %w", uri.address, err)
		}
		return dnstap.NewFrameStreamSockOutput(addr)
	case schemeYAML:
		return dnstap.NewTextOutputFromFilename(uri.address, dnstap.YamlFormat, false)
	default:
		return nil, fmt.Errorf("unsupported output scheme %q", uri.scheme)
	}
}

// defaultQueryFormat implements dnstap.TextFormatFunc.
// It renders each dnstap message as a single line: "<time> <name> <type>"
//
// Time is taken from QueryTimeSec if present, otherwise ResponseTimeSec.
// Name and type are taken from the first Question of the DNS message.
func defaultQueryFormat(dt *dnstap.Dnstap) ([]byte, bool) {
	if dt.Type == nil || *dt.Type != dnstap.Dnstap_MESSAGE || dt.Message == nil {
		return nil, false
	}
	m := dt.Message

	var t time.Time
	if m.QueryTimeSec != nil {
		nsec := int64(0)
		if m.QueryTimeNsec != nil {
			nsec = int64(*m.QueryTimeNsec)
		}
		t = time.Unix(int64(*m.QueryTimeSec), nsec)
	} else if m.ResponseTimeSec != nil {
		nsec := int64(0)
		if m.ResponseTimeNsec != nil {
			nsec = int64(*m.ResponseTimeNsec)
		}
		t = time.Unix(int64(*m.ResponseTimeSec), nsec)
	}

	var msgBytes []byte
	if m.QueryMessage != nil {
		msgBytes = m.QueryMessage
	} else if m.ResponseMessage != nil {
		msgBytes = m.ResponseMessage
	}
	if msgBytes == nil {
		return nil, false
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBytes); err != nil || len(msg.Question) == 0 {
		return nil, false
	}

	q := msg.Question[0]
	var s bytes.Buffer
	s.WriteString(t.Format(defaultTimeFormat))
	s.WriteByte(' ')
	s.WriteString(q.Name)
	s.WriteByte(' ')
	s.WriteString(dns.Type(q.Qtype).String())
	s.WriteByte('\n')
	return s.Bytes(), true
}
