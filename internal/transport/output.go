package transport

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

const defaultTimeFormat = "2006-01-02 15:04:05"

// stdoutField represents a field that can be included in stdout output.
type stdoutField int

const (
	fieldTime    stdoutField = iota // timestamp
	fieldQR                         // Q or R indicator
	fieldMsgType                    // full message type name (e.g. CLIENT_QUERY)
	fieldName                       // query name
	fieldType                       // query type (e.g. A, AAAA)
	fieldRcode                      // response code (empty for queries)
	fieldIP                         // client IP (QueryAddress)
)

var defaultFields = []stdoutField{fieldTime, fieldQR, fieldName, fieldType, fieldRcode}

var fieldNameMap = map[string]stdoutField{
	"time":    fieldTime,
	"qr":      fieldQR,
	"msgtype": fieldMsgType,
	"name":    fieldName,
	"type":    fieldType,
	"rcode":   fieldRcode,
	"ip":      fieldIP,
}

// parseStdoutFields parses a comma-separated list of field names.
// An empty spec returns the default fields.
func parseStdoutFields(spec string) ([]stdoutField, error) {
	if spec == "" {
		return defaultFields, nil
	}
	parts := strings.Split(spec, ",")
	fields := make([]stdoutField, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("empty field name in stdout spec")
		}
		f, ok := fieldNameMap[strings.ToLower(p)]
		if !ok {
			valid := make([]string, 0, len(fieldNameMap))
			for k := range fieldNameMap {
				valid = append(valid, k)
			}
			return nil, fmt.Errorf("unknown stdout field %q (valid: %s)", p, strings.Join(valid, ", "))
		}
		fields = append(fields, f)
	}
	return fields, nil
}

// isResponseType returns true if the dnstap message type is a response
// (even enum values are responses in the protobuf definition).
func isResponseType(mt dnstap.Message_Type) bool {
	return int32(mt)%2 == 0
}

// newStdoutFormatFunc builds a dnstap.TextFormatFunc that outputs the
// requested fields separated by spaces.
func newStdoutFormatFunc(fields []stdoutField) dnstap.TextFormatFunc {
	return func(dt *dnstap.Dnstap) ([]byte, bool) {
		if dt.Type == nil || *dt.Type != dnstap.Dnstap_MESSAGE || dt.Message == nil {
			return nil, false
		}
		m := dt.Message

		// Pre-compute commonly needed values lazily.
		var (
			timestamp   time.Time
			timeParsed  bool
			dnsMsg      *dns.Msg
			dnsMsgReady bool
			respMsg     *dns.Msg
			respReady   bool
			isResp      bool
		)

		if m.Type != nil {
			isResp = isResponseType(*m.Type)
		}

		getTime := func() time.Time {
			if timeParsed {
				return timestamp
			}
			timeParsed = true
			if m.QueryTimeSec != nil {
				nsec := int64(0)
				if m.QueryTimeNsec != nil {
					nsec = int64(*m.QueryTimeNsec)
				}
				timestamp = time.Unix(int64(*m.QueryTimeSec), nsec)
			} else if m.ResponseTimeSec != nil {
				nsec := int64(0)
				if m.ResponseTimeNsec != nil {
					nsec = int64(*m.ResponseTimeNsec)
				}
				timestamp = time.Unix(int64(*m.ResponseTimeSec), nsec)
			}
			return timestamp
		}

		getDNSMsg := func() *dns.Msg {
			if dnsMsgReady {
				return dnsMsg
			}
			dnsMsgReady = true
			var msgBytes []byte
			if m.QueryMessage != nil {
				msgBytes = m.QueryMessage
			} else if m.ResponseMessage != nil {
				msgBytes = m.ResponseMessage
			}
			if msgBytes == nil {
				return nil
			}
			msg := new(dns.Msg)
			if err := msg.Unpack(msgBytes); err != nil {
				return nil
			}
			dnsMsg = msg
			return dnsMsg
		}

		getRespMsg := func() *dns.Msg {
			if respReady {
				return respMsg
			}
			respReady = true
			if m.ResponseMessage == nil {
				return nil
			}
			msg := new(dns.Msg)
			if err := msg.Unpack(m.ResponseMessage); err != nil {
				return nil
			}
			respMsg = msg
			return respMsg
		}

		parts := make([]string, 0, len(fields))
		for _, f := range fields {
			switch f {
			case fieldTime:
				parts = append(parts, getTime().Format(defaultTimeFormat))
			case fieldQR:
				if isResp {
					parts = append(parts, "R")
				} else {
					parts = append(parts, "Q")
				}
			case fieldMsgType:
				if m.Type != nil {
					parts = append(parts, dnstap.Message_Type_name[int32(*m.Type)])
				}
			case fieldName:
				msg := getDNSMsg()
				if msg == nil || len(msg.Question) == 0 {
					return nil, false
				}
				parts = append(parts, msg.Question[0].Name)
			case fieldType:
				msg := getDNSMsg()
				if msg == nil || len(msg.Question) == 0 {
					return nil, false
				}
				parts = append(parts, dns.Type(msg.Question[0].Qtype).String())
			case fieldRcode:
				if !isResp {
					continue
				}
				resp := getRespMsg()
				if resp == nil {
					continue
				}
				parts = append(parts, dns.RcodeToString[resp.Rcode])
			case fieldIP:
				if m.QueryAddress != nil {
					parts = append(parts, net.IP(m.QueryAddress).String())
				}
			}
		}

		if len(parts) == 0 {
			return nil, false
		}

		line := strings.Join(parts, " ") + "\n"
		return []byte(line), true
	}
}

// defaultQueryFormat implements dnstap.TextFormatFunc.
// It renders each dnstap message as: "<time> <Q|R> <name> <type> [<rcode>]"
var defaultQueryFormat = newStdoutFormatFunc(defaultFields)

// MultiOutput fans out dnstap frames to multiple outputs.
type MultiOutput struct {
	outputs []dnstap.Output
	ch      chan []byte
	done    chan struct{}
}

// NewMultiOutput creates a MultiOutput that distributes frames to all given outputs.
func NewMultiOutput(outputs []dnstap.Output) *MultiOutput {
	return &MultiOutput{
		outputs: outputs,
		ch:      make(chan []byte, 32),
		done:    make(chan struct{}),
	}
}

func (m *MultiOutput) GetOutputChannel() chan []byte {
	return m.ch
}

func (m *MultiOutput) RunOutputLoop() {
	defer close(m.done)
	for _, o := range m.outputs {
		go o.RunOutputLoop()
	}
	for frame := range m.ch {
		for _, o := range m.outputs {
			o.GetOutputChannel() <- frame
		}
	}
}

func (m *MultiOutput) Close() {
	close(m.ch)
	<-m.done
	for _, o := range m.outputs {
		o.Close()
	}
}

// ParseOutputs parses multiple output specs and returns a single dnstap.Output.
// If no specs are given, the default stdout output is returned.
// If one spec is given, a single output is returned (no fan-out overhead).
// If multiple specs are given, a MultiOutput fan-out wrapper is returned.
func ParseOutputs(specs []string) (dnstap.Output, error) {
	if len(specs) == 0 {
		return ParseOutput("")
	}
	if len(specs) == 1 {
		return ParseOutput(specs[0])
	}
	outputs := make([]dnstap.Output, 0, len(specs))
	for _, spec := range specs {
		o, err := ParseOutput(spec)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, o)
	}
	return NewMultiOutput(outputs), nil
}

// ParseOutput parses a transport spec and returns a dnstap.Output.
//
// Supported schemes:
//   - (empty)              - default: print "<time> <Q|R> <name> <type> [<rcode>]" to stdout
//   - stdout:<fields>      - customizable stdout (fields: time,qr,msgtype,name,type,rcode,ip)
//   - file:<path>          - dnstap frame stream file (with SIGHUP log rotation)
//   - unix:<path>          - Unix domain socket client (connects to a collector)
//   - tcp:<host:port>      - TCP client (connects to a collector)
//   - yaml:<path>|yaml:-   - human-readable YAML format (- means stdout)
//   - jsonl:<path>|jsonl:-  - structured JSONL format (one JSON object per line, - means stdout)
//
// Bare paths without a scheme are treated as file: (backward compatibility).
func ParseOutput(spec string) (dnstap.Output, error) {
	if spec == "" {
		return dnstap.NewTextOutput(os.Stdout, defaultQueryFormat), nil
	}

	u, err := parseURI(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid output spec %q: %w", spec, err)
	}

	switch u.scheme {
	case schemeStdout:
		fields, err := parseStdoutFields(u.address)
		if err != nil {
			return nil, fmt.Errorf("stdout output: %w", err)
		}
		return dnstap.NewTextOutput(os.Stdout, newStdoutFormatFunc(fields)), nil
	case schemeFile:
		return newFileOutput(u.address)
	case schemeUnix:
		addr, err := net.ResolveUnixAddr("unix", u.address)
		if err != nil {
			return nil, fmt.Errorf("unix output: invalid path %q: %w", u.address, err)
		}
		return dnstap.NewFrameStreamSockOutput(addr)
	case schemeTCP:
		addr, err := net.ResolveTCPAddr("tcp", u.address)
		if err != nil {
			return nil, fmt.Errorf("tcp output: invalid address %q: %w", u.address, err)
		}
		return dnstap.NewFrameStreamSockOutput(addr)
	case schemeYAML:
		return dnstap.NewTextOutputFromFilename(u.address, dnstap.YamlFormat, false)
	case schemeJSONL:
		return dnstap.NewTextOutputFromFilename(u.address, jsonlOutputFormat, false)
	default:
		return nil, fmt.Errorf("unsupported output scheme %q", u.scheme)
	}
}
