package transport

import (
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

type jsonlOutput struct {
	Type            string    `json:"type"`
	MessageType     string    `json:"message_type"`
	Timestamp       string    `json:"timestamp"`
	SocketFamily    string    `json:"socket_family,omitempty"`
	SocketProtocol  string    `json:"socket_protocol,omitempty"`
	QueryAddress    string    `json:"query_address,omitempty"`
	QueryPort       uint32    `json:"query_port,omitempty"`
	ResponseAddress string    `json:"response_address,omitempty"`
	ResponsePort    uint32    `json:"response_port,omitempty"`
	DNS             *jsonlDNS `json:"dns,omitempty"`
}

type jsonlDNS struct {
	ID         uint16        `json:"id"`
	QR         bool          `json:"qr"`
	Opcode     string        `json:"opcode"`
	Rcode      string        `json:"rcode"`
	Flags      jsonlDNSFlags `json:"flags"`
	Question   []jsonlDNSQ   `json:"question"`
	Answer     []jsonlDNSRR  `json:"answer"`
	Authority  []jsonlDNSRR  `json:"authority"`
	Additional []jsonlDNSRR  `json:"additional"`
}

type jsonlDNSFlags struct {
	AA bool `json:"aa"`
	TC bool `json:"tc"`
	RD bool `json:"rd"`
	RA bool `json:"ra"`
	AD bool `json:"ad"`
	CD bool `json:"cd"`
}

type jsonlDNSQ struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type jsonlDNSRR struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

var jsonlOutputFormat dnstap.TextFormatFunc = func(dt *dnstap.Dnstap) ([]byte, bool) {
	if dt.Type == nil || *dt.Type != dnstap.Dnstap_MESSAGE || dt.Message == nil {
		return nil, false
	}
	m := dt.Message

	out := jsonlOutput{
		Type: dnstap.Dnstap_Type_name[int32(*dt.Type)],
	}

	if m.Type != nil {
		out.MessageType = dnstap.Message_Type_name[int32(*m.Type)]
	}

	// Timestamp: prefer response time for responses, query time for queries.
	isResp := m.Type != nil && isResponseType(*m.Type)
	if isResp && m.ResponseTimeSec != nil {
		nsec := int64(0)
		if m.ResponseTimeNsec != nil {
			nsec = int64(*m.ResponseTimeNsec)
		}
		out.Timestamp = time.Unix(int64(*m.ResponseTimeSec), nsec).UTC().Format(time.RFC3339Nano)
	} else if m.QueryTimeSec != nil {
		nsec := int64(0)
		if m.QueryTimeNsec != nil {
			nsec = int64(*m.QueryTimeNsec)
		}
		out.Timestamp = time.Unix(int64(*m.QueryTimeSec), nsec).UTC().Format(time.RFC3339Nano)
	}

	if m.SocketFamily != nil {
		out.SocketFamily = dnstap.SocketFamily_name[int32(*m.SocketFamily)]
	}
	if m.SocketProtocol != nil {
		out.SocketProtocol = dnstap.SocketProtocol_name[int32(*m.SocketProtocol)]
	}
	if m.QueryAddress != nil {
		out.QueryAddress = net.IP(m.QueryAddress).String()
	}
	if m.QueryPort != nil {
		out.QueryPort = *m.QueryPort
	}
	if m.ResponseAddress != nil {
		out.ResponseAddress = net.IP(m.ResponseAddress).String()
	}
	if m.ResponsePort != nil {
		out.ResponsePort = *m.ResponsePort
	}

	// Parse the DNS message.
	var msgBytes []byte
	if isResp && m.ResponseMessage != nil {
		msgBytes = m.ResponseMessage
	} else if m.QueryMessage != nil {
		msgBytes = m.QueryMessage
	} else if m.ResponseMessage != nil {
		msgBytes = m.ResponseMessage
	}

	if msgBytes != nil {
		msg := new(dns.Msg)
		if err := msg.Unpack(msgBytes); err == nil {
			d := &jsonlDNS{
				ID:     msg.Id,
				QR:     msg.Response,
				Opcode: dns.OpcodeToString[msg.Opcode],
				Rcode:  dns.RcodeToString[msg.Rcode],
				Flags: jsonlDNSFlags{
					AA: msg.Authoritative,
					TC: msg.Truncated,
					RD: msg.RecursionDesired,
					RA: msg.RecursionAvailable,
					AD: msg.AuthenticatedData,
					CD: msg.CheckingDisabled,
				},
				Question:   make([]jsonlDNSQ, 0, len(msg.Question)),
				Answer:     make([]jsonlDNSRR, 0, len(msg.Answer)),
				Authority:  make([]jsonlDNSRR, 0, len(msg.Ns)),
				Additional: make([]jsonlDNSRR, 0, len(msg.Extra)),
			}
			for _, q := range msg.Question {
				d.Question = append(d.Question, jsonlDNSQ{
					Name:  q.Name,
					Type:  dns.Type(q.Qtype).String(),
					Class: dns.Class(q.Qclass).String(),
				})
			}
			for _, rr := range msg.Answer {
				d.Answer = append(d.Answer, rrToJSONL(rr))
			}
			for _, rr := range msg.Ns {
				d.Authority = append(d.Authority, rrToJSONL(rr))
			}
			for _, rr := range msg.Extra {
				d.Additional = append(d.Additional, rrToJSONL(rr))
			}
			out.DNS = d
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		return nil, false
	}
	b = append(b, '\n')
	return b, true
}

func rrToJSONL(rr dns.RR) jsonlDNSRR {
	hdr := rr.Header()
	data := strings.TrimSpace(strings.TrimPrefix(rr.String(), hdr.String()))
	return jsonlDNSRR{
		Name:  hdr.Name,
		Type:  dns.Type(hdr.Rrtype).String(),
		Class: dns.Class(hdr.Class).String(),
		TTL:   hdr.Ttl,
		Data:  data,
	}
}
