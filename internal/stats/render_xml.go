package stats

import (
	"encoding/xml"
	"fmt"
	"io"
)

// RenderXML writes the stats report in DSC-compatible XML format.
// Each time window produces a set of <array> elements for qtype, rcode,
// client IPs, and top domains.
func RenderXML(w io.Writer, windows []*Snapshot, allTime *Snapshot) error {
	if _, err := fmt.Fprintln(w, `<?xml version="1.0" encoding="UTF-8"?>`); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, `<dnstap-filter-stats>`); err != nil {
		return err
	}

	// Write per-window arrays.
	for _, snap := range windows {
		if err := writeWindowArrays(w, snap); err != nil {
			return err
		}
	}

	// Write all-time summary.
	if allTime != nil {
		if _, err := fmt.Fprintln(w, `  <!-- all-time summary -->`); err != nil {
			return err
		}
		if err := writeWindowArrays(w, allTime); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(w, `</dnstap-filter-stats>`)
	return err
}

func writeWindowArrays(w io.Writer, snap *Snapshot) error {
	startEpoch := snap.Start.Unix()
	stopEpoch := snap.End.Unix()

	// qtype array: All × Qtype
	if err := writeArray(w, "qtype", startEpoch, stopEpoch, "All", "Qtype", []outerEntry{
		{Val: "ALL", Children: snap.QtypeDist},
	}); err != nil {
		return err
	}

	// rcode array: All × Rcode
	if err := writeArray(w, "rcode", startEpoch, stopEpoch, "All", "Rcode", []outerEntry{
		{Val: "ALL", Children: snap.RcodeDist},
	}); err != nil {
		return err
	}

	// client_addr array: All × ClientAddr
	if err := writeArray(w, "client_addr", startEpoch, stopEpoch, "All", "ClientAddr", []outerEntry{
		{Val: "ALL", Children: snap.ClientIPs},
	}); err != nil {
		return err
	}

	// qname array: All × Qname
	if err := writeArray(w, "qname", startEpoch, stopEpoch, "All", "Qname", []outerEntry{
		{Val: "ALL", Children: snap.TopDomains},
	}); err != nil {
		return err
	}

	return nil
}

type outerEntry struct {
	Val      string
	Children []RankedEntry
}

func writeArray(w io.Writer, name string, startEpoch, stopEpoch int64, dim1Type, dim2Type string, data []outerEntry) error {
	type innerElement struct {
		XMLName xml.Name
		Val     string `xml:"val,attr"`
		Count   uint64 `xml:"count,attr"`
	}

	type outerElement struct {
		XMLName  xml.Name
		Val      string         `xml:"val,attr"`
		Children []innerElement `xml:",any"`
	}

	type arrayData struct {
		XMLName xml.Name       `xml:"data"`
		Entries []outerElement `xml:",any"`
	}

	type dimension struct {
		Number int    `xml:"number,attr"`
		Type   string `xml:"type,attr"`
	}

	type array struct {
		XMLName    xml.Name    `xml:"array"`
		Name       string      `xml:"name,attr"`
		Dimensions int         `xml:"dimensions,attr"`
		StartTime  int64       `xml:"start_time,attr"`
		StopTime   int64       `xml:"stop_time,attr"`
		Dims       []dimension `xml:"dimension"`
		Data       arrayData
	}

	entries := make([]outerElement, 0, len(data))
	for _, outer := range data {
		children := make([]innerElement, 0, len(outer.Children))
		for _, child := range outer.Children {
			children = append(children, innerElement{
				XMLName: xml.Name{Local: dim2Type},
				Val:     child.Key,
				Count:   child.Count,
			})
		}
		entries = append(entries, outerElement{
			XMLName:  xml.Name{Local: dim1Type},
			Val:      outer.Val,
			Children: children,
		})
	}

	a := array{
		Name:       name,
		Dimensions: 2,
		StartTime:  startEpoch,
		StopTime:   stopEpoch,
		Dims: []dimension{
			{Number: 1, Type: dim1Type},
			{Number: 2, Type: dim2Type},
		},
		Data: arrayData{Entries: entries},
	}

	enc := xml.NewEncoder(w)
	enc.Indent("  ", "  ")
	if err := enc.EncodeElement(a, xml.StartElement{Name: xml.Name{Local: "array"}}); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w)
	return err
}
