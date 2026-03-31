package stats

import (
	"fmt"
	"io"
)

// RenderMarkdown writes the stats report as a Markdown document to w.
func RenderMarkdown(w io.Writer, windows []*Snapshot, allTime *Snapshot) error {
	if _, err := fmt.Fprintln(w, "# dnstap-filter Statistics Report"); err != nil {
		return err
	}

	if allTime != nil {
		if _, err := fmt.Fprintln(w, "\n## All Time Summary"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "\n- **Total frames:** %d\n", allTime.TotalFrames); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "- **Period:** %s — %s\n",
			allTime.Start.Format("2006-01-02 15:04:05"),
			allTime.End.Format("2006-01-02 15:04:05")); err != nil {
			return err
		}
		if err := writeMarkdownTables(w, allTime); err != nil {
			return err
		}
	}

	if len(windows) > 0 {
		if _, err := fmt.Fprintln(w, "\n## Time Windows"); err != nil {
			return err
		}
		for i, snap := range windows {
			if _, err := fmt.Fprintf(w, "\n### Window %d: %s — %s (%d frames)\n",
				i+1,
				snap.Start.Format("2006-01-02 15:04:05"),
				snap.End.Format("2006-01-02 15:04:05"),
				snap.TotalFrames); err != nil {
				return err
			}
			if err := writeMarkdownTables(w, snap); err != nil {
				return err
			}
		}
	}

	return nil
}

func writeMarkdownTables(w io.Writer, snap *Snapshot) error {
	if len(snap.TopDomains) > 0 {
		if _, err := fmt.Fprintf(w, "\n#### Top Queried Domains\n\n"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "| # | Domain | Count |"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "|---|--------|-------|"); err != nil {
			return err
		}
		for i, e := range snap.TopDomains {
			if _, err := fmt.Fprintf(w, "| %d | %s | %d |\n", i+1, e.Key, e.Count); err != nil {
				return err
			}
		}
	}

	if len(snap.QtypeDist) > 0 {
		if _, err := fmt.Fprintf(w, "\n#### Query Type Distribution\n\n"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "| Type | Count |"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "|------|-------|"); err != nil {
			return err
		}
		for _, e := range snap.QtypeDist {
			if _, err := fmt.Fprintf(w, "| %s | %d |\n", e.Key, e.Count); err != nil {
				return err
			}
		}
	}

	if len(snap.RcodeDist) > 0 {
		if _, err := fmt.Fprintf(w, "\n#### Response Code Distribution\n\n"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "| Rcode | Count |"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "|-------|-------|"); err != nil {
			return err
		}
		for _, e := range snap.RcodeDist {
			if _, err := fmt.Fprintf(w, "| %s | %d |\n", e.Key, e.Count); err != nil {
				return err
			}
		}
	}

	if len(snap.ClientIPs) > 0 {
		if _, err := fmt.Fprintf(w, "\n#### Top Client IPs\n\n"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "| # | Client IP | Count |"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "|---|-----------|-------|"); err != nil {
			return err
		}
		for i, e := range snap.ClientIPs {
			if _, err := fmt.Fprintf(w, "| %d | %s | %d |\n", i+1, e.Key, e.Count); err != nil {
				return err
			}
		}
	}

	return nil
}
