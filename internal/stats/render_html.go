package stats

import (
	"encoding/json"
	"html/template"
	"io"
	"time"
)

var htmlFuncs = template.FuncMap{
	"inc": func(i int) int { return i + 1 },
}

var htmlTemplate = template.Must(template.New("stats").Funcs(htmlFuncs).Parse(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>dnstap-filter Statistics</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  body { font-family: sans-serif; margin: 2em; background: #fafafa; color: #333; }
  h1 { color: #1a1a2e; }
  h2 { color: #16213e; margin-top: 2em; border-bottom: 2px solid #e2e2e2; padding-bottom: 0.3em; }
  h3 { color: #0f3460; }
  h4 { color: #333; margin-bottom: 0.3em; }
  table { border-collapse: collapse; margin: 1em 0; min-width: 300px; }
  th, td { border: 1px solid #ddd; padding: 6px 12px; text-align: left; }
  th { background: #e8e8e8; }
  tr:nth-child(even) { background: #f5f5f5; }
  .summary { font-size: 1.1em; margin: 0.5em 0; }
  .window { margin-bottom: 2em; padding: 1em; background: #fff; border: 1px solid #e0e0e0; border-radius: 4px; }
  .charts { display: flex; flex-wrap: wrap; gap: 2em; margin: 1.5em 0; }
  .chart-box { background: #fff; border: 1px solid #e0e0e0; border-radius: 4px; padding: 1em; flex: 1 1 400px; max-width: 700px; }
  .chart-box canvas { max-height: 300px; }
</style>
</head>
<body>
<h1>dnstap-filter Statistics Report</h1>

{{if .AllTime}}
<h2>All Time Summary</h2>
<p class="summary">Total frames: {{.AllTime.TotalFrames}}</p>
<p class="summary">Period: {{.AllTime.Start.Format "2006-01-02 15:04:05"}} &mdash; {{.AllTime.End.Format "2006-01-02 15:04:05"}}</p>

{{template "tables" .AllTime}}
{{end}}

{{if .Windows}}
<h2>Time Series Charts</h2>
<div class="charts">
  <div class="chart-box">
    <h4>Total Frames per Window</h4>
    <canvas id="chartFrames"></canvas>
  </div>
  <div class="chart-box">
    <h4>Query Type Distribution over Time</h4>
    <canvas id="chartQtype"></canvas>
  </div>
  <div class="chart-box">
    <h4>Response Code Distribution over Time</h4>
    <canvas id="chartRcode"></canvas>
  </div>
</div>

<h2>Time Windows</h2>
{{range $i, $w := .Windows}}
<div class="window">
<h3>Window {{inc $i}}: {{$w.Start.Format "2006-01-02 15:04:05"}} &mdash; {{$w.End.Format "2006-01-02 15:04:05"}} ({{$w.TotalFrames}} frames)</h3>
{{template "tables" $w}}
</div>
{{end}}
{{end}}

<script>
(function() {
  var windowsData = {{.WindowsJSON}};
  if (!windowsData || windowsData.length === 0) return;

  var labels = windowsData.map(function(w, i) {
    return w.start ? w.start.substring(0, 19).replace('T', ' ') : 'Window ' + (i+1);
  });

  // --- Total Frames chart ---
  var framesData = windowsData.map(function(w) { return w.total_frames || 0; });
  new Chart(document.getElementById('chartFrames'), {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Total Frames',
        data: framesData,
        backgroundColor: 'rgba(54, 162, 235, 0.6)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }]
    },
    options: { responsive: true, plugins: { legend: { display: false } } }
  });

  // --- Qtype chart ---
  var qtypeKeys = {};
  windowsData.forEach(function(w) {
    (w.qtype_distribution || []).forEach(function(e) { qtypeKeys[e.key] = true; });
  });
  var qtypeColors = ['#FF6384','#36A2EB','#FFCE56','#4BC0C0','#9966FF','#FF9F40','#C9CBCF','#E7E9ED'];
  var qtypeDatasets = Object.keys(qtypeKeys).map(function(key, idx) {
    return {
      label: key,
      data: windowsData.map(function(w) {
        var entry = (w.qtype_distribution || []).find(function(e) { return e.key === key; });
        return entry ? entry.count : 0;
      }),
      backgroundColor: qtypeColors[idx % qtypeColors.length],
      borderWidth: 1
    };
  });
  new Chart(document.getElementById('chartQtype'), {
    type: 'bar',
    data: { labels: labels, datasets: qtypeDatasets },
    options: { responsive: true, scales: { x: { stacked: true }, y: { stacked: true } } }
  });

  // --- Rcode chart ---
  var rcodeKeys = {};
  windowsData.forEach(function(w) {
    (w.rcode_distribution || []).forEach(function(e) { rcodeKeys[e.key] = true; });
  });
  var rcodeColors = ['#4BC0C0','#FF6384','#FFCE56','#9966FF','#36A2EB','#FF9F40'];
  var rcodeDatasets = Object.keys(rcodeKeys).map(function(key, idx) {
    return {
      label: key,
      data: windowsData.map(function(w) {
        var entry = (w.rcode_distribution || []).find(function(e) { return e.key === key; });
        return entry ? entry.count : 0;
      }),
      backgroundColor: rcodeColors[idx % rcodeColors.length],
      borderWidth: 1
    };
  });
  new Chart(document.getElementById('chartRcode'), {
    type: 'bar',
    data: { labels: labels, datasets: rcodeDatasets },
    options: { responsive: true, scales: { x: { stacked: true }, y: { stacked: true } } }
  });
})();
</script>

</body>
</html>

{{define "tables"}}
{{if .TopDomains}}
<h4>Top Queried Domains</h4>
<table>
<tr><th>#</th><th>Domain</th><th>Count</th></tr>
{{range $i, $e := .TopDomains}}<tr><td>{{inc $i}}</td><td>{{$e.Key}}</td><td>{{$e.Count}}</td></tr>
{{end}}
</table>
{{end}}

{{if .QtypeDist}}
<h4>Query Type Distribution</h4>
<table>
<tr><th>Type</th><th>Count</th></tr>
{{range .QtypeDist}}<tr><td>{{.Key}}</td><td>{{.Count}}</td></tr>
{{end}}
</table>
{{end}}

{{if .RcodeDist}}
<h4>Response Code Distribution</h4>
<table>
<tr><th>Rcode</th><th>Count</th></tr>
{{range .RcodeDist}}<tr><td>{{.Key}}</td><td>{{.Count}}</td></tr>
{{end}}
</table>
{{end}}

{{if .ClientIPs}}
<h4>Top Client IPs</h4>
<table>
<tr><th>#</th><th>Client IP</th><th>Count</th></tr>
{{range $i, $e := .ClientIPs}}<tr><td>{{inc $i}}</td><td>{{$e.Key}}</td><td>{{$e.Count}}</td></tr>
{{end}}
</table>
{{end}}
{{end}}`))

// snapshotForJSON is a JSON-serializable Snapshot with UTC time strings.
type snapshotForJSON struct {
	Start       string        `json:"start"`
	End         string        `json:"end"`
	TotalFrames uint64        `json:"total_frames"`
	TopDomains  []RankedEntry `json:"top_domains"`
	QtypeDist   []RankedEntry `json:"qtype_distribution"`
	RcodeDist   []RankedEntry `json:"rcode_distribution"`
	ClientIPs   []RankedEntry `json:"client_ips"`
}

func toJSON(s *Snapshot) snapshotForJSON {
	return snapshotForJSON{
		Start:       s.Start.UTC().Format(time.RFC3339),
		End:         s.End.UTC().Format(time.RFC3339),
		TotalFrames: s.TotalFrames,
		TopDomains:  s.TopDomains,
		QtypeDist:   s.QtypeDist,
		RcodeDist:   s.RcodeDist,
		ClientIPs:   s.ClientIPs,
	}
}

// RenderHTML writes the stats report as an HTML page to w.
func RenderHTML(w io.Writer, windows []*Snapshot, allTime *Snapshot) error {
	// Build JSON-serializable window list for chart data.
	jsonWindows := make([]snapshotForJSON, len(windows))
	for i, snap := range windows {
		jsonWindows[i] = toJSON(snap)
	}
	jsonBytes, err := json.Marshal(jsonWindows)
	if err != nil {
		return err
	}

	data := struct {
		Windows     []*Snapshot
		AllTime     *Snapshot
		WindowsJSON template.JS
	}{
		Windows:     windows,
		AllTime:     allTime,
		WindowsJSON: template.JS(jsonBytes),
	}
	return htmlTemplate.Execute(w, data)
}
