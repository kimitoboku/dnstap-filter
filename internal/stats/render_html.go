package stats

import (
	"html/template"
	"io"
)

var htmlFuncs = template.FuncMap{
	"inc": func(i int) int { return i + 1 },
}

var htmlTemplate = template.Must(template.New("stats").Funcs(htmlFuncs).Parse(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>dnstap-filter Statistics</title>
<style>
  body { font-family: sans-serif; margin: 2em; background: #fafafa; color: #333; }
  h1 { color: #1a1a2e; }
  h2 { color: #16213e; margin-top: 2em; border-bottom: 2px solid #e2e2e2; padding-bottom: 0.3em; }
  h3 { color: #0f3460; }
  table { border-collapse: collapse; margin: 1em 0; min-width: 300px; }
  th, td { border: 1px solid #ddd; padding: 6px 12px; text-align: left; }
  th { background: #e8e8e8; }
  tr:nth-child(even) { background: #f5f5f5; }
  .summary { font-size: 1.1em; margin: 0.5em 0; }
  .window { margin-bottom: 2em; padding: 1em; background: #fff; border: 1px solid #e0e0e0; border-radius: 4px; }
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
<h2>Time Windows</h2>
{{range $i, $w := .Windows}}
<div class="window">
<h3>Window {{inc $i}}: {{$w.Start.Format "2006-01-02 15:04:05"}} &mdash; {{$w.End.Format "2006-01-02 15:04:05"}} ({{$w.TotalFrames}} frames)</h3>
{{template "tables" $w}}
</div>
{{end}}
{{end}}

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

// RenderHTML writes the stats report as an HTML page to w.
func RenderHTML(w io.Writer, windows []*Snapshot, allTime *Snapshot) error {
	data := struct {
		Windows []*Snapshot
		AllTime *Snapshot
	}{
		Windows: windows,
		AllTime: allTime,
	}
	return htmlTemplate.Execute(w, data)
}
