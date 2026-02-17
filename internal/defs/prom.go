package defs

import (
	"strconv"
	"strings"

	"wakora.io/agent/internal/protocol"
)

const promMaxSeriesPerRule = 200

func applyProm(o *Outcome, rules []protocol.PromRule, body []byte) {
	if len(rules) == 0 {
		return
	}
	want := map[string][]protocol.PromRule{}
	for _, r := range rules {
		want[r.Metric] = append(want[r.Metric], r)
	}
	counts := map[string]int{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		name, labels, value, ok := parsePromLine(line)
		if !ok {
			continue
		}
		for _, r := range want[name] {
			if counts[r.Name] >= promMaxSeriesPerRule {
				continue
			}
			counts[r.Name]++
			var tags map[string]string
			if len(r.Tags) > 0 {
				tags = map[string]string{}
				for _, t := range r.Tags {
					if v, ok := labels[t]; ok {
						tags[t] = v
					}
				}
			}
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: r.Name, Value: value, Tags: tags})
		}
	}
}

func parsePromLine(line string) (name string, labels map[string]string, value float64, ok bool) {
	i := 0
	for i < len(line) && isPromNameChar(line[i]) {
		i++
	}
	if i == 0 {
		return "", nil, 0, false
	}
	name = line[:i]
	rest := line[i:]
	if strings.HasPrefix(rest, "{") {
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return "", nil, 0, false
		}
		labels = parsePromLabels(rest[1:end])
		rest = rest[end+1:]
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", nil, 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "", nil, 0, false
	}
	return name, labels, v, true
}

func parsePromLabels(s string) map[string]string {
	out := map[string]string{}
	for _, part := range splitPromLabels(s) {
		k, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return out
}

func splitPromLabels(s string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			b.WriteByte(c)
		case c == ',' && !inQuote:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func isPromNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == ':'
}
