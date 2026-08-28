package redact

import "regexp"

type rule struct {
	re   *regexp.Regexp
	repl string
}

var rules = []rule{
	{regexp.MustCompile(`(?i)(authorization:?\s*bearer\s+)\S+`), "${1}***"},
	{regexp.MustCompile(`(?i)((?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*["']?\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)`), "${1}***"},
	{regexp.MustCompile(`(?i)(--(?:password|passwd|pwd|token|secret|api[_-]?key)[= ]\s*)("[^"]*"|'[^']*'|\S+)`), "${1}***"},
	{regexp.MustCompile(`([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY)=)("[^"]*"|'[^']*'|\S+)`), "${1}***"},
	{regexp.MustCompile(`(?i)(\b(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mariadb|mariadb-dump)\b[^\n]*?\s-p)([^\s-]\S*)`), "${1}***"},
	{regexp.MustCompile(`(?i)(\bcurl\b[^\n]*?\s-u\s*\S*?:)(\S+)`), "${1}***"},
	{regexp.MustCompile(`(-----BEGIN [A-Z ]*PRIVATE KEY-----).*`), "${1}***"},
	{regexp.MustCompile(`(://[^:/@\s]+:)[^@/\s]+(@)`), "${1}***${2}"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "***"},
	{regexp.MustCompile(`\b(?:\d[ -]?){13,16}\b`), "***"},
}

func Scrub(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}
