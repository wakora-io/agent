package redact

import (
	"regexp"
	"strings"
)

const mask = "***"

var urlInText = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'"<>|\\]+`)

var sensitiveHeader = regexp.MustCompile(`(?i)(authorization|cookie|token|api[_.\-]?key|secret|credential|password|passwd|session|signature|auth)`)

func Attr(key, value string) string {
	if value == "" {
		return value
	}
	if name, ok := headerName(key); ok {
		if sensitiveHeader.MatchString(name) {
			return mask
		}
		return value
	}
	switch key {
	case "url.query", "http.query":
		return maskQuery(value)
	}
	return URLish(value)
}

func URLish(s string) string {
	if strings.Contains(s, "://") {
		return urlInText.ReplaceAllStringFunc(s, maskURL)
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "?") {
		return maskPathQuery(s)
	}
	return s
}

func headerName(key string) (string, bool) {
	i := strings.Index(key, ".header.")
	if i < 0 {
		return "", false
	}
	return key[i+len(".header."):], true
}

func maskURL(u string) string {
	return maskPathQuery(maskUserinfo(dropFragment(u)))
}

func maskPathQuery(u string) string {
	u = dropFragment(u)
	i := strings.IndexByte(u, '?')
	if i < 0 {
		return u
	}
	return u[:i+1] + maskQuery(u[i+1:])
}

func dropFragment(u string) string {
	if i := strings.IndexByte(u, '#'); i >= 0 {
		return u[:i]
	}
	return u
}

func maskUserinfo(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	authority, tail := rest, ""
	if end := strings.IndexAny(rest, "/?"); end >= 0 {
		authority, tail = rest[:end], rest[end:]
	}
	at := strings.LastIndexByte(authority, '@')
	if at < 0 {
		return u
	}
	cred := authority[:at]
	if c := strings.IndexByte(cred, ':'); c >= 0 {
		cred = cred[:c+1] + mask
	}
	return u[:i+3] + cred + authority[at:] + tail
}

func maskQuery(q string) string {
	if q == "" {
		return q
	}
	parts := strings.Split(q, "&")
	for i, p := range parts {
		eq := strings.IndexByte(p, '=')
		if eq < 0 || eq == len(p)-1 {
			continue
		}
		parts[i] = p[:eq+1] + mask
	}
	return strings.Join(parts, "&")
}
