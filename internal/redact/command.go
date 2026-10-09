package redact

import (
	"regexp"
	"strings"
)

var longToken = regexp.MustCompile(`(^|[\s=:"',;(])([A-Za-z0-9_+\-]{24,}={0,2})`)

var pathToken = regexp.MustCompile(`^(?:[A-Za-z0-9_\-]{16,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)

func ScrubCommand(s string) string {
	s = Scrub(s)
	s = urlInText.ReplaceAllStringFunc(s, maskCommandURL)
	return longToken.ReplaceAllStringFunc(s, func(m string) string {
		sub := longToken.FindStringSubmatch(m)
		if !tokenShaped(sub[2]) {
			return m
		}
		return sub[1] + mask
	})
}

func maskCommandURL(u string) string {
	u = maskURL(u)
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return u
	}
	path, query := rest[slash:], ""
	if q := strings.IndexByte(path, '?'); q >= 0 {
		path, query = path[:q], path[q:]
	}
	segs := strings.Split(path, "/")
	for k, seg := range segs {
		if pathToken.MatchString(seg) && tokenShaped(seg) {
			segs[k] = mask
		}
	}
	return u[:i+3] + rest[:slash] + strings.Join(segs, "/") + query
}

func tokenShaped(s string) bool {
	digit, letter := false, false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
			letter = true
		}
	}
	return digit && letter
}
