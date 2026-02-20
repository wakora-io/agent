package defs

import "strings"

func hypervVMGuid(instanceID string) string {
	s, ok := strings.CutPrefix(instanceID, "Microsoft:")
	if !ok {
		return ""
	}
	if i := strings.IndexByte(s, '\\'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

func hypervStateName(state uint16) string {
	switch state {
	case 2:
		return "running"
	case 3:
		return "off"
	case 6:
		return "saved"
	case 9:
		return "paused"
	default:
		return "other"
	}
}

func looksLikeGuid(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
