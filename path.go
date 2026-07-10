package receipt

import "strings"

// Templatize collapses id-like path segments (numeric, uuid, long hex) to {id}
// so receipts are comparable across runs and don't leak ids into the path. It is
// generic and shared by every agent's classifier before recording an Entry.Path.
func Templatize(path string) string {
	if path == "" {
		return path
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if isIDLike(s) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}

func isIDLike(s string) bool {
	if s == "" {
		return false
	}
	if isAllDigits(s) {
		return true
	}
	if isUUID(s) {
		return true
	}
	// Long opaque hex tokens (e.g. 32-char ids) but not ordinary words.
	if len(s) >= 16 && isHex(s) {
		return true
	}
	return false
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
