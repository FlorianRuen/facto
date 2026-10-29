package secret

import (
	"fmt"
	"strings"
)

// Reference schemes understood by ParseRef.
const (
	SchemeBitwarden = "bw"
	SchemeKeyring   = "keyring"
)

// Ref is a parsed, canonical secret reference. Refs are not secret.
type Ref struct {
	// Scheme is "bw" or "keyring".
	Scheme string
	// Item is the Bitwarden item UUID (lowercase canonical form) or the
	// keyring service.
	Item string
	// Field is the Bitwarden field ("username", "password" or "totp") or the
	// keyring key, which may contain "/".
	Field string
}

// String returns the canonical form "bw://<uuid>/<field>" or
// "keyring://<service>/<key>". ParseRef(r.String()) == r for a parsed Ref.
func (r Ref) String() string {
	return r.Scheme + "://" + r.Item + "/" + r.Field
}

// invalid builds an ErrInvalidRef error with a fixed reason. The reason must
// never contain the input: a plaintext password pasted in the config would
// otherwise reach logs and reports.
func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRef, reason)
}

// ParseRef parses a reference. Accepted forms, nothing else:
//
//	bw://<uuid>/<username|password|totp>
//	    uuid: 8-4-4-4-12 hex digits, any case, normalized to lowercase.
//	    Items are resolved by UUID only: a name is refused.
//	keyring://<service>/<key>
//	    service: one segment; key: one or more segments separated by "/".
//	    Segments match [A-Za-z0-9._-]+ and are neither "." nor "..".
//
// The scheme is lowercase; whitespace, userinfo, port, query, fragment,
// percent-encoding, empty segments and a trailing "/" are refused. Every
// failure wraps ErrInvalidRef and its message never contains the input.
func ParseRef(s string) (Ref, error) {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return Ref{}, invalid("not a reference (want bw:// or keyring://)")
	}
	switch scheme {
	case SchemeBitwarden:
		return parseBitwarden(rest)
	case SchemeKeyring:
		return parseKeyring(rest)
	default:
		return Ref{}, invalid("unknown scheme (want bw or keyring)")
	}
}

func parseBitwarden(rest string) (Ref, error) {
	item, field, ok := strings.Cut(rest, "/")
	if !ok {
		return Ref{}, invalid("bw: missing field")
	}
	if !isUUID(item) {
		return Ref{}, invalid("bw: item must be a UUID (8-4-4-4-12 hex digits)")
	}
	switch field {
	case "username", "password", "totp":
	default:
		return Ref{}, invalid("bw: field must be username, password or totp")
	}
	return Ref{Scheme: SchemeBitwarden, Item: strings.ToLower(item), Field: field}, nil
}

func parseKeyring(rest string) (Ref, error) {
	service, key, ok := strings.Cut(rest, "/")
	if !ok {
		return Ref{}, invalid("keyring: missing key")
	}
	if !isSegment(service) {
		return Ref{}, invalid("keyring: invalid service")
	}
	for seg := range strings.SplitSeq(key, "/") {
		if !isSegment(seg) {
			return Ref{}, invalid("keyring: invalid key")
		}
	}
	return Ref{Scheme: SchemeKeyring, Item: service, Field: key}, nil
}

// isUUID reports whether s is 8-4-4-4-12 hex digits.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHex(c) {
				return false
			}
		}
	}
	return true
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// isSegment reports whether s matches [A-Za-z0-9._-]+ and is not "." or "..".
func isSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for i := range len(s) {
		c := s[i]
		ok := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
			c == '.' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}
