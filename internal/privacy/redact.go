package privacy

import (
	"regexp"
	"strings"

	"AegisPlus/CrystaL/internal/model"
)

// Redaction is intentionally conservative for known sensitive key/value patterns.
// Unknown formats and arbitrary free-form secrets are NOT guaranteed safe.
var (
	assignment = regexp.MustCompile(`(?i)(?:--?|/)?(?:password|passwd|pwd|token|api[_-]?key|client[_-]?secret|secret)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
	spacedFlag = regexp.MustCompile(`(?i)(?:--?|/)(?:password|passwd|pwd|token|api[_-]?key|client[_-]?secret|secret)\s+(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
	authHeader = regexp.MustCompile(`(?i)(?:authorization\s*:\s*)?bearer\s+(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
)

// RedactCommandLine masks recognized credentials without retaining their values.
func RedactCommandLine(cmd string) model.Redaction {
	if cmd == "" {
		return model.Redaction{Redacted: cmd}
	}
	found := assignment.MatchString(cmd) || spacedFlag.MatchString(cmd) || authHeader.MatchString(cmd)
	if !found {
		return model.Redaction{Redacted: cmd}
	}
	out := assignment.ReplaceAllStringFunc(cmd, func(s string) string {
		idx := strings.IndexAny(s, ":=")
		if idx < 0 { return "[REDACTED]" }
		return s[:idx+1] + "[REDACTED]"
	})
	out = spacedFlag.ReplaceAllStringFunc(out, func(s string) string {
		fields := strings.Fields(s)
		if len(fields) == 0 { return "[REDACTED]" }
		return fields[0] + " [REDACTED]"
	})
	out = authHeader.ReplaceAllStringFunc(out, func(s string) string {
		i := strings.Index(strings.ToLower(s), "bearer")
		if i < 0 { return "[REDACTED]" }
		return s[:i+len("bearer")] + " [REDACTED]"
	})
	return model.Redaction{Redacted: out, Indicator: true, PatternType: "credential", Field: "command_line"}
}

func ContainsSecret(s string) bool {
	return assignment.MatchString(s) || spacedFlag.MatchString(s) || authHeader.MatchString(s)
}

func AssertNoSecret(haystack, originalCmd string) bool {
	redacted := RedactCommandLine(originalCmd)
	if !redacted.Indicator { return true }
	// A safe positive only when the original recognized matches are not reproduced.
	for _, re := range []*regexp.Regexp{assignment, spacedFlag, authHeader} {
		for _, m := range re.FindAllString(originalCmd, -1) {
			if m == "" { continue }
			var secret string
			if i := strings.IndexAny(m, ":="); i >= 0 {
				secret = strings.TrimSpace(m[i+1:])
				if strings.EqualFold(secret, "Bearer") {
					secret = ""
				}
			} else if f := strings.Fields(m); len(f) > 1 {
				secret = f[len(f)-1]
			}
			secret = strings.Trim(secret, "\"'")
			if secret != "" && strings.Contains(haystack, secret) {
				return false
			}
		}
	}
	return true
}
