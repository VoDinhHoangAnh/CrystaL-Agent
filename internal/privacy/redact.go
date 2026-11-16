package privacy

import (
	"regexp"
	"strings"

	"AegisPlus/CrystaL/internal/model"
)

var secretPattern = regexp.MustCompile(`(?i)((?:password|passwd|pwd|token|api[_-]?key|client[_-]?secret|authorization|bearer|secret))\s*[:=]\s*([^\s,;]+)`)

// RedactCommandLine che giá trị tham số có vẻ là bí mật nhưng giữ lại tên tham số.
func RedactCommandLine(cmd string) model.Redaction {
	if cmd == "" {
		return model.Redaction{Redacted: cmd}
	}
	if !secretPattern.MatchString(cmd) {
		return model.Redaction{Redacted: cmd}
	}
	out := secretPattern.ReplaceAllStringFunc(cmd, func(m string) string {
		sub := secretPattern.FindStringSubmatch(m)
		if len(sub) >= 2 {
			return sub[1] + "=[REDACTED]"
		}
		return "[REDACTED]"
	})
	kind := "credential_assignment"
	if sub := secretPattern.FindStringSubmatch(cmd); len(sub) >= 2 {
		kind = strings.ToLower(sub[1])
	}
	return model.Redaction{Redacted: out, Indicator: true, PatternType: kind, Field: "command_line"}
}

// ContainsSecret chỉ báo có dấu hiệu bí mật; hàm không trả lại giá trị tìm thấy.
func ContainsSecret(s string) bool {
	return secretPattern.MatchString(s)
}

func AssertNoSecret(haystack, originalCmd string) bool {
	m := secretPattern.FindStringSubmatch(originalCmd)
	if len(m) < 3 {
		return true
	}
	return !strings.Contains(haystack, m[2])
}
