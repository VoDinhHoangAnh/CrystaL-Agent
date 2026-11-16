package tracking

import (
	"context"
)

type caseCloser interface {
	CloseCase(context.Context, string, string, string) error
}

// ShouldTrack quyết định severity nào được đưa vào danh sách theo dõi hiện hành.
func ShouldTrack(severity string, trackMedium bool) bool {
	switch severity {
	case "high", "critical":
		return true
	case "medium":
		return trackMedium
	default:
		return false
	}
}

// Close đóng một case và lưu lý do cùng người thực hiện.
func Close(ctx context.Context, st caseCloser, id, reason, actor string) error {
	if actor == "" {
		actor = "operator"
	}
	if reason == "" {
		reason = "closed"
	}
	return st.CloseCase(ctx, id, reason, actor)
}
