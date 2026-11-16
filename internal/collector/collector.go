package collector

import (
	"context"
	"strings"

	"AegisPlus/CrystaL/internal/model"
)

// Collector là hợp đồng chung để agent chạy và theo dõi sức khỏe từng nguồn dữ liệu.
type Collector interface {
	ID() string
	Run(ctx context.Context, emit func(model.CollectorRecord) error) error
	Health() model.CollectorHealth
}

// ClassifyWinErr gom lỗi Windows thành trạng thái dễ hiển thị trong CLI và log agent.
func ClassifyWinErr(err error) (status, reason, priv string) {
	if err == nil {
		return "available", "", "ok"
	}
	ls := strings.ToLower(err.Error())
	switch {
	case strings.Contains(ls, "access is denied") || strings.Contains(ls, "access denied") || strings.Contains(ls, "(5)"):
		return "unavailable", "access_denied", "insufficient"
	case strings.Contains(ls, "channel not found") || strings.Contains(ls, "evt_channel_not_found") || strings.Contains(ls, "15007"):
		return "unavailable", "channel_missing", "ok"
	case strings.Contains(ls, "no events") || strings.Contains(ls, "no more items") || strings.Contains(ls, "259"):
		return "available", "no_events", "ok"
	default:
		return "degraded", "error", "unknown"
	}
}
