package process

import (
	"AegisPlus/CrystaL/internal/dto"
	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/repository"
	"context"
)

const Category = "process"

// EventGroups chọn các nguồn event dùng để dựng lịch sử tiến trình.
func EventGroups(cfg model.Config) []model.EventGroup {
	out := make([]model.EventGroup, 0)
	for _, group := range cfg.EventGroups {
		if group.Category == Category {
			out = append(out, group)
		}
	}
	return out
}

// TraceService truy vấn timeline qua interface lưu trữ, không phụ thuộc JSON backend.
type TraceService struct{ repository repository.Repository }

func NewTraceService(repo repository.Repository) TraceService {
	return TraceService{repository: repo}
}

// Get trả về cây tiến trình, event và các TCP flow khớp PID hoặc Process GUID.
func (s TraceService) Get(ctx context.Context, selector string) (dto.ProcessTrace, error) {
	return s.repository.TraceProcess(ctx, selector)
}
