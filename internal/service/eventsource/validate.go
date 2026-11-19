package eventsource

import (
	"context"
	"fmt"

	"AegisPlus/CrystaL/internal/collector"
	"AegisPlus/CrystaL/internal/dto"
	"AegisPlus/CrystaL/internal/model"
)

// ValidateService điều phối kiểm tra channel theo nhóm sự kiện đã cấu hình.
type ValidateService struct{}

func (ValidateService) ValidateGroups(ctx context.Context, groups []model.EventGroup) ([]dto.EventSourceStatus, error) {
	if len(groups) == 0 {
		return []dto.EventSourceStatus{}, nil
	}
	checked := collector.ValidateEventSources(ctx, groups)
	out := make([]dto.EventSourceStatus, 0, len(checked))
	for i, item := range checked {
		out = append(out, dto.EventSourceStatus{
			Group: item.Group, Category: groups[i].Category, Channel: item.Channel, ChannelPresent: item.ChannelPresent,
			SampleFound: item.SampleFound, AccessDenied: item.AccessDenied,
			ChannelMissing: item.ChannelMissing, QueryError: item.QueryError, Detail: item.Detail,
		})
	}
	return out, nil
}

func (ValidateService) ValidateConfiguredGroups(ctx context.Context, cfg model.Config, groups []model.EventGroup) ([]dto.EventSourceStatus, error) {
	if cfg.EventConfigError != "" {
		return nil, fmt.Errorf("events.yaml không hợp lệ (%s): %s", cfg.EventsFile, cfg.EventConfigError)
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("không có nhóm event phù hợp trong %s", cfg.EventsFile)
	}
	return (ValidateService{}).ValidateGroups(ctx, groups)
}
