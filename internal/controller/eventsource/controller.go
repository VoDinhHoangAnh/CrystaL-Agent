package eventsource

import (
	"context"

	"AegisPlus/CrystaL/internal/dto"
	"AegisPlus/CrystaL/internal/model"
	eventsourceservice "AegisPlus/CrystaL/internal/service/eventsource"
)

// Controller chuyển yêu cầu kiểm tra nguồn event sang service tương ứng.
type Controller struct {
	service eventsourceservice.ValidateService
}

func NewController() Controller {
	return Controller{service: eventsourceservice.ValidateService{}}
}

func (c Controller) ValidateGroups(ctx context.Context, cfg model.Config, groups []model.EventGroup) ([]dto.EventSourceStatus, error) {
	return c.service.ValidateConfiguredGroups(ctx, cfg, groups)
}
