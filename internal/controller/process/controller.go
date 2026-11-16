package process

import (
	eventsourcecontroller "AegisPlus/CrystaL/internal/controller/eventsource"
	"AegisPlus/CrystaL/internal/dto"
	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/repository"
	processservice "AegisPlus/CrystaL/internal/service/process"
	"context"
)

// Controller nhận yêu cầu tra cứu process và chuyển cho TraceService.
type Controller struct{ service processservice.TraceService }

func NewController(repo repository.Repository) Controller {
	return Controller{service: processservice.NewTraceService(repo)}
}

func (c Controller) Trace(ctx context.Context, selector string) (dto.ProcessTrace, error) {
	return c.service.Get(ctx, selector)
}

func ValidateSources(ctx context.Context, cfg model.Config) ([]dto.EventSourceStatus, error) {
	return eventsourcecontroller.NewController().ValidateGroups(ctx, cfg, processservice.EventGroups(cfg))
}
