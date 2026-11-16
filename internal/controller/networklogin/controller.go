package networklogin

import (
	"AegisPlus/CrystaL/internal/controller/eventsource"
	"AegisPlus/CrystaL/internal/dto"
	"AegisPlus/CrystaL/internal/model"
	loginservice "AegisPlus/CrystaL/internal/service/networklogin"
	"context"
)

type Controller struct{ sources eventsource.Controller }

func NewController() Controller { return Controller{sources: eventsource.NewController()} }

func (c Controller) ValidateSources(ctx context.Context, cfg model.Config) ([]dto.EventSourceStatus, error) {
	return c.sources.ValidateGroups(ctx, cfg, loginservice.EventGroups(cfg))
}
