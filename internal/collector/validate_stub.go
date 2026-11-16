//go:build !windows

package collector

import (
	"context"

	"AegisPlus/CrystaL/internal/model"
)

type SourceValidation struct {
	Group          string
	Channel        string
	ChannelPresent bool
	SampleFound    bool
	AccessDenied   bool
	ChannelMissing bool
	Detail         string
}

func ValidateEventSources(_ context.Context, groups []model.EventGroup) []SourceValidation {
	results := make([]SourceValidation, 0, len(groups))
	for _, group := range groups {
		results = append(results, SourceValidation{Group: group.Name, Channel: group.Channel, Detail: "Chỉ kiểm tra trực tiếp trên Windows."})
	}
	return results
}
