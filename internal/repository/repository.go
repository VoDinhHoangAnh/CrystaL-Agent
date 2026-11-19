// Package repository định nghĩa hợp đồng lưu trữ mà các service sử dụng.
package repository

import (
	"context"
	"time"

	"AegisPlus/CrystaL/internal/dto"
	"AegisPlus/CrystaL/internal/model"
)

// Repository tách luồng xử lý khỏi cách lưu cụ thể để có thể thay backend về sau.
type Repository interface {
	Path() string
	Close() error
	EnsureAgent(context.Context, string, string, string, string, string, string) error
	AppendRaw(context.Context, model.RawEnvelope) error
	InsertRawIndex(context.Context, model.RawEnvelope, string, int64, string) error
	MarkRawProcessed(context.Context, string) error
	UnprocessedRaw(context.Context, int) ([]model.RawEnvelope, error)
	EventExists(context.Context, string, string, string) (bool, error)
	RecentAuthFailures(context.Context, model.AuthenticationFacts, time.Time, time.Time) ([]model.Normalized, error)
	PersistAnalyzed(context.Context, model.PersistInput) error
	ListCurrentTracking(context.Context) ([]model.TrackedEntity, error)
	GetTracked(context.Context, string) (model.TrackedEntity, []model.Finding, error)
	CloseCase(context.Context, string, string, string) error
	SaveCheckpoint(context.Context, string, string, int64, time.Time) error
	LoadCheckpoint(context.Context, string) (string, int64, error)
	SaveHealth(context.Context, model.CollectorHealth) error
	Stats(context.Context, string, string) (model.Stats, error)
	RunRetention(context.Context, time.Time, time.Time, time.Time) error
	SessionFiredRules(context.Context, string) (map[string]bool, error)
	TraceProcess(context.Context, string) (dto.ProcessTrace, error)
}
