//go:build !windows

package collector

import "AegisPlus/CrystaL/internal/model"

// WindowsCollectors trả danh sách rỗng trên hệ điều hành chưa có bộ thu thập tương ứng.
func WindowsCollectors(cfg model.Config, loadBookmark func(id string) (string, int64, error), saveBookmark func(id, bm string, rec int64) error) []Collector {
	return nil
}
