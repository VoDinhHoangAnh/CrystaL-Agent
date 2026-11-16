//go:build windows

package collector

import (
	"AegisPlus/CrystaL/internal/model"
)

// WindowsCollectors lắp các nguồn Event Log và snapshot process/network trên Windows.
func WindowsCollectors(cfg model.Config, loadBookmark func(id string) (string, int64, error), saveBookmark func(id, bm string, rec int64) error) []Collector {
	out := eventLogCollectors(cfg, loadBookmark, saveBookmark)
	out = append(out, newProcessSnapshot(cfg.SnapshotEvery), newNetworkSnapshot(cfg.SnapshotEvery))
	return out
}
