//go:build windows

package collector

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"AegisPlus/CrystaL/internal/model"

	"golang.org/x/sys/windows"
)

type processSnapshot struct {
	every  time.Duration
	mu     sync.Mutex
	health model.CollectorHealth
	prev   map[uint32]model.ProcessFacts
}

func newProcessSnapshot(every time.Duration) *processSnapshot {
	if every <= 0 {
		every = 30 * time.Second
	}
	return &processSnapshot{
		every:  every,
		prev:   map[uint32]model.ProcessFacts{},
		health: model.CollectorHealth{CollectorID: "snapshot:process", Status: "available", Reason: "fallback_reconciliation", PrivilegeStatus: "ok"},
	}
}

func (c *processSnapshot) ID() string { return "snapshot:process" }
func (c *processSnapshot) Health() model.CollectorHealth {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

func (c *processSnapshot) Run(ctx context.Context, emit func(model.CollectorRecord) error) error {
	ticker := time.NewTicker(c.every)
	defer ticker.Stop()
	// Lần quét đầu tạo baseline; chỉ các thay đổi ở những lần sau mới được phát thành event.
	c.scan(emit, true)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.scan(emit, false)
		}
	}
}

func (c *processSnapshot) scan(emit func(model.CollectorRecord) error, first bool) {
	cur, err := listProcesses()
	if err != nil {
		st, reason, priv := ClassifyWinErr(err)
		c.mu.Lock()
		c.health.Status = st
		c.health.Reason = reason
		c.health.PrivilegeStatus = priv
		c.health.LastError = err.Error()
		c.health.LastErrorAt = time.Now().UTC()
		c.mu.Unlock()
		return
	}
	now := time.Now().UTC()
	c.mu.Lock()
	prev := c.prev
	c.prev = cur
	c.health.Status = "available"
	c.health.Reason = "fallback_reconciliation"
	c.health.LastSuccessAt = now
	c.mu.Unlock()
	if first {
		return
	}
	for pid, p := range cur {
		if _, ok := prev[pid]; ok {
			continue
		}
		p := p
		key := "snapshot|process|" + itoa32(pid) + "|" + p.ImageName
		_ = emit(model.CollectorRecord{
			Source: "snapshot.process", SourceEventKey: key, EventTime: now,
			Kind: "process", Snapshot: true, Process: &p,
		})
		c.mu.Lock()
		c.health.EventsSeen++
		c.mu.Unlock()
	}
	for pid, p := range prev {
		if _, ok := cur[pid]; ok {
			continue
		}
		p := p
		p.Action = "terminate"
		p.EndedAt = now
		key := "snapshot|process|exit|" + itoa32(pid) + "|" + now.Format(time.RFC3339)
		_ = emit(model.CollectorRecord{
			Source: "snapshot.process", SourceEventKey: key, EventTime: now,
			Kind: "process", Snapshot: true, Process: &p,
		})
	}
}

func listProcesses() (map[uint32]model.ProcessFacts, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return nil, err
	}
	out := map[uint32]model.ProcessFacts{}
	for {
		name := windows.UTF16ToString(pe.ExeFile[:])
		p := model.ProcessFacts{
			PID: int64(pe.ProcessID), PPID: int64(pe.ParentProcessID),
			ImageName: name, Action: "create",
		}
		if path, ok := imagePath(pe.ProcessID); ok {
			p.ImagePath = path
			if p.ImageName == "" {
				p.ImageName = base(path)
			}
		}
		out[pe.ProcessID] = p
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return out, nil
}

func imagePath(pid uint32) (string, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)
	var buf [windows.MAX_PATH]uint16
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", false
	}
	return windows.UTF16ToString(buf[:n]), true
}

func itoa32(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}

func base(p string) string {
	p = strings.ReplaceAll(p, "/", "\\")
	if i := strings.LastIndex(p, "\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}
