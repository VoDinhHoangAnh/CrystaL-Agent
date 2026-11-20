package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"AegisPlus/CrystaL/internal/collector"
	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/processgraph"
	"AegisPlus/CrystaL/internal/store/jsonfile"

	"github.com/google/uuid"
)

// Run khởi tạo agent, dựng các collector và giữ chúng chạy đến khi nhận tín hiệu dừng.
func Run(ctx context.Context, cfg model.Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	if cfg.EventConfigError != "" {
		return fmt.Errorf("events.yaml không hợp lệ (%s): %s", cfg.EventsFile, cfg.EventConfigError)
	}
	id, err := loadOrCreateAgentID(cfg.AgentIDPath)
	if err != nil {
		return err
	}
	st, err := jsonfile.Open(cfg.JSONPath, 0)
	if err != nil {
		return fmt.Errorf("mở JSON state: %w", err)
	}
	defer st.Close()
	host, _ := os.Hostname()
	if err := st.EnsureAgent(ctx, id, host, runtime.GOOS, os.Getenv("OS"), runtime.GOARCH, model.AgentVersion); err != nil {
		return err
	}
	p := &Pipeline{Cfg: cfg, Store: st, Graph: processgraph.New(id), AgentID: id}
	if err := p.ReplayUnprocessed(ctx); err != nil {
		return fmt.Errorf("replay unprocessed events: %w", err)
	}

	cols := collector.WindowsCollectors(cfg,
		func(cid string) (string, int64, error) { return st.LoadCheckpoint(ctx, cid) },
		func(cid, bm string, rec int64) error {
			// Bookmark cần được ghi cả khi service đang shutdown.
			writeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return st.SaveCheckpoint(writeCtx, cid, bm, rec, time.Now().UTC())
		},
	)

	fmt.Println("PBRA agent starting")
	fmt.Printf("agent_id=%s version=%s analyzer=%s ruleset=%s\n", id, model.AgentVersion, model.AnalyzerVersion, model.RulesetVersion)
	fmt.Printf("data_dir=%s\n", cfg.DataDir)
	fmt.Printf("json_state=%s\n", cfg.JSONPath)
	if len(cols) == 0 {
		fmt.Println("collectors=none (this build has no live Windows adapters; ingest/replay still work)")
	}
	for _, c := range cols {
		h := c.Health()
		fmt.Printf("collector %s status=%s reason=%s\n", c.ID(), nz(h.Status, "starting"), h.Reason)
	}
	fmt.Println("policy=observe-only (no block/kill/quarantine, no audit policy change)")

	// Collector chạy song song nhưng checkpoint chỉ được xác nhận khi ingest
	// hoàn thành: enqueue không đồng nghĩa đã ghi bền vững.
	type queuedRecord struct {
		rec model.CollectorRecord
		ack chan error
	}
	q := make(chan queuedRecord, cfg.QueueSize)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for item := range q {
			// Drain các bản ghi đã chấp nhận kể cả khi ctx chạy chính bị hủy.
			writeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := p.Ingest(writeCtx, item.rec)
			cancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "ingest error: %v\n", err)
			}
			item.ack <- err
		}
	}()

	emit := func(rec model.CollectorRecord) error {
		item := queuedRecord{rec: rec, ack: make(chan error, 1)}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case q <- item:
		}
		select {
		case err := <-item.ack:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Persist health trong khi collector đang chạy, không chỉ lúc dừng.
	healthDone := make(chan struct{})
	go func() {
		defer close(healthDone)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, c := range cols {
					wctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					_ = st.SaveHealth(wctx, c.Health())
					cancel()
				}
			}
		}
	}()

	var cwg sync.WaitGroup
	for _, c := range cols {
		c := c
		cwg.Add(1)
		go func() {
			defer cwg.Done()
			err := c.Run(ctx, emit)
			h := c.Health()
			if err != nil && h.LastError == "" {
				h.LastError = err.Error()
				stt, reason, priv := collector.ClassifyWinErr(err)
				h.Status, h.Reason, h.PrivilegeStatus = stt, reason, priv
			}
			_ = st.SaveHealth(context.Background(), h)
			fmt.Printf("collector %s stopped status=%s reason=%s\n", c.ID(), h.Status, h.Reason)
		}()
	}

	<-ctx.Done()
	<-healthDone
	cwg.Wait()
	close(q)
	wg.Wait()
	return nil
}

// Status đọc thống kê đã lưu để xem agent đang có bao nhiêu dữ liệu và collector nào lỗi.
func Status(ctx context.Context, cfg model.Config) error {
	st, err := jsonfile.OpenReadOnly(cfg.JSONPath)
	if err != nil {
		return err
	}
	defer st.Close()
	s, err := st.Stats(ctx, cfg.JSONPath, cfg.DataDir)
	if err != nil {
		return err
	}
	fmt.Printf("json=%s\ndata=%s bytes=%d\nevents=%d raw_pending=%d tracking_current=%d last_event=%s\n",
		s.JSONPath, s.DataDir, s.RawBytes, s.TelemetryCount, s.RawUnprocessed, s.CurrentTracked, s.LastEventTime)
	if len(s.Collectors) == 0 {
		fmt.Println("collectors: (none recorded yet; run the agent first)")
	}
	for _, h := range s.Collectors {
		fmt.Printf("collector %s status=%s reason=%s events=%d last_error=%s\n", h.CollectorID, h.Status, h.Reason, h.EventsSeen, sanitize(h.LastError))
	}
	return nil
}

func loadOrCreateAgentID(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	id := uuid.NewString()
	return id, os.WriteFile(path, []byte(id+"\n"), 0o600)
}

func nz(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func sanitize(s string) string {
	if privacyContains(s) {
		return "[redacted-error]"
	}
	return s
}

func privacyContains(s string) bool {
	ls := strings.ToLower(s)
	return strings.Contains(ls, "password") && strings.Contains(ls, "=")
}
