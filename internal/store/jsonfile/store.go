// Package jsonfile lưu toàn bộ trạng thái cục bộ của agent trong một tài liệu JSON.
package jsonfile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"AegisPlus/CrystaL/internal/dto"
	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/repository"
	"github.com/google/uuid"
)

type RawRecord struct {
	Envelope    model.RawEnvelope `json:"envelope"`
	Processed   bool              `json:"processed"`
	ProcessedAt time.Time         `json:"processed_at,omitempty"`
}
type AnalyzedRecord struct {
	Data model.PersistInput `json:"data"`
}
type AgentRecord struct {
	ID           string    `json:"id"`
	Host         string    `json:"host"`
	OS           string    `json:"os"`
	OSVersion    string    `json:"os_version"`
	Architecture string    `json:"architecture"`
	Version      string    `json:"version"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	Status       string    `json:"status"`
}
type Checkpoint struct {
	Bookmark  string    `json:"bookmark"`
	RecordID  int64     `json:"record_id"`
	EventTime time.Time `json:"event_time,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Transition struct {
	ID       string    `json:"id"`
	EntityID string    `json:"entity_id"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Actor    string    `json:"actor"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
}
type Document struct {
	SchemaVersion  int                              `json:"schema_version"`
	UpdatedAt      time.Time                        `json:"updated_at"`
	Agents         []AgentRecord                    `json:"agents"`
	RawEvents      []RawRecord                      `json:"raw_events"`
	AnalyzedEvents []AnalyzedRecord                 `json:"analyzed_events"`
	Checkpoints    map[string]Checkpoint            `json:"checkpoints"`
	Collectors     map[string]model.CollectorHealth `json:"collectors"`
	Tracked        []model.TrackedEntity            `json:"tracked_entities"`
	Findings       map[string][]model.Finding       `json:"findings"`
	Transitions    []Transition                     `json:"transitions"`
}

type Store struct {
	path string
	mu   sync.Mutex
	doc  Document
}

var _ repository.Repository = (*Store)(nil)

// Open nạp JSON hiện có hoặc tạo tài liệu khởi đầu nếu đây là lần chạy đầu.
func Open(path string, _ int) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: path, doc: emptyDocument()}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &s.doc); err != nil {
			return nil, fmt.Errorf("đọc JSON state %s: %w", path, err)
		}
		s.normalize()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return s, nil
}
func emptyDocument() Document {
	return Document{SchemaVersion: 1, Agents: []AgentRecord{}, RawEvents: []RawRecord{}, AnalyzedEvents: []AnalyzedRecord{}, Checkpoints: map[string]Checkpoint{}, Collectors: map[string]model.CollectorHealth{}, Tracked: []model.TrackedEntity{}, Findings: map[string][]model.Finding{}, Transitions: []Transition{}}
}
func (s *Store) normalize() {
	if s.doc.SchemaVersion == 0 {
		s.doc.SchemaVersion = 1
	}
	if s.doc.Agents == nil {
		s.doc.Agents = []AgentRecord{}
	}
	if s.doc.RawEvents == nil {
		s.doc.RawEvents = []RawRecord{}
	}
	if s.doc.AnalyzedEvents == nil {
		s.doc.AnalyzedEvents = []AnalyzedRecord{}
	}
	if s.doc.Checkpoints == nil {
		s.doc.Checkpoints = map[string]Checkpoint{}
	}
	if s.doc.Collectors == nil {
		s.doc.Collectors = map[string]model.CollectorHealth{}
	}
	if s.doc.Tracked == nil {
		s.doc.Tracked = []model.TrackedEntity{}
	}
	if s.doc.Findings == nil {
		s.doc.Findings = map[string][]model.Finding{}
	}
	if s.doc.Transitions == nil {
		s.doc.Transitions = []Transition{}
	}
}
func (s *Store) Close() error { return nil }
func (s *Store) Path() string { return s.path }
func (s *Store) saveLocked() error {
	s.doc.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(s.doc, "", "  ")
	if err != nil {
		return err
	}
	// Ghi file tạm rồi rename để tránh để lại JSON dở dang nếu tiến trình dừng giữa chừng.
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
func (s *Store) EnsureAgent(ctx context.Context, id, host, osName, osVersion, arch, version string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for i := range s.doc.Agents {
		if s.doc.Agents[i].ID == id {
			a := &s.doc.Agents[i]
			a.LastSeenAt = now
			a.Version = version
			a.Status = "running"
			return s.saveLocked()
		}
	}
	s.doc.Agents = append(s.doc.Agents, AgentRecord{ID: id, Host: host, OS: osName, OSVersion: osVersion, Architecture: arch, Version: version, EnrolledAt: now, LastSeenAt: now, Status: "running"})
	return s.saveLocked()
}
func (s *Store) AppendRaw(ctx context.Context, env model.RawEnvelope) error {
	return s.InsertRawIndex(ctx, env, s.path, 0, "")
}
func (s *Store) InsertRawIndex(ctx context.Context, env model.RawEnvelope, path string, offset int64, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.doc.RawEvents {
		if r.Envelope.EventID == env.EventID || (r.Envelope.AgentID == env.AgentID && r.Envelope.Source == env.Source && r.Envelope.SourceEventKey == env.SourceEventKey) {
			return nil
		}
	}
	env.SpoolPath = path
	env.SpoolOffset = offset
	s.doc.RawEvents = append(s.doc.RawEvents, RawRecord{Envelope: env})
	return s.saveLocked()
}
func (s *Store) MarkRawProcessed(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.doc.RawEvents {
		if s.doc.RawEvents[i].Envelope.EventID == id {
			s.doc.RawEvents[i].Processed = true
			s.doc.RawEvents[i].ProcessedAt = time.Now().UTC()
			return s.saveLocked()
		}
	}
	return nil
}
func (s *Store) UnprocessedRaw(ctx context.Context, limit int) ([]model.RawEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 500
	}
	out := []model.RawEnvelope{}
	for _, r := range s.doc.RawEvents {
		if !r.Processed {
			r.Envelope.SpoolPath = s.path
			out = append(out, r.Envelope)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}
func (s *Store) EventExists(ctx context.Context, agentID, source, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.doc.AnalyzedEvents {
		n := r.Data.Norm
		if n.AgentID == agentID && n.Source == source && n.SourceEventKey == key {
			return true, nil
		}
	}
	return false, nil
}

// RecentAuthFailures truy xuất các thất bại đã lưu trong cửa sổ thời gian.
// Chỉ so sánh khi có đủ username + nguồn IP để tránh kết luận nhầm.
func (s *Store) RecentAuthFailures(ctx context.Context, auth model.AuthenticationFacts, since, until time.Time) ([]model.Normalized, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if auth.Username == "" || auth.SourceIP == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Normalized, 0, 8)
	for _, r := range s.doc.AnalyzedEvents {
		n := r.Data.Norm
		a := n.Authentication
		if a == nil || a.Result != "failure" || a.EventCode != 4625 {
			continue
		}
		if n.EventTime.Before(since) || n.EventTime.After(until) {
			continue
		}
		if strings.EqualFold(a.Username, auth.Username) &&
			strings.EqualFold(a.Domain, auth.Domain) &&
			strings.EqualFold(a.SourceIP, auth.SourceIP) {
			out = append(out, n)
		}
	}
	return out, nil
}

// PersistAnalyzed lưu event chuẩn hóa, kết quả phân tích và trạng thái theo dõi liên quan.
func (s *Store) PersistAnalyzed(ctx context.Context, in model.PersistInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.doc.AnalyzedEvents {
		n := r.Data.Norm
		if n.AgentID == in.Norm.AgentID && n.Source == in.Norm.Source && n.SourceEventKey == in.Norm.SourceEventKey {
			return s.markProcessedLocked(in.Norm.EventID)
		}
	}
	s.doc.AnalyzedEvents = append(s.doc.AnalyzedEvents, AnalyzedRecord{Data: in})
	for i := range s.doc.RawEvents {
		if s.doc.RawEvents[i].Envelope.EventID == in.Norm.EventID {
			s.doc.RawEvents[i].Processed = true
			s.doc.RawEvents[i].ProcessedAt = time.Now().UTC()
		}
	}
	if in.TrackProcess && in.InstanceID != "" {
		s.upsertTrackedLocked(in, "process", in.InstanceID)
	}
	if in.TrackIP && in.IPKey != "" {
		s.upsertTrackedLocked(in, "ip", in.IPKey)
	}
	return s.saveLocked()
}
func (s *Store) markProcessedLocked(id string) error {
	for i := range s.doc.RawEvents {
		if s.doc.RawEvents[i].Envelope.EventID == id {
			s.doc.RawEvents[i].Processed = true
			s.doc.RawEvents[i].ProcessedAt = time.Now().UTC()
		}
	}
	return s.saveLocked()
}
func (s *Store) upsertTrackedLocked(in model.PersistInput, typ, key string) {
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(in.Norm.AgentID+"|"+typ+"|"+key)).String()
	now := in.Norm.EventTime.UTC()
	if now.IsZero() {
		now = in.Norm.ObservedAt.UTC()
	}
	status := "open"
	if in.Assessment.Severity == "high" || in.Assessment.Severity == "critical" {
		status = "watching"
	}
	found := false
	// Cập nhật case hiện có theo entity key; nếu chưa có thì tạo một case mới.
	for i := range s.doc.Tracked {
		e := &s.doc.Tracked[i]
		if e.EntityID == id {
			e.LastSeen = now
			if in.Assessment.Score >= e.Score {
				e.Score = in.Assessment.Score
				e.Severity = in.Assessment.Severity
			}
			if e.Status == "resolved" || e.Status == "false_positive" {
				e.Status = status
			}
			found = true
			break
		}
	}
	if !found {
		s.doc.Tracked = append(s.doc.Tracked, model.TrackedEntity{EntityID: id, AgentID: in.Norm.AgentID, EntityType: typ, EntityKey: key, Status: status, Severity: in.Assessment.Severity, Score: in.Assessment.Score, FirstSeen: now, LastSeen: now})
	}
	s.doc.Findings[id] = append(s.doc.Findings[id], in.Assessment.Findings...)
}
func (s *Store) ListCurrentTracking(ctx context.Context) ([]model.TrackedEntity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.TrackedEntity{}
	for _, e := range s.doc.Tracked {
		if e.Status == "open" || e.Status == "watching" {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Score > out[j].Score
	})
	return out, nil
}
func (s *Store) GetTracked(ctx context.Context, id string) (model.TrackedEntity, []model.Finding, error) {
	if err := ctx.Err(); err != nil {
		return model.TrackedEntity{}, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.doc.Tracked {
		if e.EntityID == id {
			return e, append([]model.Finding(nil), s.doc.Findings[id]...), nil
		}
	}
	return model.TrackedEntity{}, nil, os.ErrNotExist
}
func (s *Store) CloseCase(ctx context.Context, id, reason, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.doc.Tracked {
		e := &s.doc.Tracked[i]
		if e.EntityID == id {
			from := e.Status
			e.Status = "resolved"
			e.Note = reason
			s.doc.Transitions = append(s.doc.Transitions, Transition{ID: uuid.NewString(), EntityID: id, From: from, To: "resolved", Actor: actor, Reason: reason, At: time.Now().UTC()})
			return s.saveLocked()
		}
	}
	return os.ErrNotExist
}
func (s *Store) SaveCheckpoint(ctx context.Context, id, bookmark string, recordID int64, eventTime time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.doc.Checkpoints[id] = Checkpoint{Bookmark: bookmark, RecordID: recordID, EventTime: eventTime.UTC(), UpdatedAt: time.Now().UTC()}
	return s.saveLocked()
}
func (s *Store) LoadCheckpoint(ctx context.Context, id string) (string, int64, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.doc.Checkpoints[id]
	if !ok {
		return "", 0, nil
	}
	return c.Bookmark, c.RecordID, nil
}
func (s *Store) SaveHealth(ctx context.Context, h model.CollectorHealth) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.doc.Collectors[h.CollectorID] = h
	return s.saveLocked()
}
func (s *Store) Stats(ctx context.Context, path, rawDir string) (model.Stats, error) {
	if err := ctx.Err(); err != nil {
		return model.Stats{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := model.Stats{JSONPath: path, DataDir: rawDir, TelemetryCount: int64(len(s.doc.AnalyzedEvents)), Collectors: []model.CollectorHealth{}}
	for _, r := range s.doc.RawEvents {
		if !r.Processed {
			st.RawUnprocessed++
		}
	}
	for _, e := range s.doc.Tracked {
		if e.Status == "open" || e.Status == "watching" {
			st.CurrentTracked++
		}
	}
	for _, r := range s.doc.AnalyzedEvents {
		if r.Data.Norm.EventTime.After(st.LastEventTime) {
			st.LastEventTime = r.Data.Norm.EventTime
		}
	}
	for _, h := range s.doc.Collectors {
		st.Collectors = append(st.Collectors, h)
	}
	if info, err := os.Stat(path); err == nil {
		st.RawBytes = info.Size()
	}
	return st, nil
}

// RunRetention xóa dữ liệu đã quá hạn theo mốc riêng của từng loại record.
func (s *Store) RunRetention(ctx context.Context, rawCutoff, normCutoff, resolvedCutoff time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Retention lọc từng nhóm theo mốc riêng để giữ finding/case lâu hơn raw event.
	raw := s.doc.RawEvents[:0]
	for _, r := range s.doc.RawEvents {
		t, _ := time.Parse(time.RFC3339Nano, r.Envelope.ObservedAt)
		if !r.Processed || t.IsZero() || !t.Before(rawCutoff) {
			raw = append(raw, r)
		}
	}
	s.doc.RawEvents = raw
	norm := s.doc.AnalyzedEvents[:0]
	for _, r := range s.doc.AnalyzedEvents {
		if !r.Data.Norm.EventTime.Before(normCutoff) {
			norm = append(norm, r)
		}
	}
	s.doc.AnalyzedEvents = norm
	tracked := s.doc.Tracked[:0]
	for _, e := range s.doc.Tracked {
		if (e.Status != "resolved" && e.Status != "false_positive") || !e.LastSeen.Before(resolvedCutoff) {
			tracked = append(tracked, e)
		}
	}
	s.doc.Tracked = tracked
	return s.saveLocked()
}
func (s *Store) SessionFiredRules(ctx context.Context, instanceID string) (map[string]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	if instanceID == "" {
		return out, nil
	}
	for _, r := range s.doc.AnalyzedEvents {
		if r.Data.InstanceID == instanceID {
			for _, f := range r.Data.Assessment.Findings {
				out[f.RuleID] = true
			}
		}
	}
	return out, nil
}

// TraceProcess dựng lại timeline từ event đã lưu và lọc theo PID hoặc Process GUID.
func (s *Store) TraceProcess(ctx context.Context, selector string) (dto.ProcessTrace, error) {
	if err := ctx.Err(); err != nil {
		return dto.ProcessTrace{}, err
	}
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return dto.ProcessTrace{}, fmt.Errorf("process selector is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	trace := dto.ProcessTrace{Selector: selector, Nodes: []dto.ProcessNode{}, Events: []dto.TraceEvent{}, TCPFlows: []dto.TCPFlow{}}
	pid, pidErr := strconv.ParseInt(selector, 10, 64)
	included := map[string]bool{}
	parents := map[string]string{}
	nodes := map[string]dto.ProcessNode{}
	var seeds []string
	for _, record := range s.doc.AnalyzedEvents {
		in := record.Data
		if in.InstanceID != "" && in.ParentID != "" {
			parents[in.InstanceID] = in.ParentID
		}
		p := in.Norm.Process
		if p == nil {
			continue
		}
		match := strings.EqualFold(p.GUID, selector) || (pidErr == nil && p.PID == pid)
		if !match {
			continue
		}
		if in.InstanceID != "" {
			included[in.InstanceID] = true
			seeds = append(seeds, in.InstanceID)
		}
		nodes[in.InstanceID] = dto.ProcessNode{InstanceID: in.InstanceID, ParentID: in.ParentID, Process: *p}
	}
	if len(seeds) == 0 {
		return trace, os.ErrNotExist
	}
	// Lần ngược lên tiến trình cha, sau đó tìm tiếp toàn bộ tiến trình con.
	for _, id := range seeds {
		for parent := parents[id]; parent != "" && !included[parent]; parent = parents[parent] {
			included[parent] = true
		}
	}
	changed := true
	for changed {
		changed = false
		for id, parent := range parents {
			if included[parent] && !included[id] {
				included[id] = true
				changed = true
			}
		}
	}
	flowIndex := map[string]int{}
	for _, record := range s.doc.AnalyzedEvents {
		in := record.Data
		if !included[in.InstanceID] {
			continue
		}
		n := in.Norm
		traceEvent := dto.TraceEvent{EventID: n.EventID, EventType: n.EventType, Source: n.Source, SourceEventKey: n.SourceEventKey, EventTime: n.EventTime, Process: n.Process, Network: n.Network, Windows: n.Windows, Score: in.Assessment.Score, Severity: in.Assessment.Severity, Findings: in.Assessment.Findings}
		trace.Events = append(trace.Events, traceEvent)
		if node, ok := nodes[in.InstanceID]; ok && n.Process != nil {
			node.Process = *n.Process
			nodes[in.InstanceID] = node
		} else if n.Process != nil {
			nodes[in.InstanceID] = dto.ProcessNode{InstanceID: in.InstanceID, ParentID: in.ParentID, Process: *n.Process}
		}
		if nw := n.Network; nw != nil && strings.EqualFold(nw.Protocol, "tcp") {
			a := fmt.Sprintf("%s:%d", nw.LocalIP, nw.LocalPort)
			b := fmt.Sprintf("%s:%d", nw.RemoteIP, nw.RemotePort)
			if b < a {
				a, b = b, a
			}
			key := strings.ToLower(nw.Protocol) + "|" + a + "|" + b
			idx, ok := flowIndex[key]
			if !ok {
				idx = len(trace.TCPFlows)
				flowIndex[key] = idx
				trace.TCPFlows = append(trace.TCPFlows, dto.TCPFlow{Protocol: nw.Protocol, Direction: nw.Direction, LocalIP: nw.LocalIP, LocalPort: nw.LocalPort, RemoteIP: nw.RemoteIP, RemotePort: nw.RemotePort, Events: []dto.TraceEvent{}})
			}
			trace.TCPFlows[idx].Events = append(trace.TCPFlows[idx].Events, traceEvent)
		}
	}
	for _, node := range nodes {
		trace.Nodes = append(trace.Nodes, node)
	}
	sort.Slice(trace.Nodes, func(i, j int) bool { return trace.Nodes[i].Process.StartedAt.Before(trace.Nodes[j].Process.StartedAt) })
	sort.Slice(trace.Events, func(i, j int) bool { return trace.Events[i].EventTime.Before(trace.Events[j].EventTime) })
	for i := range trace.TCPFlows {
		sort.Slice(trace.TCPFlows[i].Events, func(a, b int) bool {
			return trace.TCPFlows[i].Events[a].EventTime.Before(trace.TCPFlows[i].Events[b].EventTime)
		})
	}
	return trace, nil
}
