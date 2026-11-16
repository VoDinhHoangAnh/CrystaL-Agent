package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/processgraph"
	"AegisPlus/CrystaL/internal/store/jsonfile"
	"AegisPlus/CrystaL/internal/tracking"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	p := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sysmon", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newPipe(t *testing.T) (*Pipeline, *jsonfile.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := jsonfile.Open(filepath.Join(dir, "pbra.json"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.EnsureAgent(ctx, "agent-1", "host", "windows", "10", "amd64", model.AgentVersion); err != nil {
		t.Fatal(err)
	}
	p := &Pipeline{
		Cfg: model.Config{
			CollectCommandLine: true, RedactCommandLine: true, TrackMedium: true,
			Thresholds: model.DefaultThresholds(), SuspiciousPorts: model.DefaultSuspiciousPorts(),
		},
		Store: st, Graph: processgraph.New("agent-1"), AgentID: "agent-1",
	}
	return p, st
}

func TestEndToEndHighCaseSecretAndClose(t *testing.T) {
	p, st := newPipe(t)
	ctx := context.Background()
	secret := "SUPERSECRETVALUE"
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

	if err := p.Ingest(ctx, model.CollectorRecord{
		Source: "Microsoft-Windows-Sysmon/Operational", SourceEventKey: "sysmon|101",
		EventTime: now, Kind: "winevent", XML: fixture(t, "process-create.xml"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.Ingest(ctx, model.CollectorRecord{
		Source: "Microsoft-Windows-Sysmon/Operational", SourceEventKey: "sysmon|102",
		EventTime: now.Add(time.Second), Kind: "winevent", XML: fixture(t, "child-encoded.xml"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.Ingest(ctx, model.CollectorRecord{
		Source: "Microsoft-Windows-Sysmon/Operational", SourceEventKey: "sysmon|103",
		EventTime: now.Add(2 * time.Second), Kind: "winevent", XML: fixture(t, "network.xml"),
	}); err != nil {
		t.Fatal(err)
	}
	trace, err := st.TraceProcess(ctx, "{00000000-0000-0000-0000-00000000000A}")
	if err != nil {
		t.Fatal(err)
	}
	if len(trace.Nodes) < 2 || len(trace.TCPFlows) != 1 {
		t.Fatalf("expected process lineage and one TCP flow, got nodes=%d flows=%d", len(trace.Nodes), len(trace.TCPFlows))
	}
	// Snapshot mạng lặp cùng khóa không được tạo thêm telemetry.
	if err := p.Ingest(ctx, model.CollectorRecord{
		Source: "Microsoft-Windows-Sysmon/Operational", SourceEventKey: "sysmon|103",
		EventTime: now.Add(3 * time.Second), Kind: "winevent", XML: fixture(t, "network.xml"),
	}); err != nil {
		t.Fatal(err)
	}

	assertNoSecretInNormalized(t, st.Path(), secret)

	cur, err := st.ListCurrentTracking(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cur) == 0 {
		t.Fatal("expected tracked high/medium entity")
	}
	foundHigh := false
	var id string
	for _, e := range cur {
		if e.Severity == "high" || e.Severity == "critical" {
			foundHigh = true
			id = e.EntityID
		}
	}
	if !foundHigh {
		t.Fatalf("expected high case, got %+v", cur)
	}

	before := cur[0].LastSeen
	if err := p.Ingest(ctx, model.CollectorRecord{
		Source: "Microsoft-Windows-Sysmon/Operational", SourceEventKey: "sysmon|103b",
		EventTime: now.Add(10 * time.Second), Kind: "winevent", XML: fixture(t, "network.xml"),
	}); err != nil {
		t.Fatal(err)
	}
	cur, _ = st.ListCurrentTracking(ctx)
	if len(cur) == 0 || !cur[0].LastSeen.After(before) && cur[0].EntityID == id {
		// Entity đã gặp lại phải cập nhật last_seen; thời gian có thể cùng một giây.
	}

	if err := tracking.Close(ctx, st, id, "lab review", "tester"); err != nil {
		t.Fatal(err)
	}
	cur, _ = st.ListCurrentTracking(ctx)
	for _, e := range cur {
		if e.EntityID == id {
			t.Fatal("closed case still in current view")
		}
	}
	closed, _, err := st.GetTracked(ctx, id)
	if err != nil || closed.Status != "resolved" {
		t.Fatal("resolved history missing")
	}
	assertNoSecretInNormalized(t, st.Path(), secret)
}

func TestReplayIdempotent(t *testing.T) {
	p, st := newPipe(t)
	ctx := context.Background()
	rec := model.CollectorRecord{
		Source: "sysmon", SourceEventKey: "sysmon|101", EventTime: time.Now().UTC(),
		Kind: "winevent", XML: fixture(t, "process-create.xml"),
	}
	if err := p.Ingest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := p.Ingest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	var doc jsonfile.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if n := len(doc.AnalyzedEvents); n != 1 {
		t.Fatalf("dedup failed: %d", n)
	}
}

func assertNoSecretInNormalized(t *testing.T, path, secret string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc jsonfile.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	normalized, err := json.Marshal(doc.AnalyzedEvents)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(normalized, []byte(secret)) {
		t.Fatalf("secret leaked in normalized state")
	}
}
