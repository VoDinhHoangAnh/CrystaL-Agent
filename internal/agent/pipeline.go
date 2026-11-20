package agent

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/normalize"
	"AegisPlus/CrystaL/internal/privacy"
	"AegisPlus/CrystaL/internal/processgraph"
	"AegisPlus/CrystaL/internal/rawstore"
	"AegisPlus/CrystaL/internal/repository"
	"AegisPlus/CrystaL/internal/risk"
	"AegisPlus/CrystaL/internal/tracking"

	"github.com/google/uuid"
)

type Pipeline struct {
	Cfg     model.Config
	Store   repository.Repository
	Graph   *processgraph.Graph
	AgentID string
}

// Ingest ghi nhận sự kiện raw trước, rồi chuyển sang xử lý chuẩn hóa.
func (p *Pipeline) Ingest(ctx context.Context, rec model.CollectorRecord) error {
	now := time.Now().UTC()
	id := uuid.NewString()
	var err error
	rec.SecretDetected = rec.SecretDetected || privacy.ContainsSecret(rec.XML) ||
		(rec.Process != nil && (privacy.ContainsSecret(rec.Process.CommandLine) || privacy.ContainsSecret(rec.Process.ParentCommand))) ||
		(rec.Parent != nil && privacy.ContainsSecret(rec.Parent.CommandLine))
	rec, err = privacy.SanitizeCollectorRecord(rec, p.Cfg.CollectCommandLine, p.Cfg.RedactCommandLine)
	if err != nil { return fmt.Errorf("raw privacy guard: %w", err) }
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	env := model.RawEnvelope{
		EventID: id, AgentID: p.AgentID, Source: rec.Source, SourceEventKey: rec.SourceEventKey,
		EventTime: rec.EventTime.UTC().Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano),
		SchemaVersion: model.SchemaVersion, Kind: rec.Kind, Snapshot: rec.Snapshot, XML: rec.XML, Payload: payload,
	}
	// Giữ đầy đủ Process, Parent và Network facts cho cả snapshot và replay.
	// Bản JSON của CollectorRecord được chuẩn hóa về cùng một schema ở Handle().
	env.SpoolPath = p.Store.Path()
	if err := p.Store.AppendRaw(ctx, env); err != nil {
		return err
	}
	return p.Handle(ctx, env)
}

func (p *Pipeline) Handle(ctx context.Context, env model.RawEnvelope) error {
	exists, err := p.Store.EventExists(ctx, env.AgentID, env.Source, env.SourceEventKey)
	if err != nil {
		return err
	}
	if exists {
		// Event ID từ nguồn giúp tránh phân tích lại cùng một bản ghi sau restart.
		return p.Store.MarkRawProcessed(ctx, env.EventID)
	}
	evTime, _ := time.Parse(time.RFC3339Nano, env.EventTime)
	obs, _ := time.Parse(time.RFC3339Nano, env.ObservedAt)
	src := model.SourceRecord{
		EventID: env.EventID, Source: env.Source, SourceEventKey: env.SourceEventKey,
		EventTime: evTime, ObservedAt: obs, Kind: env.Kind, Snapshot: env.Snapshot, XML: env.XML, Payload: env.Payload,
	}
	if len(env.Payload) > 0 {
		var rec model.CollectorRecord
		if err := json.Unmarshal(env.Payload, &rec); err != nil {
			return fmt.Errorf("invalid raw collector payload: %w", err)
		}
		src.SecretDetected = rec.SecretDetected
		if env.XML == "" {
			src.Process, src.Parent, src.Network = rec.Process, rec.Parent, rec.Network
			if rec.XML != "" {
				src.XML = rec.XML
			}
			if rec.Kind != "" {
				src.Kind = rec.Kind
			}
		}
	}
	if src.XML != "" {
		var event model.WinEvent
		if err := xml.Unmarshal([]byte(src.XML), &event); err != nil {
			return fmt.Errorf("invalid Windows event XML (source=%s key=%s): %w", src.Source, src.SourceEventKey, err)
		}
		if event.XMLName.Local != "Event" || event.System.EventID == "" {
			return fmt.Errorf("missing Event root or EventID (source=%s key=%s)", src.Source, src.SourceEventKey)
		}
	}
	n := normalize.Envelope(p.AgentID, src, p.Cfg)
	n.SecretIndicator = n.SecretIndicator || src.SecretDetected

	// Ghép sự kiện với đúng lần chạy process trước khi gắn event và network vào timeline.
	var rr model.ResolveResult
	if n.Process != nil {
		terminated := strings.EqualFold(n.Process.Action, "terminate")
		start := n.Process.StartedAt
		if start.IsZero() {
			start = n.EventTime
		}
		if start.IsZero() {
			start = n.ObservedAt
		}
		rr = p.Graph.Resolve(n.Process.PID, n.Process.GUID, n.Process.PPID, n.Process.ParentGUID, start, terminated)
	} else if n.Network != nil && n.Network.PID != 0 {
		rr = p.Graph.Resolve(n.Network.PID, n.Network.GUID, 0, "", n.EventTime, false)
	}

	fired, _ := p.Store.SessionFiredRules(ctx, rr.InstanceID)
	var codes []int
	if n.Windows != nil {
		codes = append(codes, n.Windows.EventCode)
	}
	cmd, img, parentImg := "", "", ""
	if n.Process != nil {
		cmd, img = n.Process.CommandLine, n.Process.ImagePath
		parentImg = n.Process.ParentImage
	}
	if n.Parent != nil && parentImg == "" {
		parentImg = n.Parent.ImagePath
	}
	remoteIP, port := "", 0
	if n.Network != nil {
		remoteIP, port = n.Network.RemoteIP, n.Network.RemotePort
	}
	// Phân tích hiện tại chỉ nhận dữ liệu đã chuẩn hóa; rule cụ thể nằm riêng trong package risk.
	a := risk.AnalyzeInput(model.RiskInput{
		CommandLine: cmd, ImagePath: img, ParentImage: parentImg, EventIDs: codes,
		RemoteIP: remoteIP, RemotePort: port, EventID: n.EventID, ProcessInstanceID: rr.InstanceID,
		ParentResolved: rr.ParentResolved, MissingParent: rr.MissingParent, PIDReuseAmbiguous: rr.PIDReuseAmbiguous,
		CollectorDegraded: false, IsSnapshot: n.Snapshot, AlreadyFired: fired, SecretIndicator: n.SecretIndicator,
		Low: p.Cfg.Thresholds.Low, Medium: p.Cfg.Thresholds.Medium, High: p.Cfg.Thresholds.High, Critical: p.Cfg.Thresholds.Critical,
		TrackMedium: p.Cfg.TrackMedium, SuspiciousPorts: p.Cfg.SuspiciousPorts,
	})

	// Auth correlation is computed from persisted event-time history in the
	// repository transaction, not the arrival order of this single event.
	if n.Authentication != nil {
		remoteIP = n.Authentication.SourceIP
	}

	imageID := ""
	if n.Process != nil && n.Process.ImagePath != "" {
		imageID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(n.Process.ImagePath+"|"+n.Process.SHA256)).String()
	}
	sessionID := ""
	root := rr.InstanceID
	if rr.ParentID != "" {
		root = rr.ParentID
	}
	if root != "" {
		sessionID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(p.AgentID+"|session|"+root)).String()
	}
	ipKey := ""
	if remoteIP != "" && !isLoopback(remoteIP) {
		ipKey = normalize.CanonicalIP(remoteIP)
	}
	trackProc := tracking.ShouldTrack(a.Severity, p.Cfg.TrackMedium) && rr.InstanceID != ""
	trackIP := tracking.ShouldTrack(a.Severity, p.Cfg.TrackMedium) && ipKey != ""

	in := model.PersistInput{
		Norm: n, RawRef: env.SpoolPath, ImageID: imageID, InstanceID: rr.InstanceID, ParentID: rr.ParentID,
		SessionID: sessionID, Assessment: a, TrackProcess: trackProc, TrackIP: trackIP, IPKey: ipKey,
	}
	if err := p.Store.PersistAnalyzed(ctx, in); err != nil {
		return err
	}
	return assertNoSecretLeak(n, a, cmd)
}

func (p *Pipeline) ReplayFile(ctx context.Context, path string) (int, error) {
	envs, err := rawstore.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n := 0
	// Replay dùng cùng pipeline với thu thập trực tiếp để kết quả lưu có cùng schema.
	for _, env := range envs {
		if env.AgentID == "" {
			env.AgentID = p.AgentID
		}
		if env.EventID == "" {
			env.EventID = uuid.NewString()
		}
		env.SpoolPath = p.Store.Path()
		if err := p.Store.InsertRawIndex(ctx, env, path, 0, ""); err != nil {
			return n, err
		}
		if err := p.Handle(ctx, env); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (p *Pipeline) ReplayUnprocessed(ctx context.Context) error {
	for {
		rows, err := p.Store.UnprocessedRaw(ctx, 500)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, env := range rows {
			env.SpoolPath = p.Store.Path()
			if err := p.Handle(ctx, env); err != nil {
				return err
			}
		}
	}
}

func isLoopback(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}

func assertNoSecretLeak(n model.Normalized, a model.Assessment, originalRedacted string) error {
	for _, f := range a.Findings {
		if originalRedacted != "" && !privacy.AssertNoSecret(f.Reason, originalRedacted) {
			return os.ErrInvalid
		}
		if strings.Contains(strings.ToLower(f.Reason), "supersecret") {
			return os.ErrInvalid
		}
	}
	return nil
}
