package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"AegisPlus/CrystaL/internal/agent"
	"AegisPlus/CrystaL/internal/config"
	"AegisPlus/CrystaL/internal/controller/bruteforce"
	"AegisPlus/CrystaL/internal/controller/networklogin"
	processcontroller "AegisPlus/CrystaL/internal/controller/process"
	"AegisPlus/CrystaL/internal/dto"
	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/processgraph"
	"AegisPlus/CrystaL/internal/service"
	"AegisPlus/CrystaL/internal/store/jsonfile"
	"AegisPlus/CrystaL/internal/tracking"
)

func main() {
	cfg := config.Load()
	if service.IsService() {
		// Khi chạy dưới SCM, ghi stdout và stderr vào cùng file để tiện kiểm tra lỗi.
		_ = os.MkdirAll(cfg.DataDir, 0o700)
		f, err := os.OpenFile(filepath.Join(cfg.DataDir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			os.Stdout = f
			os.Stderr = f
			defer f.Close()
		}
		if err := service.RunService(func(ctx context.Context) error {
			return agent.Run(ctx, cfg)
		}); err != nil {
			fmt.Fprintln(os.Stderr, "service error:", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	switch cmd {
	case "run":
		err = agent.Run(ctx, cfg)
	case "status":
		err = agent.Status(ctx, cfg)
	case "validate-sources":
		err = validateSources(ctx, cfg)
	case "tracking":
		err = trackingCmd(ctx, cfg, os.Args[2:])
	case "process":
		err = processCmd(ctx, cfg, os.Args[2:])
	case "replay":
		err = replayCmd(ctx, cfg, os.Args[2:])
	case "data":
		err = dataCmd(ctx, cfg, os.Args[2:])
	case "retention":
		err = retentionCmd(ctx, cfg, os.Args[2:])
	case "install":
		err = service.Install()
		if err == nil {
			fmt.Printf("Service %s đã được cài và khởi động. Service sẽ tự chạy cùng Windows.\n", service.Name)
		}
	case "uninstall":
		err = service.Uninstall()
	case "start":
		err = service.Start()
	case "stop":
		err = service.Stop()
	case "help", "-h", "--help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %s", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func validateSources(ctx context.Context, cfg model.Config) error {
	if cfg.EventConfigError != "" {
		return fmt.Errorf("events.yaml không hợp lệ (%s): %s", cfg.EventsFile, cfg.EventConfigError)
	}
	fmt.Printf("Kiểm tra nguồn Windows theo %s\n", cfg.EventsFile)
	checks := []struct {
		name  string
		check func(context.Context, model.Config) ([]dto.EventSourceStatus, error)
	}{
		{"BRUTE FORCE", bruteforce.NewController().ValidateSources},
		{"NETWORK LOGIN", networklogin.NewController().ValidateSources},
		{"PROCESS / FOLLOW", processcontroller.ValidateSources},
	}
	for _, group := range checks {
		results, err := group.check(ctx, cfg)
		if err != nil {
			return err
		}
		fmt.Printf("\n%s\n", group.name)
		for _, result := range results {
			printSourceResult(result)
		}
	}
	return nil
}

func printSourceResult(result dto.EventSourceStatus) {
	status := "CHƯA XÁC ĐỊNH"
	switch {
	case result.AccessDenied:
		status = "THIẾU QUYỀN KIỂM TRA"
	case result.ChannelMissing:
		status = "THIẾU CHANNEL"
	case result.ChannelPresent && result.SampleFound:
		status = "CHANNEL OK, CÓ EVENT MẪU"
	case result.ChannelPresent:
		status = "CHANNEL OK, CHƯA THẤY EVENT MẪU"
	}
	fmt.Printf("[%s] %s (%s): %s\n", status, result.Group, result.Channel, result.Detail)
}

func trackingCmd(ctx context.Context, cfg model.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("tracking subcommand required: list|show|close")
	}
	st, err := jsonfile.Open(cfg.JSONPath, 0)
	if err != nil {
		return err
	}
	defer st.Close()
	switch args[0] {
	case "list":
		items, err := st.ListCurrentTracking(ctx)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			fmt.Println("no open/watching entities")
			return nil
		}
		for _, e := range items {
			fmt.Printf("%s type=%s key=%s status=%s severity=%s score=%d last_seen=%s\n",
				e.EntityID, e.EntityType, e.EntityKey, e.Status, e.Severity, e.Score, e.LastSeen.UTC().Format("2006-01-02T15:04:05Z"))
		}
		return nil
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: tracking show <id>")
		}
		e, findings, err := st.GetTracked(ctx, args[1])
		if err != nil {
			return err
		}
		fmt.Printf("id=%s type=%s key=%s status=%s severity=%s score=%d\n", e.EntityID, e.EntityType, e.EntityKey, e.Status, e.Severity, e.Score)
		for _, f := range findings {
			fmt.Printf("  finding rule=%s sev=%s points=%d evidence=%s reason=%s\n", f.RuleID, f.Severity, f.Points, strings.Join(f.EventIDs, ","), f.Reason)
		}
		return nil
	case "close":
		fs := flag.NewFlagSet("close", flag.ContinueOnError)
		reason := fs.String("reason", "", "close reason")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("usage: tracking close <id> --reason ...")
		}
		return tracking.Close(ctx, st, fs.Arg(0), *reason, "operator")
	default:
		return fmt.Errorf("unknown tracking command %s", args[0])
	}
}

func processCmd(ctx context.Context, cfg model.Config, args []string) error {
	if len(args) != 2 || args[0] != "trace" {
		return fmt.Errorf("cách dùng: process trace <PID-hoặc-Process-GUID>")
	}
	repo, err := jsonfile.Open(cfg.JSONPath, 0)
	if err != nil {
		return err
	}
	defer repo.Close()
	trace, err := processcontroller.NewController(repo).Trace(ctx, args[1])
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(trace)
}

func replayCmd(ctx context.Context, cfg model.Config, args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	from := fs.String("from", "", "raw jsonl path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" {
		return fmt.Errorf("usage: replay --from <raw-file>")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := jsonfile.Open(cfg.JSONPath, 0)
	if err != nil {
		return err
	}
	defer st.Close()
	id := "00000000-0000-0000-0000-000000000001"
	if b, err := os.ReadFile(cfg.AgentIDPath); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			id = s
		}
	}
	host, _ := os.Hostname()
	_ = st.EnsureAgent(ctx, id, host, "", "", "", model.AgentVersion)
	p := &agent.Pipeline{Cfg: cfg, Store: st, Graph: processgraph.New(id), AgentID: id}
	n, err := p.ReplayFile(ctx, *from)
	if err != nil {
		return err
	}
	fmt.Printf("replayed %d raw records from %s (idempotent)\n", n, *from)
	return nil
}

func dataCmd(ctx context.Context, cfg model.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("data subcommand required: stats|show")
	}
	switch args[0] {
	case "stats":
		return agent.Status(ctx, cfg)
	case "show":
		b, err := os.ReadFile(cfg.JSONPath)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		return err
	default:
		return fmt.Errorf("unknown data command %s", args[0])
	}
}

func retentionCmd(ctx context.Context, cfg model.Config, args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("usage: retention run")
	}
	st, err := jsonfile.Open(cfg.JSONPath, 0)
	if err != nil {
		return err
	}
	defer st.Close()
	now := time.Now().UTC()
	if err := st.RunRetention(ctx, now.Add(-cfg.RawRetention), now.Add(-cfg.NormalizedRetention), now.Add(-cfg.ResolvedRetention)); err != nil {
		return err
	}
	fmt.Println("retention pass complete")
	return nil
}

func usage() {
	fmt.Println(`crystal-agent commands:
  run                         observe-only collector + local risk analyst
	  status                      collector health and local JSON state
  validate-sources            kiểm tra channel/event trong events.yaml trên Windows
  tracking list               current open/watching process and IP cases
  tracking show <id>          sanitized score, findings, evidence ids
  tracking close <id> --reason TEXT
  process trace <pid|guid>    process tree, events and grouped TCP flows
  replay --from <raw.jsonl>   re-run parser/rules without new collection
	  data stats | data show        xem thống kê hoặc toàn bộ pbra.json
  retention run
  install | uninstall | start | stop   quản lý Windows service chạy nền`)
}
