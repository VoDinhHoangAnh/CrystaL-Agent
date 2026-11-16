package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"AegisPlus/CrystaL/internal/model"
)

const (
	AgentVersion    = model.AgentVersion
	AnalyzerVersion = model.AnalyzerVersion
	RulesetVersion  = model.RulesetVersion
	SchemaVersion   = model.SchemaVersion
)

// Load ghép cấu hình mặc định với .env và danh sách nguồn trong events.yaml.
func Load() model.Config {
	loadDotEnv()
	eventsFile := FindEventsFile()
	eventGroups, eventErr := LoadEventGroups(eventsFile)
	data := os.Getenv("PBRA_DATA_DIR")
	if data == "" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			data = filepath.Join(pd, "PBRA")
		} else {
			data = filepath.Join(".", "pb-data")
		}
	}
	return model.Config{
		DataDir:             data,
		JSONPath:            filepath.Join(data, "pbra.json"),
		AgentIDPath:         filepath.Join(data, "agent-id"),
		EventsFile:          eventsFile,
		EventConfigError:    errorText(eventErr),
		EventGroups:         eventGroups,
		QueueSize:           envInt("PBRA_QUEUE_SIZE", 1024, 1, 1_000_000),
		SnapshotEvery:       time.Duration(envInt("PBRA_SNAPSHOT_SECONDS", 30, 1, 86_400)) * time.Second,
		CollectCommandLine:  envBool("PBRA_COLLECT_CMDLINE", true),
		RedactCommandLine:   envBool("PBRA_REDACT_CMDLINE", true),
		RawRetention:        envDurationDays("PBRA_RAW_RETENTION_DAYS", 14),
		NormalizedRetention: envDurationDays("PBRA_NORM_RETENTION_DAYS", 30),
		ResolvedRetention:   envDurationDays("PBRA_RESOLVED_RETENTION_DAYS", 90),
		TrackMedium:         envBool("PBRA_TRACK_MEDIUM", true),
		Thresholds:          envThresholds(),
		SuspiciousPorts:     envPorts(),
		Channels:            ChannelsFromEventGroups(eventGroups),
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func envInt(key string, def, min, max int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return def
	}
	return n
}

func envThresholds() model.Thresholds {
	defaults := model.DefaultThresholds()
	t := model.Thresholds{
		Low:      envInt("PBRA_RISK_LOW", defaults.Low, 0, 100),
		Medium:   envInt("PBRA_RISK_MEDIUM", defaults.Medium, 0, 100),
		High:     envInt("PBRA_RISK_HIGH", defaults.High, 0, 100),
		Critical: envInt("PBRA_RISK_CRITICAL", defaults.Critical, 0, 100),
	}
	// Ngưỡng sai thứ tự sẽ dùng lại bộ mặc định để tránh phân loại severity bất thường.
	if t.Low > t.Medium || t.Medium > t.High || t.High > t.Critical {
		return defaults
	}
	return t
}

func envPorts() map[int]struct{} {
	value := strings.TrimSpace(os.Getenv("PBRA_SUSPICIOUS_PORTS"))
	if value == "" {
		return model.DefaultSuspiciousPorts()
	}
	ports := make(map[int]struct{})
	for _, part := range strings.Split(value, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && port > 0 && port <= 65535 {
			ports[port] = struct{}{}
		}
	}
	if len(ports) == 0 {
		return model.DefaultSuspiciousPorts()
	}
	return ports
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDurationDays(key string, days int) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return time.Duration(days) * 24 * time.Hour
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return time.Duration(days) * 24 * time.Hour
	}
	return time.Duration(n) * 24 * time.Hour
}
