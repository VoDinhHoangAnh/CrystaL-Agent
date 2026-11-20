package normalize

import (
	"net"
	"path/filepath"
	"strings"

	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/privacy"
)

// Envelope chuyển các nguồn Windows khác nhau về cùng một cấu trúc event.
func Envelope(agentID string, rec model.SourceRecord, cfg model.Config) model.Normalized {
	n := model.Normalized{
		EventID:        rec.EventID,
		AgentID:        agentID,
		Source:         rec.Source,
		SourceEventKey: rec.SourceEventKey,
		EventTime:      rec.EventTime,
		ObservedAt:     rec.ObservedAt,
		SchemaVersion:  model.SchemaVersion,
		Snapshot:       rec.Snapshot,
		EventType:      rec.Kind,
	}
	if n.EventTime.IsZero() {
		n.EventTime = rec.ObservedAt
	}
	if rec.XML != "" {
		if ev, data, err := parseWinXML(rec.XML); err == nil {
			n.Windows = windowsFacts(ev, data)
			n.EventType = "winevent"
			applySysmon(&n, ev, data, cfg)
			applySecurity(&n, ev, data, cfg)
			applyAuthentication(&n, ev, data)
		}
	}
	if rec.Kind == "process" || rec.Process != nil {
		n.EventType = "process"
		n.Process = rec.Process
		if rec.Parent != nil {
			n.Parent = rec.Parent
		}
	}
	if rec.Kind == "network" || rec.Network != nil {
		if n.EventType == "" || n.EventType == "winevent" {
			n.EventType = "network"
		}
		n.Network = rec.Network
		if n.Network != nil {
			n.Network.LocalIP = CanonicalIP(n.Network.LocalIP)
			n.Network.RemoteIP = CanonicalIP(n.Network.RemoteIP)
		}
	}
	applyRedaction(&n, cfg)
	if n.Process != nil && n.Process.ImageName == "" {
		n.Process.ImageName = basename(n.Process.ImagePath)
	}
	return n
}

func applySysmon(n *model.Normalized, ev model.WinEvent, data map[string]string, cfg model.Config) {
	if !strings.Contains(strings.ToLower(ev.System.Provider.Name), "sysmon") &&
		!strings.Contains(strings.ToLower(ev.System.Channel), "sysmon") {
		return
	}
	// Sysmon cung cấp Process GUID ổn định hơn PID để ghép event trong cùng lần chạy.
	code := int(atoi64(ev.System.EventID))
	switch code {
	case 1:
		n.EventType = "process"
		n.Process = &model.ProcessFacts{
			PID: atoi64(data["ProcessId"]), PPID: atoi64(data["ParentProcessId"]),
			GUID: data["ProcessGuid"], ParentGUID: data["ParentProcessGuid"],
			ImagePath: data["Image"], ImageName: basename(data["Image"]),
			CommandLine: data["CommandLine"], User: data["User"], Integrity: data["IntegrityLevel"],
			StartedAt: parseTime(data["UtcTime"]), Action: "create",
			Hashes: data["Hashes"], SHA256: hashSHA256(data["Hashes"]),
			LogonID: data["LogonId"], SessionID: data["TerminalSessionId"],
			ParentImage: data["ParentImage"], ParentCommand: data["ParentCommandLine"],
		}
		n.Parent = &model.ProcessFacts{
			PID: n.Process.PPID, GUID: n.Process.ParentGUID, ImagePath: data["ParentImage"],
			ImageName: basename(data["ParentImage"]), CommandLine: data["ParentCommandLine"],
			User: data["ParentUser"],
		}
	case 5:
		n.EventType = "process"
		n.Process = &model.ProcessFacts{
			PID: atoi64(data["ProcessId"]), GUID: data["ProcessGuid"],
			ImagePath: data["Image"], ImageName: basename(data["Image"]),
			EndedAt: parseTime(data["UtcTime"]), Action: "terminate",
		}
	case 3:
		n.EventType = "network"
		n.Network = &model.NetworkFacts{
			Protocol: strings.ToLower(data["Protocol"]), Direction: strings.ToLower(data["Initiated"]),
			LocalIP: CanonicalIP(data["SourceIp"]), LocalPort: int(atoi64(data["SourcePort"])),
			RemoteIP: CanonicalIP(data["DestinationIp"]), RemotePort: int(atoi64(data["DestinationPort"])),
			PID: atoi64(data["ProcessId"]), GUID: data["ProcessGuid"],
			Domain: data["DestinationHostname"],
		}
		if n.Network.Direction == "true" {
			n.Network.Direction = "outbound"
		} else if n.Network.Direction == "false" {
			n.Network.Direction = "inbound"
		}
		n.Process = &model.ProcessFacts{
			PID: n.Network.PID, GUID: n.Network.GUID, ImagePath: data["Image"], ImageName: basename(data["Image"]),
			User: data["User"], Action: "network",
		}
	case 22:
		n.EventType = "network"
		n.Network = &model.NetworkFacts{
			Protocol: "dns", Domain: data["QueryName"], PID: atoi64(data["ProcessId"]), GUID: data["ProcessGuid"],
		}
		n.Process = &model.ProcessFacts{PID: n.Network.PID, GUID: n.Network.GUID, ImagePath: data["Image"], ImageName: basename(data["Image"])}
	case 10:
		n.EventType = "process"
		n.Process = &model.ProcessFacts{
			PID: atoi64(data["TargetProcessId"]), GUID: data["TargetProcessGuid"],
			ImagePath: data["TargetImage"], Action: "access",
		}
		n.Parent = &model.ProcessFacts{
			PID: atoi64(data["SourceProcessId"]), GUID: data["SourceProcessGuid"], ImagePath: data["SourceImage"],
		}
	}
	_ = cfg
}

func applySecurity(n *model.Normalized, ev model.WinEvent, data map[string]string, cfg model.Config) {
	if !strings.EqualFold(ev.System.Channel, "Security") && !strings.Contains(strings.ToLower(ev.System.Provider.Name), "security") {
		return
	}
	code := int(atoi64(ev.System.EventID))
	switch code {
	case 4688:
		n.EventType = "process"
		n.Process = &model.ProcessFacts{
			PID:         atoi64(first(data, "NewProcessId", "ProcessId")),
			PPID:        atoi64(first(data, "ProcessId", "ParentProcessId")),
			ImagePath:   first(data, "NewProcessName", "ProcessName"),
			CommandLine: first(data, "CommandLine"),
			User:        first(data, "SubjectUserName"),
			Action:      "create",
			StartedAt:   parseTime(ev.System.TimeCreated.SystemTime),
		}
		n.Parent = &model.ProcessFacts{PID: n.Process.PPID, ImagePath: first(data, "ParentProcessName")}
	case 4689:
		n.EventType = "process"
		n.Process = &model.ProcessFacts{
			PID:       atoi64(first(data, "ProcessId")),
			ImagePath: first(data, "ProcessName"),
			Action:    "terminate",
			EndedAt:   parseTime(ev.System.TimeCreated.SystemTime),
		}
	case 5156:
		n.EventType = "network"
		direction := dirName(first(data, "Direction"))
		srcIP, srcPort := CanonicalIP(first(data, "SourceAddress")), int(atoi64(first(data, "SourcePort")))
		dstIP, dstPort := CanonicalIP(first(data, "DestAddress")), int(atoi64(first(data, "DestPort")))
		// 5156 source/destination follow packet direction. NetworkFacts
		// local/remote instead describe the observed Windows endpoint.
		if direction == "inbound" {
			srcIP, dstIP = dstIP, srcIP
			srcPort, dstPort = dstPort, srcPort
		}
		n.Network = &model.NetworkFacts{
			Protocol: protoName(first(data, "Protocol")),
			Direction: direction,
			LocalIP: srcIP, LocalPort: srcPort,
			RemoteIP: dstIP, RemotePort: dstPort,
			PID: atoi64(first(data, "ProcessID", "ProcessId")),
		}
	}
	_ = cfg
}

func windowsFacts(ev model.WinEvent, data map[string]string) *model.WindowsFacts {
	safeData := make(map[string]string, len(data))
	for key, value := range data {
		safeData[key] = privacy.RedactCommandLine(value).Redacted
	}
	return &model.WindowsFacts{
		Provider:  ev.System.Provider.Name,
		Channel:   ev.System.Channel,
		EventCode: int(atoi64(ev.System.EventID)),
		Version:   int(atoi64(ev.System.Version)),
		Computer:  ev.System.Computer,
		RecordID:  atoi64(ev.System.EventRecordID),
		Severity:  ev.System.Level,
		EventData: safeData,
	}
}

func applyRedaction(n *model.Normalized, cfg model.Config) {
	if n.Process == nil {
		return
	}
	if !cfg.CollectCommandLine {
		n.Process.CommandLine = ""
		n.CommandLineRedacted = ""
		return
	}
	r := privacy.RedactCommandLine(n.Process.CommandLine)
	if cfg.RedactCommandLine {
		n.CommandLineRedacted = r.Redacted
		n.Process.CommandLine = r.Redacted
	} else {
		n.CommandLineRedacted = r.Redacted
	}
	n.SecretIndicator = r.Indicator
	n.SecretPatternType = r.PatternType
	n.SecretField = r.Field
	if cfg.RedactCommandLine {
		parentCmd := privacy.RedactCommandLine(n.Process.ParentCommand)
		n.Process.ParentCommand = parentCmd.Redacted
		if parentCmd.Indicator {
			n.SecretIndicator = true
		}
		if n.Parent != nil {
			pr := privacy.RedactCommandLine(n.Parent.CommandLine)
			n.Parent.CommandLine = pr.Redacted
			if pr.Indicator {
				n.SecretIndicator = true
			}
		}
	}
}

// CanonicalIP chuẩn hóa địa chỉ hợp lệ để tránh một IP có nhiều cách biểu diễn.
func CanonicalIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func first(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func protoName(s string) string {
	switch s {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	default:
		if s == "" {
			return "tcp"
		}
		return strings.ToLower(s)
	}
}

func dirName(s string) string {
	switch s {
	case "%%14592":
		return "inbound"
	case "%%14593":
		return "outbound"
	default:
		return strings.ToLower(s)
	}
}

func ImageName(path string) string {
	return filepath.Base(strings.ReplaceAll(path, "/", "\\"))
}
