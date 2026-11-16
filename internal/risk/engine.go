package risk

import (
	"path/filepath"
	"strings"

	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/privacy"

	"github.com/google/uuid"
)

const RuleVersion = "1.0.0"

func Analyze(commandLine, imagePath string, eventIDs []int) model.Assessment {
	return AnalyzeInput(model.RiskInput{
		CommandLine: commandLine, ImagePath: imagePath, EventIDs: eventIDs,
		Low: 1, Medium: 40, High: 70, Critical: 85, TrackMedium: true,
		SuspiciousPorts: map[int]struct{}{4444: {}, 1337: {}, 5555: {}, 6666: {}, 31337: {}},
		SecretIndicator: privacy.ContainsSecret(commandLine),
	})
}

func AnalyzeInput(in model.RiskInput) model.Assessment {
	a := model.Assessment{
		AssessmentID:    uuid.NewString(),
		AnalyzerVersion: model.AnalyzerVersion,
		RulesetVersion:  model.RulesetVersion,
		Confidence:      1.0,
	}
	fired := in.AlreadyFired
	if fired == nil {
		fired = map[string]bool{}
	}
	add := func(id string, points int, severity, reason string) {
		if fired[id] {
			return
		}
		fired[id] = true
		a.Findings = append(a.Findings, model.Finding{
			FindingID: uuid.NewString(), RuleID: id, RuleVersion: RuleVersion,
			Points: points, Severity: severity, Reason: reason, Confidence: a.Confidence,
			EventIDs: nonEmpty(in.EventID), ProcessIDs: nonEmpty(in.ProcessInstanceID), IPIDs: nonEmpty(in.RemoteIP),
		})
	}

	cmd := strings.ToLower(in.CommandLine)
	path := strings.ToLower(in.ImagePath)
	parent := strings.ToLower(in.ParentImage)

	if in.SecretIndicator || privacy.ContainsSecret(in.CommandLine) {
		add("secret_in_commandline", 35, "high", "Command line appears to contain a credential-like parameter; value withheld")
	}
	if strings.Contains(cmd, "-enc ") || strings.Contains(cmd, "-encodedcommand") || strings.Contains(cmd, " -enc") {
		add("powershell_encoded", 30, "high", "Encoded PowerShell command observed")
	}
	if strings.Contains(cmd, "-windowstyle hidden") || strings.Contains(cmd, "-w hidden") {
		add("hidden_window", 10, "low", "Process requests a hidden window")
	}
	if unusualPath(path) {
		add("unusual_execution_path", 15, "medium", "Executable is running from a commonly abused writable location")
	}
	if officeSpawnsScript(parent, path, cmd) {
		add("suspicious_parent_child", 25, "high", "Office or browser parent spawned a scripting interpreter")
	}
	if strings.EqualFold(in.SignatureStatus, "unsigned") || strings.EqualFold(in.SignatureStatus, "invalid") {
		add("unsigned_or_invalid_signature", 10, "low", "Unsigned or invalid signature is a weak signal, not a malware conclusion")
	}
	if in.RemotePort > 0 {
		if _, ok := in.SuspiciousPorts[in.RemotePort]; ok {
			add("suspicious_port", 15, "medium", "Connection uses a locally configured uncommon port")
		}
	}
	for _, id := range uniqueInts(in.EventIDs) {
		switch id {
		case 10:
			add("process_access", 25, "medium", "Sysmon process access event observed")
		case 22:
			add("dns_query", 5, "info", "Sysmon DNS query observed")
		case 3:
			add("network_connection", 5, "info", "Sysmon network connection observed")
		}
	}

	if in.MissingParent {
		a.DataQuality = append(a.DataQuality, "missing_parent")
		a.Confidence -= 0.15
	}
	if in.PIDReuseAmbiguous {
		a.DataQuality = append(a.DataQuality, "pid_reuse_ambiguity")
		a.Confidence -= 0.2
	}
	if in.CollectorDegraded {
		a.DataQuality = append(a.DataQuality, "collector_gap")
		a.Confidence -= 0.2
	}
	if in.IsSnapshot {
		a.DataQuality = append(a.DataQuality, "snapshot_reconciliation")
		a.Confidence -= 0.1
	}
	if a.Confidence < 0.2 {
		a.Confidence = 0.2
	}

	score := 0
	for _, f := range a.Findings {
		score += f.Points
	}
	if score > 100 {
		score = 100
	}
	a.Score = score
	low, med, high, crit := in.Low, in.Medium, in.High, in.Critical
	if low == 0 && med == 0 && high == 0 {
		low, med, high, crit = 1, 40, 70, 85
	}
	switch {
	case score >= crit:
		a.Severity = "critical"
	case score >= high:
		a.Severity = "high"
	case score >= med:
		a.Severity = "medium"
	case score >= low:
		a.Severity = "low"
	default:
		a.Severity = "info"
	}
	a.Track = a.Severity == "high" || a.Severity == "critical" || (in.TrackMedium && a.Severity == "medium")
	return a
}

func HasSecretFinding(a model.Assessment) bool {
	return HasRule(a, "secret_in_commandline")
}

func HasRule(a model.Assessment, id string) bool {
	for _, f := range a.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func unusualPath(path string) bool {
	p := strings.ReplaceAll(path, "/", "\\")
	for _, c := range []string{`\users\public\`, `\appdata\local\temp\`, `\windows\temp\`, `\downloads\`} {
		if strings.Contains(p, c) {
			return true
		}
	}
	return false
}

func officeSpawnsScript(parent, childPath, cmd string) bool {
	parents := []string{"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "iexplore.exe", "msedge.exe", "chrome.exe", "firefox.exe"}
	children := []string{"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
	pn := strings.ToLower(filepath.Base(strings.ReplaceAll(parent, "/", "\\")))
	cn := strings.ToLower(filepath.Base(strings.ReplaceAll(childPath, "/", "\\")))
	okP, okC := false, false
	for _, x := range parents {
		if pn == x {
			okP = true
		}
	}
	for _, x := range children {
		if cn == x || strings.Contains(cmd, x) {
			okC = true
		}
	}
	return okP && okC
}

func uniqueInts(in []int) []int {
	seen := map[int]struct{}{}
	var out []int
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
