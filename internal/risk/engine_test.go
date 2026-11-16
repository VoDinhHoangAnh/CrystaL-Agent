package risk

import (
	"testing"

	"AegisPlus/CrystaL/internal/model"
)

func TestAnalyzeSecretsRedactedAndTracked(t *testing.T) {
	r := Analyze("app.exe --api-key=SUPERSECRET", `C:\Users\Public\app.exe`, []int{10})
	if !HasSecretFinding(r) || !r.Track || r.Severity != "high" {
		t.Fatalf("unexpected result: %+v", r)
	}
	for _, f := range r.Findings {
		if f.Reason == "SUPERSECRET" || contains(f.Reason, "SUPERSECRET") {
			t.Fatal("secret leaked into finding")
		}
	}
}

func TestAnalyzeBenign(t *testing.T) {
	r := Analyze("notepad.exe", `C:\Windows\System32\notepad.exe`, nil)
	if r.Score != 0 || r.Track {
		t.Fatalf("unexpected risk for benign input: %+v", r)
	}
}

func TestSeverityThresholds(t *testing.T) {
	a := AnalyzeInput(model.RiskInput{
		CommandLine: "pwsh -EncodedCommand aaaa -WindowStyle Hidden",
		ImagePath:   `C:\Users\Public\a.exe`,
		Low:         1, Medium: 40, High: 70, Critical: 85, TrackMedium: true,
	})
	if a.Score != 55 || a.Severity != "medium" {
		t.Fatalf("expected medium 55, got score=%d sev=%s findings=%v", a.Score, a.Severity, a.Findings)
	}
}

func TestNoDuplicateRulePoints(t *testing.T) {
	a := AnalyzeInput(model.RiskInput{
		CommandLine:  "pwsh -EncodedCommand aaaa",
		AlreadyFired: map[string]bool{"powershell_encoded": true},
		Low:          1, Medium: 40, High: 70, Critical: 85,
	})
	if HasRule(a, "powershell_encoded") {
		t.Fatal("duplicate rule should not score again")
	}
}

func TestPublicIPNotAutoMalicious(t *testing.T) {
	a := AnalyzeInput(model.RiskInput{
		RemoteIP: "8.8.8.8", RemotePort: 443, EventIDs: []int{3},
		Low: 1, Medium: 40, High: 70, Critical: 85,
	})
	if a.Score > 10 {
		t.Fatalf("public IP should not be treated as malware: %+v", a)
	}
}

func TestMissingParentLowersConfidence(t *testing.T) {
	a := AnalyzeInput(model.RiskInput{MissingParent: true, CollectorDegraded: true, Low: 1, Medium: 40, High: 70, Critical: 85})
	if a.Confidence >= 1 {
		t.Fatal("confidence should drop")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && index(s, sub) >= 0
}
func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
