package authdetect

import (
	"testing"

	"AegisPlus/CrystaL/internal/model"
)

func TestBurstThreshold(t *testing.T) {
	current := model.Normalized{EventID: "e5", Authentication: &model.AuthenticationFacts{EventCode: 4625, Result: "failure", Username: "tester", SourceIP: "192.0.2.10"}}
	if n := len(Analyze(current, make([]model.Normalized, 3))); n != 0 { t.Fatalf("premature finding: %d", n) }
	f := Analyze(current, make([]model.Normalized, 4))
	if len(f) != 1 || f[0].RuleID != "auth_burst_same_account_source" { t.Fatalf("missing fifth failure finding: %+v", f) }
	current.Authentication.SourceIP = ""
	if len(Analyze(current, make([]model.Normalized, 4))) != 0 { t.Fatal("should not correlate missing IP") }
}

func TestRDPNetworkSuccessAfterFailures(t *testing.T) {
	current := model.Normalized{EventID: "e6", Authentication: &model.AuthenticationFacts{EventCode: 4624, Result: "success", Username: "tester", SourceIP: "192.0.2.10", LogonType: 10}}
	f := Analyze(current, make([]model.Normalized, 5))
	if len(f) != 1 || f[0].RuleID != "auth_success_after_failures" { t.Fatalf("missing success finding: %+v", f) }
	current.Authentication.LogonType = 2
	if len(Analyze(current, make([]model.Normalized, 5))) != 0 { t.Fatal("local interactive is not remote login") }
}
