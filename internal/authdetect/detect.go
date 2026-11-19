// Package authdetect tương quan các sự kiện xác thực đã chuẩn hóa.
package authdetect

import (
	"AegisPlus/CrystaL/internal/model"
	"github.com/google/uuid"
)

const FailureThreshold = 5

// Analyze chỉ nâng cảnh báo khi có đủ username và source IP.
// Chỉ dùng các sự kiện 4625 để không đếm một lỗi xác thực nhiều lần qua DC/NTLM.
func Analyze(now model.Normalized, prior []model.Normalized) []model.Finding {
	a := now.Authentication
	if a == nil || a.Username == "" || a.SourceIP == "" {
		return nil
	}
	var rule, reason string
	points := 0
	switch {
	case a.EventCode == 4625 && a.Result == "failure" && len(prior) == FailureThreshold-1:
		rule = "auth_burst_same_account_source"
		reason = "At least five failed logons for one account and source IP within five minutes"
		points = 75
	case a.EventCode == 4624 && a.Result == "success" &&
		(a.LogonType == 3 || a.LogonType == 10) && len(prior) >= FailureThreshold:
		rule = "auth_success_after_failures"
		reason = "Successful network or remote-interactive logon after repeated failures"
		points = 85
	default:
		return nil
	}
	return []model.Finding{{
		FindingID: uuid.NewString(), RuleID: rule, RuleVersion: "1.0.0",
		Points: points, Severity: "high", Reason: reason, Confidence: 0.85,
		EventIDs: []string{now.EventID}, IPIDs: []string{a.SourceIP},
	}}
}
