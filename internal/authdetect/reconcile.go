package authdetect

import (
	"sort"
	"strings"
	"time"

	"AegisPlus/CrystaL/internal/model"
	"github.com/google/uuid"
)

const Window = 5 * time.Minute

// Reconcile derives auth findings from event time, independently of arrival order.
// Only Security 4625 failures contribute to the burst; 4624 LogonType 3/10
// can produce a success-after-failures signal. Returns a replacement plan
// for the supplied account/domain/source-IP identity.
func Reconcile(history []model.Normalized) map[string][]model.Finding {
	results := make(map[string][]model.Finding)
	events := make([]model.Normalized, 0, len(history))
	for _, n := range history {
		a := n.Authentication
		if a == nil || a.Username == "" || a.SourceIP == "" {
			continue
		}
		if (a.EventCode == 4625 && a.Result == "failure") ||
			(a.EventCode == 4624 && a.Result == "success") {
			events = append(events, n)
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if !events[i].EventTime.Equal(events[j].EventTime) {
			return events[i].EventTime.Before(events[j].EventTime)
		}
		if events[i].SourceEventKey != events[j].SourceEventKey {
			return events[i].SourceEventKey < events[j].SourceEventKey
		}
		return events[i].EventID < events[j].EventID
	})
	failures := make([]model.Normalized, 0, FailureThreshold)
	burstActive := false
	for _, n := range events {
		// Time is ordered, so all the remaining failures are no later
		// than this event and at most five minutes old.
		cutoff := n.EventTime.Add(-Window)
		start := 0
		for start < len(failures) && failures[start].EventTime.Before(cutoff) {
			start++
		}
		if start > 0 {
			failures = append([]model.Normalized(nil), failures[start:]...)
		}
		if len(failures) < FailureThreshold {
			burstActive = false
		}
		a := n.Authentication
		switch {
		case a.EventCode == 4625:
			failures = append(failures, n)
			if len(failures) >= FailureThreshold && !burstActive {
				evidence := evidenceIDs(failures[len(failures)-FailureThreshold:])
				results[n.EventID] = append(results[n.EventID],
					makeFinding("auth_burst_same_account_source", n,
						75, "At least five failed logons for one account and source IP within five minutes", evidence))
				burstActive = true
			}
		case a.EventCode == 4624 && (a.LogonType == 3 || a.LogonType == 10):
			if len(failures) >= FailureThreshold {
				evidence := append(evidenceIDs(failures[len(failures)-FailureThreshold:]), n.EventID)
				results[n.EventID] = append(results[n.EventID],
					makeFinding("auth_success_after_failures", n,
						85, "Successful network or remote-interactive logon after repeated failures", evidence))
			}
		}
	}
	return results
}

func evidenceIDs(events []model.Normalized) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.EventID)
	}
	return ids
}

func makeFinding(rule string, current model.Normalized, points int, reason string, evidence []string) model.Finding {
	return model.Finding{
		FindingID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(strings.Join([]string{"auth", current.AgentID, rule, current.EventID}, "|"))).String(),
		RuleID: rule,
		RuleVersion: "1.1.0",
		Points: points,
		Severity: "high",
		Reason: reason,
		Confidence: 0.85,
		EventIDs: evidence,
		IPIDs: []string{current.Authentication.SourceIP},
	}
}
