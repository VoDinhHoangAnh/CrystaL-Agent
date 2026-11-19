package normalize

import (
	"testing"

	"AegisPlus/CrystaL/internal/model"
)

func TestAuth4625Fields(t *testing.T) {
	xml := `<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Channel>Security</Channel><TimeCreated SystemTime="2026-11-19T10:00:00.000Z"/></System><EventData><Data Name="TargetUserName">testuser</Data><Data Name="TargetDomainName">LAB</Data><Data Name="IpAddress">192.0.2.10</Data><Data Name="LogonType">10</Data><Data Name="Status">0xC000006D</Data></EventData></Event>`
	n := Envelope("agent",model.SourceRecord{EventID:"event-1",Kind:"winevent",XML:xml},model.Config{})
	a := n.Authentication
	if a == nil || n.EventType != "authentication" || a.Result != "failure" || a.SourceIP != "192.0.2.10" || a.Username != "testuser" || a.LogonType != 10 { t.Fatalf("bad auth normalization: %+v", a) }
}
