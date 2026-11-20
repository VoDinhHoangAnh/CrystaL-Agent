package normalize

import (
	"testing"
	"time"

	"AegisPlus/CrystaL/internal/model"
)

func TestSecurity5156InboundAndOutbound(t *testing.T) {
	for _,tc:=range []struct{name,direction,local,remote string}{
		{"inbound","%%14592","198.51.100.7","192.0.2.5"},
		{"outbound","%%14593","192.0.2.5","198.51.100.7"},
	}{
		t.Run(tc.name,func(t *testing.T){
			raw := `<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>5156</EventID><Channel>Security</Channel><TimeCreated SystemTime="2026-11-20T00:00:00Z"/></System><EventData><Data Name="ProcessID">4556</Data><Data Name="Protocol">6</Data><Data Name="Direction">`+tc.direction+`</Data><Data Name="SourceAddress">192.0.2.5</Data><Data Name="SourcePort">5555</Data><Data Name="DestAddress">198.51.100.7</Data><Data Name="DestPort">443</Data></EventData></Event>`
			n:=Envelope("agent",model.SourceRecord{XML:raw,EventTime:time.Now().UTC()},model.Config{})
			if n.Network == nil {t.Fatal("missing network facts")}
			nw:=n.Network
			if nw.PID!=4556 || nw.Direction!=tc.name || nw.LocalIP!=tc.local || nw.RemoteIP!=tc.remote {
				t.Fatalf("wrong WFP mapping: %+v",nw)
			}
		})
	}
}
