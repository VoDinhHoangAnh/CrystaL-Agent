package normalize

import (
	"testing"
	"AegisPlus/CrystaL/internal/model"
)

func TestRDP1149NamespacedUserData(t *testing.T) {
	raw:=`<Event><System><EventID>1149</EventID><Channel>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</Channel></System><UserData><EventXML xmlns="Event_NS"><Param1>audit-user</Param1><Param2>LAB</Param2><Param3>192.0.2.10</Param3></EventXML></UserData></Event>`
	n:=Envelope("agent",model.SourceRecord{XML:raw},model.Config{})
	if n.Authentication==nil {t.Fatal("missing RDP auth")}
	a:=n.Authentication
	if a.Username!="audit-user" || a.Domain!="LAB" || a.SourceIP!="192.0.2.10" || a.Result!="rdp_authentication" {
		t.Fatalf("incorrect RDP UserData normalization: %+v",a)
	}
}
