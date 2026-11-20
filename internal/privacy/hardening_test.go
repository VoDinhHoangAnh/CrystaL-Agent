package privacy

import (
	"strings"
	"testing"
	"AegisPlus/CrystaL/internal/model"
)

func TestRawWindowsXMLSanitized(t *testing.T) {
	xml := `<Event><System><EventID>1</EventID></System><EventData><Data Name="CommandLine">pwsh --password SENTINEL123 -enc AAA</Data><Data Name="ParentCommandLine">cmd token="SENTINEL456"</Data></EventData></Event>`
	rec := model.CollectorRecord{Kind:"winevent",XML:xml}
	got,err:=SanitizeCollectorRecord(rec,true,true)
	if err!=nil{t.Fatal(err)}
	if strings.Contains(got.XML,"SENTINEL123")||strings.Contains(got.XML,"SENTINEL456"){t.Fatalf("raw XML secret leaked: %s",got.XML)}
	if !strings.Contains(got.XML,"-enc AAA"){t.Fatal("lost benign command flags")}
}
func TestArgumentRedaction(t *testing.T) {
	for _, s:= range []string{`app --password SENTINEL123`,`app Authorization: Bearer SENTINEL123`,`app password="first SENTINEL123"`,`app token=SENTINEL123`} {
		v:=RedactCommandLine(s)
		if !v.Indicator || strings.Contains(v.Redacted,"SENTINEL123") {t.Fatalf("secret leaked: %q",v.Redacted)}
	}
}
func TestOpaqueRawPayloadRejected(t *testing.T) {
	_,err:=SanitizeCollectorRecord(model.CollectorRecord{Payload:[]byte(`{"password":"SENTINEL"}`)},true,true)
	if err==nil {t.Fatal("opaque raw payload silently accepted")}
}
