package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/store/jsonfile"
)

func TestNetworkSnapshotPayloadSurvivesIngest(t *testing.T) {
	p, st := newPipe(t)
	n := model.NetworkFacts{Protocol:"tcp", PID:4321, LocalIP:"192.0.2.10", LocalPort:51000, RemoteIP:"198.51.100.22", RemotePort:443, State:"ESTABLISHED"}
	if err:=p.Ingest(context.Background(),model.CollectorRecord{Source:"snapshot.network",SourceEventKey:"flow1",EventTime:time.Now().UTC(),Kind:"network",Snapshot:true,Network:&n});err!=nil {
		t.Fatal(err)
	}
	data,err:=os.ReadFile(st.Path())
	if err!=nil {t.Fatal(err)}
	var doc jsonfile.Document
	if err:=json.Unmarshal(data,&doc);err!=nil {t.Fatal(err)}
	if len(doc.AnalyzedEvents)!=1 || doc.AnalyzedEvents[0].Data.Norm.Network==nil {
		t.Fatal("snapshot network facts lost")
	}
	got:=doc.AnalyzedEvents[0].Data.Norm.Network
	if got.RemoteIP!="198.51.100.22" || got.RemotePort!=443 || got.PID!=4321 {
		t.Fatalf("snapshot facts corrupted: %+v",got)
	}
}

func TestAuthBurstIntegration(t *testing.T) {
	p, st := newPipe(t)
	now:=time.Date(2026,11,19,10,0,0,0,time.UTC)
	for i:=0;i<5;i++ {
		xml:=fmt.Sprintf(`<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Channel>Security</Channel><TimeCreated SystemTime="2026-11-19T10:00:00.000Z"/></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">LAB</Data><Data Name="IpAddress">192.0.2.7</Data><Data Name="LogonType">10</Data></EventData></Event>`)
		if err:=p.Ingest(context.Background(),model.CollectorRecord{Source:"Security",SourceEventKey:fmt.Sprintf("Security|%d",i+1),EventTime:now.Add(time.Duration(i)*time.Second),Kind:"winevent",XML:xml});err!=nil {t.Fatal(err)}
	}
	data,err:=os.ReadFile(st.Path());if err!=nil{t.Fatal(err)}
	var doc jsonfile.Document
	if err:=json.Unmarshal(data,&doc);err!=nil{t.Fatal(err)}
	if len(doc.AnalyzedEvents)!=5 {t.Fatalf("expected five events: %d",len(doc.AnalyzedEvents))}
	last:=doc.AnalyzedEvents[4].Data
	found:=false
	for _,f:=range last.Assessment.Findings{
		if f.RuleID=="auth_burst_same_account_source"{found=true}
	}
	if !found || last.Assessment.Severity!="high"{t.Fatalf("expected auth burst high: %+v",last.Assessment)}
}
