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

func TestAuthReconciliationThroughIngest(t *testing.T) {
	for _,tc:=range []struct{
		name string
		order []int
	}{
		{"ordered",[]int{0,1,2,3,4,5}},
		{"reverse",[]int{4,3,2,1,0,5}},
		{"lastTwoSwapped",[]int{0,1,2,4,3,5}},
		{"successFirst",[]int{5,0,1,2,3,4}},
	}{
		t.Run(tc.name,func(t *testing.T){
			p,st:=newPipe(t)
			base:=time.Date(2026,11,20,0,0,0,0,time.UTC)
			for _,m:=range tc.order {
				code:=4625
				lt:=3
				if m==5 {code=4624;lt=10}
				xml:=fmt.Sprintf(`<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>%d</EventID><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">LAB</Data><Data Name="IpAddress">192.0.2.10</Data><Data Name="LogonType">%d</Data></EventData></Event>`,code,lt)
				err:=p.Ingest(context.Background(),model.CollectorRecord{Source:"Security",SourceEventKey:fmt.Sprint("event",m),EventTime:base.Add(time.Duration(m)*time.Minute),Kind:"winevent",XML:xml})
				if err!=nil{t.Fatal(err)}
			}
			b,err:=os.ReadFile(st.Path());if err!=nil{t.Fatal(err)}
			var doc jsonfile.Document
			if err:=json.Unmarshal(b,&doc);err!=nil{t.Fatal(err)}
			count:=map[string]int{}
			for _,record:=range doc.AnalyzedEvents {
				for _,f:=range record.Data.Assessment.Findings {
					if f.RuleID=="auth_burst_same_account_source"||f.RuleID=="auth_success_after_failures" {
						count[f.RuleID]++
						expected:=5
						if f.RuleID=="auth_success_after_failures"{expected=6}
						if len(f.EventIDs)!=expected {t.Errorf("%s evidence count=%d",f.RuleID,len(f.EventIDs))}
					}
				}
			}
			if count["auth_burst_same_account_source"]!=1 || count["auth_success_after_failures"]!=1 {
				t.Fatalf("unexpected findings (%s): %+v",tc.name,count)
			}
		})
	}
}
