package authdetect

import (
	"testing"
	"time"

	"AegisPlus/CrystaL/internal/model"
)

func testEvent(id string, minute int, code int, lt int) model.Normalized {
	result := "failure"
	if code == 4624 { result = "success" }
	return model.Normalized{
		EventID: id, AgentID: "a", SourceEventKey: id,
		EventTime: time.Date(2026,11,20,0,minute,0,0,time.UTC),
		Authentication: &model.AuthenticationFacts{
			EventCode:code, Result:result, Username:"test", Domain:"LAB",
			SourceIP:"192.0.2.2", LogonType:lt,
		},
	}
}

func TestReconcileIndependentOfArrivalOrder(t *testing.T) {
	ordered:=[]model.Normalized{
		testEvent("f0",0,4625,3),testEvent("f1",1,4625,3),
		testEvent("f2",2,4625,3),testEvent("f3",3,4625,3),
		testEvent("f4",4,4625,3),testEvent("ok",5,4624,10),
	}
	orders:=[][]int{{0,1,2,3,4,5},{4,3,2,1,0,5},{0,1,2,4,3,5},{5,0,1,2,3,4}}
	for _,order:=range orders {
		var history []model.Normalized
		for _,idx:=range order {history=append(history,ordered[idx])}
		out:=Reconcile(history)
		if len(out)!=2 || len(out["f4"])!=1 || len(out["ok"])!=1 {
			t.Fatalf("missing findings with order=%v: %+v",order,out)
		}
		if got:=len(out["f4"][0].EventIDs);got!=5 {t.Fatalf("burst evidence=%d, want 5",got)}
		if got:=len(out["ok"][0].EventIDs);got!=6 {t.Fatalf("success evidence=%d, want 6",got)}
	}
}

func TestReconcileBurstNotRepeatedForEightFailures(t *testing.T) {
	var history []model.Normalized
	for i:=0;i<8;i++ { history=append(history,testEvent(string(rune('a'+i)),i/2,4625,3))}
	out:=Reconcile(history)
	if len(out)!=1 {t.Fatalf("8 failures expected one burst, got %d findings",len(out))}
}

func TestReconcileNoFindingsForSparseFailures(t *testing.T) {
	var history []model.Normalized
	for i:=0;i<5;i++ {history=append(history,testEvent(string(rune('a'+i)),i*7,4625,3))}
	if len(Reconcile(history))!=0 {t.Fatal("sparse failures produced alert")}
}
