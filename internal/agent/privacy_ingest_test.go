package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"AegisPlus/CrystaL/internal/model"
	"AegisPlus/CrystaL/internal/processgraph"
	"AegisPlus/CrystaL/internal/store/jsonfile"
)

func TestSensitiveRawRetentionAndSignal(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"state.json")
	s,err:=jsonfile.Open(path,0);if err!=nil{t.Fatal(err)}
	defer s.Close()
	p:=&Pipeline{Store:s,Graph:processgraph.New("x"),AgentID:"x",Cfg:model.Config{CollectCommandLine:true,RedactCommandLine:true,Thresholds:model.DefaultThresholds()}}
	rec:=model.CollectorRecord{Source:"synthetic",SourceEventKey:"s1",Kind:"process",EventTime:time.Now().UTC(),
		Process:&model.ProcessFacts{PID:123,CommandLine:"app --password SENTINEL123",ParentCommand:"cmd token=SENTINEL456"}}
	if err:=p.Ingest(context.Background(),rec);err!=nil{t.Fatal(err)}
	b,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
	if strings.Contains(string(b),"SENTINEL123")||strings.Contains(string(b),"SENTINEL456"){t.Fatal("secret leaked in persisted JSON")}
	if !strings.Contains(string(b),"secret_in_commandline"){t.Fatal("risk signal lost during sanitization")}
}
