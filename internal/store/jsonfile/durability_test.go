package jsonfile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"AegisPlus/CrystaL/internal/model"
)

func TestOnlyOneWriterAndReadOnlyStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	a, err := Open(path, 0)
	if err != nil { t.Fatal(err) }
	defer a.Close()
	if _, err := Open(path, 0); err == nil {
		t.Fatal("second writer accepted; risk of acknowledged data loss")
	}
	view, err := OpenReadOnly(path)
	if err != nil { t.Fatal(err) }
	defer view.Close()
	if err := a.AppendRaw(context.Background(), model.RawEnvelope{EventID:"e1",AgentID:"a",Source:"security",SourceEventKey:"1"});err!=nil { t.Fatal(err) }
	// Read-only snapshots are intentionally not live views.
	refreshed, err := OpenReadOnly(path)
	if err != nil { t.Fatal(err) }
	if len(refreshed.doc.RawEvents) != 1 { t.Fatalf("expected one durable record: %d",len(refreshed.doc.RawEvents)) }
	refreshed.Close()
	if err := a.Close(); err != nil { t.Fatal(err) }
	b, err := Open(path, 0)
	if err != nil { t.Fatalf("lock still held after close: %v", err) }
	defer b.Close()
	if err := b.AppendRaw(context.Background(),model.RawEnvelope{EventID:"e2",AgentID:"a",Source:"security",SourceEventKey:"2"});err!=nil{ t.Fatal(err) }
	if len(b.doc.RawEvents)!=2 {t.Fatal("durable rows lost after exclusive handoff")}
}

func TestSaveFailureNeverAcknowledgesUnpersistedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	s, err := Open(path, 0)
	if err != nil { t.Fatal(err) }
	defer s.Close()
	blocker := path+".tmp"
	if err := os.Mkdir(blocker, 0o700); err != nil { t.Fatal(err) }
	rec := model.RawEnvelope{EventID:"e1",AgentID:"a",Source:"synthetic",SourceEventKey:"1"}
	if err := s.AppendRaw(context.Background(),rec); err == nil {t.Fatal("expected I/O error")}
	if err := os.Remove(blocker); err != nil {t.Fatal(err)}
	if err := s.AppendRaw(context.Background(),rec); err != nil {t.Fatalf("retry must persist: %v",err)}
	b, err := os.ReadFile(path)
	if err != nil {t.Fatal(err)}
	if !strings.Contains(string(b), "\"e1\"") {t.Fatal("retry acknowledged without durable raw record")}
}

func TestCheckpointRollbackAfterDiskFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(),"agent.json")
	s,err:=Open(path,0);if err!=nil{t.Fatal(err)}
	defer s.Close()
	if err:=os.Mkdir(path+".tmp",0o700);err!=nil{t.Fatal(err)}
	if err:=s.SaveCheckpoint(context.Background(),"sysmon","bad",42,time.Now());err==nil{t.Fatal("expected failed save")}
	if err:=os.Remove(path+".tmp");err!=nil{t.Fatal(err)}
	if bm,_,err:=s.LoadCheckpoint(context.Background(),"sysmon");err!=nil || bm!=""{t.Fatalf("stale checkpoint leaked into RAM: %q %v",bm,err)}
	if err:=s.SaveCheckpoint(context.Background(),"sysmon","good",42,time.Now());err!=nil{t.Fatal(err)}
	if bm,_,err:=s.LoadCheckpoint(context.Background(),"sysmon");err!=nil || bm!="good"{t.Fatalf("committed checkpoint missing: %q %v",bm,err)}
}
