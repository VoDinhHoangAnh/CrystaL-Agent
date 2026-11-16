package normalize

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"AegisPlus/CrystaL/internal/model"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	p := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sysmon", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSysmonProcessCreate(t *testing.T) {
	n := Envelope("agent", model.SourceRecord{
		EventID: "e1", Source: "sysmon", SourceEventKey: "sysmon|101",
		EventTime: time.Now().UTC(), XML: fixture(t, "process-create.xml"),
	}, model.Config{CollectCommandLine: true, RedactCommandLine: true})
	if n.EventType != "process" || n.Process == nil || n.Process.PID != 100 {
		t.Fatalf("unexpected: %+v", n.Process)
	}
	if n.Windows == nil || n.Windows.EventCode != 1 {
		t.Fatal("missing windows metadata")
	}
}

func TestSysmonSecretRedacted(t *testing.T) {
	n := Envelope("agent", model.SourceRecord{
		EventID: "e2", Source: "sysmon", SourceEventKey: "sysmon|102",
		XML: fixture(t, "child-encoded.xml"),
	}, model.Config{CollectCommandLine: true, RedactCommandLine: true})
	if n.Process == nil || !n.SecretIndicator {
		t.Fatal("expected secret indicator")
	}
	if contains(n.Process.CommandLine, "SUPERSECRETVALUE") || contains(n.CommandLineRedacted, "SUPERSECRETVALUE") {
		t.Fatalf("secret leaked: %q", n.Process.CommandLine)
	}
}

func TestSysmonNetworkAndTerminate(t *testing.T) {
	netn := Envelope("agent", model.SourceRecord{EventID: "e3", Source: "sysmon", SourceEventKey: "sysmon|103", XML: fixture(t, "network.xml")}, model.Config{})
	if netn.Network == nil || netn.Network.RemotePort != 4444 {
		t.Fatalf("network: %+v", netn.Network)
	}
	term := Envelope("agent", model.SourceRecord{EventID: "e4", Source: "sysmon", SourceEventKey: "sysmon|104", XML: fixture(t, "terminate.xml")}, model.Config{})
	if term.Process == nil || term.Process.Action != "terminate" {
		t.Fatalf("terminate: %+v", term.Process)
	}
}

func TestCanonicalIP(t *testing.T) {
	if CanonicalIP("::ffff:127.0.0.1") != "127.0.0.1" && CanonicalIP("127.0.0.1") != "127.0.0.1" {
		t.Fatal(CanonicalIP("127.0.0.1"))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && index(s, sub) >= 0))
}
func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
