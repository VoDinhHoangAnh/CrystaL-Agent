package processgraph

import (
	"testing"
	"time"
)

func TestChildBeforeParent(t *testing.T) {
	g := New("agent")
	start := time.Now().UTC()
	child := g.Resolve(200, "{CHILD}", 100, "{PARENT}", start, false)
	if child.InstanceID == "" || child.ParentID == "" {
		t.Fatalf("expected stub parent: %+v", child)
	}
	if !child.MissingParent {
		t.Fatal("parent should be unresolved until parent event")
	}
	parent := g.Resolve(100, "{PARENT}", 1, "", start.Add(-time.Second), false)
	if parent.InstanceID != child.ParentID {
		t.Fatalf("parent id mismatch child=%s parent=%s", child.ParentID, parent.InstanceID)
	}
}

func TestMissingParent(t *testing.T) {
	g := New("agent")
	r := g.Resolve(5, "", 4, "", time.Now().UTC(), false)
	if !r.MissingParent || r.ParentID == "" {
		t.Fatalf("expected stub missing parent: %+v", r)
	}
}

func TestPIDReuseAfterTerminate(t *testing.T) {
	g := New("agent")
	t1 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	a := g.Resolve(42, "{A}", 1, "", t1, false)
	g.TerminatePID(42, t1.Add(2*time.Second))
	b := g.Resolve(42, "{B}", 1, "", t1.Add(5*time.Second), false)
	if a.InstanceID == b.InstanceID {
		t.Fatal("reused PID must create a new process instance")
	}
}

func TestTerminateExisting(t *testing.T) {
	g := New("agent")
	t1 := time.Now().UTC()
	a := g.Resolve(7, "{X}", 1, "", t1, false)
	term := g.Resolve(7, "{X}", 1, "", t1.Add(time.Second), true)
	if term.InstanceID != a.InstanceID {
		t.Fatal("terminate should resolve same instance")
	}
}
