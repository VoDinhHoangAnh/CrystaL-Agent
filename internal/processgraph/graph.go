package processgraph

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"AegisPlus/CrystaL/internal/model"

	"github.com/google/uuid"
)

// Graph ghép event theo từng lần chạy process thay vì coi PID là định danh vĩnh viễn.
type Graph struct {
	mu      sync.Mutex
	byGUID  map[string]string
	byKey   map[string]string
	slots   []model.GraphSlot
	agentID string
}

func New(agentID string) *Graph {
	return &Graph{byGUID: map[string]string{}, byKey: map[string]string{}, agentID: agentID}
}

// Resolve tìm hoặc tạo instance, rồi ghép quan hệ với process cha nếu dữ liệu cho phép.
func (g *Graph) Resolve(pid int64, guid string, ppid int64, parentGUID string, started time.Time, terminated bool) model.ResolveResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := model.ResolveResult{}
	guid = normalizeGUID(guid)
	parentGUID = normalizeGUID(parentGUID)

	if guid != "" {
		if id, ok := g.byGUID[guid]; ok {
			r.InstanceID = id
			g.refreshSlot(id, pid, guid, started, terminated)
			r.ParentID, r.ParentResolved, r.MissingParent = g.parent(ppid, parentGUID, started)
			return r
		}
		// Conflicting nonempty GUIDs must never merge through the PID fallback.
		// A deterministic per-agent GUID identity remains stable after restart.
		r.NewInstance = true
		r.InstanceID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(g.agentID+"|process-guid|"+guid)).String()
	} else {
		if pid != 0 && !started.IsZero() {
			if id, amb := g.matchPID(pid, started); id != "" {
				r.InstanceID = id
				r.PIDReuseAmbiguous = amb
				g.refreshSlot(id, pid, guid, started, terminated)
				r.ParentID, r.ParentResolved, r.MissingParent = g.parent(ppid, parentGUID, started)
				return r
			}
			// Reconcile a unique unresolved GUID-less parent stub. PID-only
			// attribution still has weak evidence, so mark ambiguity.
			if id, ok := g.reconcilePIDStub(pid, started); ok {
				r.InstanceID = id
				r.PIDReuseAmbiguous = true
				g.refreshSlot(id, pid, guid, started, terminated)
				r.ParentID, r.ParentResolved, r.MissingParent = g.parent(ppid, parentGUID, started)
				return r
			}
		}
		r.NewInstance = true
		r.InstanceID = uuid.NewString()
	}
	slot := model.GraphSlot{InstanceID: r.InstanceID, PID: pid, GUID: guid, Started: started}
	if terminated && !started.IsZero() {
		slot.Ended = started
	}
	g.slots = append(g.slots, slot)
	if guid != "" {
		g.byGUID[guid] = r.InstanceID
	}
	if pid != 0 {
		g.byKey[pidKey(g.agentID, pid, started)] = r.InstanceID
	}
	r.ParentID, r.ParentResolved, r.MissingParent = g.parent(ppid, parentGUID, started)
	return r
}

func (g *Graph) parent(ppid int64, parentGUID string, childStart time.Time) (id string, resolved bool, missing bool) {
	if parentGUID != "" {
		if existingID, ok := g.byGUID[parentGUID]; ok {
			for _, slot := range g.slots {
				if slot.InstanceID == existingID {
					return existingID, !slot.Stub, slot.Stub
				}
			}
			return existingID, false, true
		}
		id = uuid.NewSHA1(uuid.NameSpaceOID, []byte(g.agentID+"|process-guid|"+parentGUID)).String()
		g.byGUID[parentGUID] = id
		g.slots = append(g.slots, model.GraphSlot{InstanceID: id, GUID: parentGUID, PID: ppid, Stub: true, Started: childStart.Add(-time.Second)})
		return id, false, true
	}
	if ppid == 0 {
		return "", false, false
	}
	id, amb := g.matchPID(ppid, childStart.Add(-time.Millisecond))
	if id != "" && !amb {
		return id, true, false
	}
	if id != "" && amb {
		return "", false, true
	}
	// Tạo nút tạm khi event con đến trước event tạo cha; event sau có thể bổ sung dữ liệu.
	id = uuid.NewString()
	g.slots = append(g.slots, model.GraphSlot{InstanceID: id, PID: ppid, Stub: true, Started: childStart.Add(-time.Second)})
	g.byKey[pidKey(g.agentID, ppid, childStart.Add(-time.Second))] = id
	return id, false, true
}

func (g *Graph) matchPID(pid int64, at time.Time) (string, bool) {
	var live []model.GraphSlot
	for _, s := range g.slots {
		if s.PID != pid {
			continue
		}
		if !s.Ended.IsZero() && at.After(s.Ended) {
			continue
		}
		if !s.Started.IsZero() && at.Before(s.Started.Add(-2*time.Second)) {
			continue
		}
		live = append(live, s)
	}
	if len(live) == 1 {
		return live[0].InstanceID, false
	}
	// Nhiều instance cùng khớp PID khiến kết quả không chắc chắn, cần hạ confidence.
	if len(live) > 1 {
		return live[len(live)-1].InstanceID, true
	}
	return "", false
}

// refreshSlot upgrades an unresolved stub when PID/GUID facts arrive.
func (g *Graph) refreshSlot(id string, pid int64, guid string, at time.Time, terminated bool) {
	for i := range g.slots {
		slot := &g.slots[i]
		if slot.InstanceID != id { continue }
		if pid != 0 { slot.PID = pid }
		if guid != "" { slot.GUID = guid }
		if slot.Stub {
			if !at.IsZero() && (slot.Started.IsZero() || at.Before(slot.Started)) {
				slot.Started = at
			}
			slot.Stub = false
			slot.Resolved = true
		}
		if terminated { slot.Ended = at }
		return
	}
	slot := model.GraphSlot{InstanceID:id,PID:pid,GUID:guid,Started:at}
	if terminated { slot.Ended = at }
	g.slots = append(g.slots,slot)
}

// reconcilePIDStub is only safe for a unique unresolved GUID-less stub.
func (g *Graph) reconcilePIDStub(pid int64, at time.Time) (string, bool) {
	idx := -1
	for i := range g.slots {
		slot := g.slots[i]
		if !slot.Stub || slot.PID != pid || slot.GUID != "" || !slot.Ended.IsZero() ||
			at.IsZero() || slot.Started.IsZero() || at.After(slot.Started) {
			continue
		}
		if idx != -1 { return "", false }
		idx = i
	}
	if idx == -1 { return "", false }
	return g.slots[idx].InstanceID, true
}

func (g *Graph) markEnded(id string, terminated bool, at time.Time) {
	if !terminated {
		return
	}
	for i := range g.slots {
		if g.slots[i].InstanceID == id {
			g.slots[i].Ended = at
		}
	}
}

func (g *Graph) TerminatePID(pid int64, at time.Time) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, _ := g.matchPID(pid, at)
	if id != "" {
		g.markEnded(id, true, at)
	}
	return id
}

func pidKey(agent string, pid int64, started time.Time) string {
	return agent + "|" + strconv.FormatInt(pid, 10) + "|" + started.UTC().Format(time.RFC3339Nano)
}

func normalizeGUID(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	return strings.Trim(s, "{}")
}
