//go:build windows

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"AegisPlus/CrystaL/internal/model"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
	afINET              = 2
	afINET6             = 23
)

type networkSnapshot struct {
	every  time.Duration
	mu     sync.Mutex
	health model.CollectorHealth
}

func newNetworkSnapshot(every time.Duration) *networkSnapshot {
	if every <= 0 {
		every = 30 * time.Second
	}
	return &networkSnapshot{
		every:  every,
		health: model.CollectorHealth{CollectorID: "snapshot:network", Status: "available", Reason: "fallback_reconciliation", PrivilegeStatus: "ok"},
	}
}

func (c *networkSnapshot) ID() string { return "snapshot:network" }
func (c *networkSnapshot) Health() model.CollectorHealth {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

func (c *networkSnapshot) Run(ctx context.Context, emit func(model.CollectorRecord) error) error {
	ticker := time.NewTicker(c.every)
	defer ticker.Stop()
	// Snapshot định kỳ là nguồn dự phòng; kết nối tồn tại ngắn hơn chu kỳ có thể không được thấy.
	c.scan(emit)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.scan(emit)
		}
	}
}

func (c *networkSnapshot) scan(emit func(model.CollectorRecord) error) {
	rows, err := listTCP()
	if err != nil {
		st, reason, priv := ClassifyWinErr(err)
		c.mu.Lock()
		c.health.Status, c.health.Reason, c.health.PrivilegeStatus = st, reason, priv
		c.health.LastError = err.Error()
		c.health.LastErrorAt = time.Now().UTC()
		c.mu.Unlock()
		return
	}
	now := time.Now().UTC()
	for _, n := range rows {
		n := n
		key := fmt.Sprintf("snapshot|tcp|%d|%s|%d|%s|%d|%s", n.PID, n.LocalIP, n.LocalPort, n.RemoteIP, n.RemotePort, n.State)
		_ = emit(model.CollectorRecord{
			Source: "snapshot.network", SourceEventKey: key, EventTime: now,
			Kind: "network", Snapshot: true, Network: &n,
		})
	}
	c.mu.Lock()
	c.health.Status = "available"
	c.health.Reason = "fallback_reconciliation"
	c.health.LastSuccessAt = now
	c.health.EventsSeen += int64(len(rows))
	c.mu.Unlock()
}

type tcpRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

func listTCP() ([]model.NetworkFacts, error) {
	var size uint32
	r, _, err := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afINET, tcpTableOwnerPIDAll, 0)
	if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && r != 0 {
		if err != syscall.Errno(0) {
			return nil, err
		}
		return nil, windows.Errno(r)
	}
	buf := make([]byte, size)
	r, _, err = procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afINET, tcpTableOwnerPIDAll, 0)
	if r != 0 {
		if err != syscall.Errno(0) {
			return nil, err
		}
		return nil, windows.Errno(r)
	}
	if size < 4 {
		return nil, nil
	}
	count := binary.LittleEndian.Uint32(buf[:4])
	out := make([]model.NetworkFacts, 0, count)
	off := 4
	rowSize := int(unsafe.Sizeof(tcpRow{}))
	for i := uint32(0); i < count; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := (*tcpRow)(unsafe.Pointer(&buf[off]))
		off += rowSize
		lip := ipv4(row.LocalAddr)
		rip := ipv4(row.RemoteAddr)
		out = append(out, model.NetworkFacts{
			Protocol: "tcp", LocalIP: lip, LocalPort: int(ntohs(uint16(row.LocalPort))),
			RemoteIP: rip, RemotePort: int(ntohs(uint16(row.RemotePort))),
			State: tcpState(row.State), PID: int64(row.OwningPid),
		})
	}
	return out, nil
}

func ipv4(v uint32) string {
	b := [4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func ntohs(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func tcpState(s uint32) string {
	switch s {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RCVD"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT1"
	case 7:
		return "FIN_WAIT2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	default:
		return fmt.Sprintf("%d", s)
	}
}
