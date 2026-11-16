package dto

import (
	"AegisPlus/CrystaL/internal/model"
	"time"
)

// TraceEvent là một sự kiện trong timeline của process.
type TraceEvent struct {
	EventID        string              `json:"event_id"`
	EventType      string              `json:"event_type"`
	Source         string              `json:"source"`
	SourceEventKey string              `json:"source_event_key"`
	EventTime      time.Time           `json:"event_time"`
	Process        *model.ProcessFacts `json:"process,omitempty"`
	Network        *model.NetworkFacts `json:"network,omitempty"`
	Windows        *model.WindowsFacts `json:"windows,omitempty"`
	Score          int                 `json:"risk_score"`
	Severity       string              `json:"severity"`
	Findings       []model.Finding     `json:"findings,omitempty"`
}

// ProcessNode biểu diễn một process và liên kết đến process cha.
type ProcessNode struct {
	InstanceID string             `json:"process_instance_id"`
	ParentID   string             `json:"parent_process_instance_id,omitempty"`
	Process    model.ProcessFacts `json:"process"`
}

// TCPFlow gom các event mạng có cùng cặp endpoint TCP.
type TCPFlow struct {
	Protocol   string       `json:"protocol"`
	Direction  string       `json:"direction,omitempty"`
	LocalIP    string       `json:"local_ip,omitempty"`
	LocalPort  int          `json:"local_port,omitempty"`
	RemoteIP   string       `json:"remote_ip,omitempty"`
	RemotePort int          `json:"remote_port,omitempty"`
	Events     []TraceEvent `json:"events"`
}

// ProcessTrace là kết quả truy vấn ngược theo PID hoặc Process GUID.
type ProcessTrace struct {
	Selector string        `json:"selector"`
	Nodes    []ProcessNode `json:"process_tree"`
	Events   []TraceEvent  `json:"events"`
	TCPFlows []TCPFlow     `json:"tcp_flows"`
}
