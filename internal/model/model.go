package model

import (
	"encoding/json"
	"encoding/xml"
	"time"
)

// RawEnvelope giữ event gần với dữ liệu nguồn để có thể phát lại khi cần.
type RawEnvelope struct {
	EventID        string          `json:"event_id"`
	AgentID        string          `json:"agent_id"`
	Source         string          `json:"source"`
	SourceEventKey string          `json:"source_event_key"`
	EventTime      string          `json:"event_time"`
	ObservedAt     string          `json:"observed_at"`
	SchemaVersion  int             `json:"schema_version"`
	Kind           string          `json:"kind"`
	Snapshot       bool            `json:"snapshot"`
	XML            string          `json:"xml,omitempty"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	SpoolPath      string          `json:"-"`
	SpoolOffset    int64           `json:"-"`
}

type SourceRecord struct {
	EventID        string
	Source         string
	SourceEventKey string
	EventTime      time.Time
	ObservedAt     time.Time
	Kind           string
	Snapshot       bool
	XML            string
	Payload        json.RawMessage
	SecretDetected bool
	Process        *ProcessFacts
	Parent         *ProcessFacts
	Network        *NetworkFacts
}

type CollectorRecord struct {
	Source         string
	SourceEventKey string
	EventTime      time.Time
	Kind           string
	Snapshot       bool
	XML            string
	Payload        json.RawMessage
	SecretDetected bool
	Process        *ProcessFacts
	Parent         *ProcessFacts
	Network        *NetworkFacts
}

// Normalized là dạng event thống nhất mà các service và rule đọc.
type Normalized struct {
	EventID             string        `json:"event_id"`
	AgentID             string        `json:"agent_id"`
	EventType           string        `json:"event_type"`
	Source              string        `json:"source"`
	SourceEventKey      string        `json:"source_event_key"`
	EventTime           time.Time     `json:"event_time"`
	ObservedAt          time.Time     `json:"observed_at"`
	SchemaVersion       int           `json:"schema_version"`
	Snapshot            bool          `json:"snapshot,omitempty"`
	Process             *ProcessFacts `json:"process,omitempty"`
	Parent              *ProcessFacts `json:"parent,omitempty"`
	Network             *NetworkFacts `json:"network,omitempty"`
	Authentication      *AuthenticationFacts `json:"authentication,omitempty"`
	Windows             *WindowsFacts `json:"windows,omitempty"`
	SecretIndicator     bool          `json:"secret_indicator,omitempty"`
	SecretPatternType   string        `json:"secret_pattern_type,omitempty"`
	SecretField         string        `json:"secret_field,omitempty"`
	CommandLineRedacted string        `json:"command_line_redacted,omitempty"`
}

// ProcessFacts mô tả một lần chạy process cùng thông tin cha và vòng đời.
type ProcessFacts struct {
	PID           int64     `json:"pid"`
	PPID          int64     `json:"ppid"`
	GUID          string    `json:"process_guid,omitempty"`
	ParentGUID    string    `json:"parent_process_guid,omitempty"`
	ImagePath     string    `json:"image_path,omitempty"`
	ImageName     string    `json:"image_name,omitempty"`
	CommandLine   string    `json:"command_line,omitempty"`
	User          string    `json:"user,omitempty"`
	Integrity     string    `json:"integrity,omitempty"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	EndedAt       time.Time `json:"ended_at,omitempty"`
	ExitCode      *int64    `json:"exit_code,omitempty"`
	Action        string    `json:"action,omitempty"`
	Hashes        string    `json:"hashes,omitempty"`
	SHA256        string    `json:"sha256,omitempty"`
	LogonID       string    `json:"logon_id,omitempty"`
	SessionID     string    `json:"session_id,omitempty"`
	ParentImage   string    `json:"parent_image,omitempty"`
	ParentCommand string    `json:"parent_command_line,omitempty"`
}

// NetworkFacts mô tả một endpoint mạng được gắn với PID hoặc Process GUID.
type NetworkFacts struct {
	Protocol   string `json:"protocol"`
	Direction  string `json:"direction,omitempty"`
	LocalIP    string `json:"local_ip,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	State      string `json:"state,omitempty"`
	Domain     string `json:"domain,omitempty"`
	PID        int64  `json:"pid,omitempty"`
	GUID       string `json:"process_guid,omitempty"`
}

// AuthenticationFacts phân biệt tín hiệu xác thực với kết luận có cuộc tấn công.
type AuthenticationFacts struct {
	EventCode int    `json:"event_code"`
	Username string   `json:"username,omitempty"`
	Domain string     `json:"domain,omitempty"`
	SourceIP string   `json:"source_ip,omitempty"`
	Workstation string `json:"workstation,omitempty"`
	LogonType int      `json:"logon_type,omitempty"`
	Result string      `json:"result"`
	FailureCode string `json:"failure_code,omitempty"`
}

// WindowsFacts giữ các trường Windows cần để tra cứu lại nguồn event.
type WindowsFacts struct {
	Provider  string            `json:"provider"`
	Channel   string            `json:"channel"`
	EventCode int               `json:"event_code"`
	Version   int               `json:"version,omitempty"`
	Computer  string            `json:"computer,omitempty"`
	RecordID  int64             `json:"record_id,omitempty"`
	Severity  string            `json:"severity,omitempty"`
	Message   string            `json:"message,omitempty"`
	EventData map[string]string `json:"event_data,omitempty"`
}

type WinEvent struct {
	XMLName   xml.Name  `xml:"Event"`
	System    WinSystem `xml:"System"`
	EventData struct {
		Data []WinData `xml:"Data"`
	} `xml:"EventData"`
}

type WinSystem struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	} `xml:"Provider"`
	EventID     string `xml:"EventID"`
	Version     string `xml:"Version"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	EventRecordID string `xml:"EventRecordID"`
	Channel       string `xml:"Channel"`
	Computer      string `xml:"Computer"`
	Level         string `xml:"Level"`
}

type WinData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// Assessment là kết quả đánh giá được lưu cạnh event đã chuẩn hóa.
type Assessment struct {
	AssessmentID    string    `json:"assessment_id"`
	Score           int       `json:"score"`
	Severity        string    `json:"severity"`
	Track           bool      `json:"track"`
	Confidence      float64   `json:"confidence"`
	DataQuality     []string  `json:"data_quality,omitempty"`
	AnalyzerVersion string    `json:"analyzer_version"`
	RulesetVersion  string    `json:"ruleset_version"`
	Findings        []Finding `json:"findings,omitempty"`
}

// Finding ghi lại rule đã khớp và các định danh bằng chứng liên quan.
type Finding struct {
	FindingID   string   `json:"finding_id"`
	RuleID      string   `json:"rule_id"`
	RuleVersion string   `json:"rule_version"`
	Points      int      `json:"points"`
	Severity    string   `json:"severity"`
	Reason      string   `json:"reason"`
	Confidence  float64  `json:"confidence"`
	EventIDs    []string `json:"event_ids,omitempty"`
	ProcessIDs  []string `json:"process_instance_ids,omitempty"`
	IPIDs       []string `json:"ip_addresses,omitempty"`
}

// RiskInput gom dữ liệu đã chuẩn hóa đưa vào bộ phân tích.
type RiskInput struct {
	CommandLine       string
	ImagePath         string
	ParentImage       string
	EventIDs          []int
	RemoteIP          string
	RemotePort        int
	Protocol          string
	SignatureStatus   string
	EventID           string
	ProcessInstanceID string
	ParentResolved    bool
	CollectorDegraded bool
	PIDReuseAmbiguous bool
	MissingParent     bool
	IsSnapshot        bool
	AlreadyFired      map[string]bool
	SecretIndicator   bool
	Low               int
	Medium            int
	High              int
	Critical          int
	TrackMedium       bool
	SuspiciousPorts   map[int]struct{}
}

// TrackedEntity là process hoặc IP đang được theo dõi qua nhiều event.
type TrackedEntity struct {
	EntityID   string    `json:"entity_id"`
	AgentID    string    `json:"agent_id"`
	EntityType string    `json:"entity_type"`
	EntityKey  string    `json:"entity_key"`
	Status     string    `json:"status"`
	Severity   string    `json:"severity"`
	Score      int       `json:"score"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Owner      string    `json:"owner,omitempty"`
	Note       string    `json:"note,omitempty"`
}

// CollectorHealth lưu trạng thái gần nhất của từng collector.
type CollectorHealth struct {
	CollectorID     string    `json:"collector_id"`
	Status          string    `json:"status"`
	Reason          string    `json:"reason,omitempty"`
	LastSuccessAt   time.Time `json:"last_success_at,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	LastErrorAt     time.Time `json:"last_error_at,omitempty"`
	PrivilegeStatus string    `json:"privilege_status,omitempty"`
	EventsSeen      int64     `json:"events_seen"`
}

// GraphSlot đại diện một instance process trong đồ thị quan hệ.
type GraphSlot struct {
	InstanceID string
	PID        int64
	GUID       string
	Started    time.Time
	Ended      time.Time
	Stub       bool
	Resolved   bool
}

// ResolveResult trả về kết quả ghép event với instance và process cha.
type ResolveResult struct {
	InstanceID        string
	ParentID          string
	ParentResolved    bool
	PIDReuseAmbiguous bool
	MissingParent     bool
	NewInstance       bool
}

type Redaction struct {
	Redacted     string
	Indicator    bool
	PatternType  string
	Field        string
	MatchedValue string
}

type PersistInput struct {
	Norm         Normalized `json:"normalized"`
	RawRef       string     `json:"raw_ref,omitempty"`
	ImageID      string     `json:"image_id,omitempty"`
	InstanceID   string     `json:"process_instance_id,omitempty"`
	ParentID     string     `json:"parent_process_instance_id,omitempty"`
	SessionID    string     `json:"session_id,omitempty"`
	Assessment   Assessment `json:"assessment"`
	TrackProcess bool       `json:"track_process"`
	TrackIP      bool       `json:"track_ip"`
	IPKey        string     `json:"ip_key,omitempty"`
}

type Stats struct {
	JSONPath       string
	DataDir        string
	RawBytes       int64
	TelemetryCount int64
	RawUnprocessed int64
	CurrentTracked int64
	LastEventTime  time.Time
	Collectors     []CollectorHealth
}
