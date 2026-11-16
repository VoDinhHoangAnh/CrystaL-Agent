package model

import "time"

const (
	AgentVersion    = "0.2.0"
	AnalyzerVersion = "1.0.0"
	RulesetVersion  = "1.0.0"
	SchemaVersion   = 1

	TypeProcess = "process"
	TypeNetwork = "network"
	TypeWinEvt  = "winevent"
)

// Config chứa giá trị agent cần trong suốt vòng đời chạy.
type Config struct {
	DataDir             string
	JSONPath            string
	AgentIDPath         string
	EventsFile          string
	EventConfigError    string
	EventGroups         []EventGroup
	QueueSize           int
	SnapshotEvery       time.Duration
	CollectCommandLine  bool
	RedactCommandLine   bool
	RawRetention        time.Duration
	NormalizedRetention time.Duration
	ResolvedRetention   time.Duration
	TrackMedium         bool
	Thresholds          Thresholds
	SuspiciousPorts     map[int]struct{}
	Channels            []Channel
}

// Thresholds là các mốc điểm dùng để gán mức severity.
type Thresholds struct {
	Low      int
	Medium   int
	High     int
	Critical int
}

// Channel mô tả một Windows Event Log channel và truy vấn Event ID cần nhận.
type Channel struct {
	Name     string
	Query    string
	EventIDs []int
}

// EventGroup mô tả mục đích giám sát và các nguồn Windows tương ứng.
type EventGroup struct {
	Name     string
	Category string
	Channel  string
	EventIDs []int
}

func DefaultThresholds() Thresholds {
	return Thresholds{Low: 1, Medium: 40, High: 70, Critical: 85}
}

func DefaultSuspiciousPorts() map[int]struct{} {
	return map[int]struct{}{4444: {}, 1337: {}, 5555: {}, 6666: {}, 31337: {}}
}
