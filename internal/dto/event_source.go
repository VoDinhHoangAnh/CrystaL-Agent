package dto

// EventSourceStatus là kết quả kiểm tra nguồn Windows để trả về cho lệnh CLI/API.
type EventSourceStatus struct {
	Group          string `json:"group"`
	Category       string `json:"category"`
	Channel        string `json:"channel"`
	ChannelPresent bool   `json:"channel_present"`
	SampleFound    bool   `json:"sample_event_found"`
	AccessDenied   bool   `json:"access_denied"`
	ChannelMissing bool   `json:"channel_missing"`
	Detail         string `json:"detail"`
}
