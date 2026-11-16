//go:build windows

package collector

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"AegisPlus/CrystaL/internal/model"
)

type SourceValidation struct {
	Group          string
	Channel        string
	ChannelPresent bool
	SampleFound    bool
	AccessDenied   bool
	ChannelMissing bool
	Detail         string
}

// ValidateEventSources kiểm tra quyền truy cập channel và log có event mẫu hay không.
// Không thấy event mẫu chưa đủ để kết luận audit đang bị tắt.
func ValidateEventSources(ctx context.Context, groups []model.EventGroup) []SourceValidation {
	results := make([]SourceValidation, 0, len(groups))
	for _, group := range groups {
		result := SourceValidation{Group: group.Name, Channel: group.Channel}
		if out, err := exec.CommandContext(ctx, "wevtutil.exe", "gl", group.Channel).CombinedOutput(); err != nil {
			detail := strings.ToLower(string(out) + " " + err.Error())
			switch {
			case strings.Contains(detail, "access is denied") || strings.Contains(detail, "access denied") || strings.Contains(detail, "error 5") || strings.Contains(detail, "exit status 5"):
				result.AccessDenied = true
				result.Detail = "Không đủ quyền đọc channel; chưa thể kết luận channel có sẵn hay không."
			case strings.Contains(detail, "specified channel could not be found") || strings.Contains(detail, "15007"):
				result.ChannelMissing = true
				result.Detail = "Không tìm thấy channel; kiểm tra thành phần Windows hoặc Sysmon đã cài chưa."
			default:
				result.Detail = "Không kiểm tra được channel: " + cleanCommandError(err)
			}
			results = append(results, result)
			continue
		}
		result.ChannelPresent = true
		ids := make([]string, 0, len(group.EventIDs))
		for _, id := range group.EventIDs {
			ids = append(ids, fmt.Sprintf("EventID=%d", id))
		}
		xpath := "*[System[" + strings.Join(ids, " or ") + "]]"
		query := "/q:" + xpath
		out, err := exec.CommandContext(ctx, "wevtutil.exe", "qe", group.Channel, query, "/c:1", "/rd:true", "/f:xml").CombinedOutput()
		if err == nil && strings.Contains(string(out), "<Event") {
			result.SampleFound = true
			result.Detail = "Channel truy cập được; tìm thấy ít nhất một event mẫu."
		} else if err == nil || containsNoEvents(string(out)) || containsNoEvents(err.Error()) {
			result.Detail = "Channel truy cập được; chưa có event mẫu phù hợp trong log hiện có."
		} else {
			result.Detail = "Channel tồn tại nhưng truy vấn event lỗi: " + cleanCommandError(err)
		}
		results = append(results, result)
	}
	return results
}

func containsNoEvents(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "no events") || strings.Contains(s, "no matching events") || strings.Contains(s, "query returned no results")
}

func cleanCommandError(err error) string {
	if err == nil {
		return "không rõ lỗi"
	}
	return strings.TrimSpace(err.Error())
}
