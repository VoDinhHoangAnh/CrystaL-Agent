package networklogin

import "AegisPlus/CrystaL/internal/model"

const Category = "network_login"

// EventGroups chọn các nguồn đăng nhập mạng và truy cập dịch vụ đã cấu hình.
func EventGroups(cfg model.Config) []model.EventGroup {
	out := make([]model.EventGroup, 0)
	for _, group := range cfg.EventGroups {
		if group.Category == Category {
			out = append(out, group)
		}
	}
	return out
}
