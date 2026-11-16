package bruteforce

import "AegisPlus/CrystaL/internal/model"

const Category = "bruteforce"

// EventGroups chọn các group đăng ký nguồn xác thực phục vụ nhánh brute force.
func EventGroups(cfg model.Config) []model.EventGroup { return filter(cfg.EventGroups) }

func filter(groups []model.EventGroup) []model.EventGroup {
	out := make([]model.EventGroup, 0)
	for _, group := range groups {
		if group.Category == Category {
			out = append(out, group)
		}
	}
	return out
}
