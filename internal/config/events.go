package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"AegisPlus/CrystaL/internal/model"
)

// LoadEventGroups đọc phần cú pháp YAML đơn giản được dùng trong events.yaml.
// Không thêm thư viện YAML giúp đóng gói agent Windows gọn hơn.
func LoadEventGroups(path string) ([]model.EventGroup, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open events config: %w", err)
	}
	defer f.Close()

	var groups []model.EventGroup
	var current *model.EventGroup
	s := bufio.NewScanner(f)
	// Parser chỉ nhận các trường agent đang dùng; cấu trúc YAML phức tạp sẽ báo lỗi rõ dòng.
	for lineNo := 1; s.Scan(); lineNo++ {
		line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
		if line == "" || line == "groups:" {
			continue
		}
		if strings.HasPrefix(line, "- name:") {
			if current != nil {
				groups = append(groups, *current)
			}
			current = &model.EventGroup{Name: strings.TrimSpace(strings.TrimPrefix(line, "- name:"))}
			continue
		}
		if current == nil {
			return nil, fmt.Errorf("events config line %d: expected a group name", lineNo)
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("events config line %d: expected key: value", lineNo)
		}
		switch strings.TrimSpace(key) {
		case "category":
			current.Category = strings.TrimSpace(strings.Trim(value, "\"'"))
		case "channel":
			current.Channel = strings.Trim(strings.TrimSpace(value), "\"'")
		case "event_ids":
			ids, err := parseEventIDs(value)
			if err != nil {
				return nil, fmt.Errorf("events config line %d: %w", lineNo, err)
			}
			current.EventIDs = ids
		default:
			return nil, fmt.Errorf("events config line %d: unsupported key %q", lineNo, strings.TrimSpace(key))
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if current != nil {
		groups = append(groups, *current)
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("events config contains no groups")
	}
	for _, g := range groups {
		if strings.TrimSpace(g.Name) == "" || strings.TrimSpace(g.Category) == "" || strings.TrimSpace(g.Channel) == "" || len(g.EventIDs) == 0 {
			return nil, fmt.Errorf("invalid event group %q: name, category, channel and event_ids are required", g.Name)
		}
	}
	return groups, nil
}

func parseEventIDs(value string) ([]int, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, fmt.Errorf("event_ids must be a YAML inline list, such as [4624, 4625]")
	}
	value = strings.TrimSpace(value[1 : len(value)-1])
	if value == "" {
		return nil, fmt.Errorf("event_ids cannot be empty")
	}
	seen := make(map[int]struct{})
	var ids []int
	for _, part := range strings.Split(value, ",") {
		id, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || id < 0 {
			return nil, fmt.Errorf("invalid event ID %q", part)
		}
		if _, ok := seen[id]; !ok {
			ids = append(ids, id)
			seen[id] = struct{}{}
		}
	}
	sort.Ints(ids)
	return ids, nil
}

func ChannelsFromEventGroups(groups []model.EventGroup) []model.Channel {
	// Nhiều nhóm có thể dùng chung channel, nên gộp Event ID để chỉ đăng ký một lần.
	byName := make(map[string]*model.Channel)
	order := make([]string, 0)
	for _, group := range groups {
		channel := byName[group.Channel]
		if channel == nil {
			channel = &model.Channel{Name: group.Channel}
			byName[group.Channel] = channel
			order = append(order, group.Channel)
		}
		for _, id := range group.EventIDs {
			found := false
			for _, existing := range channel.EventIDs {
				if existing == id {
					found = true
					break
				}
			}
			if !found {
				channel.EventIDs = append(channel.EventIDs, id)
			}
		}
	}
	channels := make([]model.Channel, 0, len(order))
	for _, name := range order {
		ch := *byName[name]
		sort.Ints(ch.EventIDs)
		if len(ch.EventIDs) > 0 {
			ids := make([]string, 0, len(ch.EventIDs))
			for _, id := range ch.EventIDs {
				ids = append(ids, strconv.Itoa(id))
			}
			ch.Query = "*[System[" + strings.Join(mapToOr(ids), " or ") + "]]"
		}
		channels = append(channels, ch)
	}
	return channels
}

func mapToOr(ids []string) []string {
	for i, id := range ids {
		ids[i] = "EventID=" + id
	}
	return ids
}

func FindEventsFile() string {
	if explicit := strings.TrimSpace(os.Getenv("PBRA_EVENTS_FILE")); explicit != "" {
		return explicit
	}
	bases := []string{"."}
	if executable, err := os.Executable(); err == nil {
		bases = append([]string{filepath.Dir(executable)}, bases...)
	}
	for _, base := range bases {
		for i := 0; i < 8; i++ {
			candidate := filepath.Join(base, "events.yaml")
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
			parent := filepath.Dir(base)
			if parent == base {
				break
			}
			base = parent
		}
	}
	return "events.yaml"
}
