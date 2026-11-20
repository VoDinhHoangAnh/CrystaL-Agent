package normalize

import (
	"encoding/xml"
	"strconv"
	"strings"
	"time"

	"AegisPlus/CrystaL/internal/model"
)

// parseWinXML tách phần System và EventData để các mapper xử lý theo Event ID.
func parseWinXML(raw string) (model.WinEvent, map[string]string, error) {
	var ev model.WinEvent
	if err := xml.Unmarshal([]byte(raw), &ev); err != nil {
		return ev, nil, err
	}
	m := map[string]string{}
	for _, d := range ev.EventData.Data {
		m[d.Name] = strings.TrimSpace(d.Value)
	}
	// Event 1149 places user/domain/client address under
	// <UserData><EventXML xmlns="Event_NS"><Param1..3>.
	// Do not mistake this authentication signal for an established logon session.
	if ev.System.EventID == "1149" {
		var nested struct {
			UserData struct {
				EventXML struct {
					Param1 string `xml:"Param1"`
					Param2 string `xml:"Param2"`
					Param3 string `xml:"Param3"`
				} `xml:"EventXML"`
			} `xml:"UserData"`
		}
		if err := xml.Unmarshal([]byte(raw), &nested); err != nil {
			return ev, nil, err
		}
		if nested.UserData.EventXML.Param1 != "" {
			m["RDPUser"] = strings.TrimSpace(nested.UserData.EventXML.Param1)
		}
		if nested.UserData.EventXML.Param2 != "" {
			m["RDPDomain"] = strings.TrimSpace(nested.UserData.EventXML.Param2)
		}
		if nested.UserData.EventXML.Param3 != "" {
			m["RDPSourceIP"] = strings.TrimSpace(nested.UserData.EventXML.Param3)
		}
	}
	return ev, m, nil
}

func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse("2006-01-02 15:04:05.000", s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse("2006-01-02 15:04:05.0000000", s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func atoi64(s string) int64 {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		n, _ := strconv.ParseInt(s[2:], 16, 64)
		return n
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func basename(p string) string {
	p = strings.ReplaceAll(p, "/", "\\")
	if i := strings.LastIndex(p, "\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func hashSHA256(hashes string) string {
	for _, part := range strings.Split(hashes, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], "SHA256") {
			return strings.ToLower(kv[1])
		}
	}
	if len(hashes) == 64 {
		return strings.ToLower(hashes)
	}
	return ""
}
