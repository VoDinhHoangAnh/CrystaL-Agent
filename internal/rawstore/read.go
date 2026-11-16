// Package rawstore đọc log JSONL cũ được đưa vào để chạy phân tích lại.
// Khi thu thập trực tiếp, dữ liệu được ghi vào file pbra.json duy nhất.
package rawstore

import (
	"bufio"
	"encoding/json"
	"os"

	"AegisPlus/CrystaL/internal/model"
)

func ReadFile(path string) ([]model.RawEnvelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []model.RawEnvelope
	// Tăng giới hạn dòng vì một event raw có thể chứa XML dài hơn mặc định của Scanner.
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var env model.RawEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			return nil, err
		}
		out = append(out, env)
	}
	return out, sc.Err()
}
