package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// loadDotEnv tìm .env gần file chạy trước, nhưng không ghi đè biến môi trường đã có.
func loadDotEnv() {
	if explicit := strings.TrimSpace(os.Getenv("PBRA_ENV_FILE")); explicit != "" {
		if loadEnvFile(explicit) {
			return
		}
	}
	bases := make([]string, 0, 2)
	if executable, err := os.Executable(); err == nil {
		bases = append(bases, filepath.Dir(executable))
	}
	if cwd, err := os.Getwd(); err == nil {
		bases = append(bases, cwd)
	}
	seen := map[string]struct{}{}
	for _, base := range bases {
		for i := 0; i < 8; i++ {
			candidate := filepath.Join(base, ".env")
			if _, duplicate := seen[candidate]; !duplicate {
				seen[candidate] = struct{}{}
				if loadEnvFile(candidate) {
					return
				}
			}
			parent := filepath.Dir(base)
			if parent == base {
				break
			}
			base = parent
		}
	}
}

func loadEnvFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, value, found := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !found || !validEnvKey(key) || value == "" {
			continue
		}
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		// Biến do hệ điều hành hoặc service truyền vào được ưu tiên hơn giá trị trong file.
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, value)
		}
	}
	return true
}

func validEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
