# PBRA Agent

PBRA Agent thu thập Windows Event Log, tiến trình và kết nối mạng. Dữ liệu được lưu trên máy tại `%ProgramData%\PBRA\pbra.json`.

## Chạy thử

Mở PowerShell bằng quyền Administrator tại thư mục dự án:

```powershell
go run ./cmd/agent validate-sources
go run ./cmd/agent run
```

Dừng bằng `Ctrl+C`.

## Chạy nền cùng Windows

Tạo file chạy:

```powershell
go build -o crystal-agent.exe ./cmd/agent
```

Cài và khởi động service:

```powershell
.\crystal-agent.exe install
Get-Service -Name CrystaLAgent
```

Service tự chạy khi Windows khởi động. Dừng hoặc chạy lại bằng:

```powershell
Stop-Service -Name CrystaLAgent
Start-Service -Name CrystaLAgent
```

Gỡ service:

```powershell
Stop-Service -Name CrystaLAgent
.\crystal-agent.exe uninstall
```

Không chạy lệnh `run` khi service đang hoạt động.

## Cấu hình và dữ liệu

Đặt `.env` và `events.yaml` cạnh file `.exe`. Mẫu cấu hình nằm trong `.env.example`. Log hoạt động của service nằm ở `%ProgramData%\PBRA\agent.log`.

Tra cứu lịch sử process:

```powershell
.\crystal-agent.exe process trace <PID-hoặc-Process-GUID>
```

## Nhánh hardening (đang kiểm thử)

Nhánh `fix/agent-ingestion-auth-hardening-20261119` chứa thay đổi ingestion và tương quan đăng nhập. Không hợp nhất vào `main` trước khi GitHub Actions (Windows + Linux) và kiểm thử thực tế chạy thành công.

- Event Log ghi checkpoint sau khi có xác nhận lưu dữ liệu, thử subscribe lại khi lỗi.
- Sửa bảo toàn NetworkFacts trong snapshot và replay.
- Chuẩn hóa AuthenticationFacts; cảnh báo theo heuristic: 5 lần 4625 trong 5 phút cùng user/domain/source IP, và 4624 LogonType 3/10 sau 5 thất bại.
- Kết quả nguồn log có trạng thái lỗi truy vấn tách biệt với "chưa thấy event".
- Chưa thay JSON store bằng SQLite, chưa xử lý xong raw XML nhạy cảm, chưa benchmark, và chưa chứng minh event không mất trong mọi failure mode. Đây chưa phải bản production-ready.

**Kiểm thử PowerShell Administrator (Windows):**

```powershell
go test ./...
go vet ./...
go run ./cmd/agent validate-sources
Get-Service CrystaLAgent -ErrorAction SilentlyContinue
go run ./cmd/agent run
```

Không chạy `run` đồng thời với service, CLI ghi hoặc replay vào cùng `pbra.json`. Sao lưu `C:\ProgramData\PBRA\pbra.json` trước khi thử nghiệm. Windows Security/Sysmon yêu cầu quyền phù hợp và audit policy; mã Agent không tự bật audit hay cấu hình Sysmon.
