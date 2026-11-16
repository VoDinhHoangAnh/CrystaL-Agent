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
