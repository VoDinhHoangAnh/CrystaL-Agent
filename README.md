# CrystaL Agent

Agent Windows viết bằng Rust, thu thập Windows Event Log, process và kết nối mạng.

## Dữ liệu

- Dữ liệu chính: `%ProgramData%\PBRA\pbra.json`.
- Log theo nhóm: `%ProgramData%\PBRA\logs\Auth.log`, `Network.log` và `Sysmon.log`.
- Mỗi dòng trong file `.log` là một bản ghi JSON. Log cũ trong `pbra.json` không tự tách ngược ra file nhóm.
- Event process, System và các nguồn endpoint còn lại được gom vào `Sysmon.log`. File `Process.log` hoặc `System.log` từ bản cũ không tự nhập/xóa.
- Khi ổ log còn dưới 512 MiB, agent thử các thư mục dự phòng trong `.env`. File cũ vẫn ở ổ trước đó; event mới được ghi sang ổ dự phòng.
- `pbra.json` giữ raw 14 ngày và normalized 30 ngày theo cấu hình mặc định. File nhóm `.log` không tự xóa.

## Chạy thử

Mở PowerShell Administrator tại thư mục dự án:

```powershell
cargo build --release
.\target\release\crystal-agent.exe validate-sources
.\target\release\crystal-agent.exe run
```

Xem trạng thái:

```powershell
.\target\release\crystal-agent.exe status
```

Tra process:

```powershell
.\target\release\crystal-agent.exe process trace <PID-hoặc-GUID>
```

## Chạy cùng Windows

Cài service một lần bằng quyền Administrator:

```powershell
.\target\release\crystal-agent.exe install
```

Service được cấu hình tự chạy khi Windows khởi động. Gỡ bằng lệnh `uninstall`.

## Cấu hình

Sao chép `.env.example` thành `.env` để cấu hình đường dẫn dữ liệu, ổ dự phòng và thời hạn lưu. Nguồn event được khai báo trong `events.yaml`.
