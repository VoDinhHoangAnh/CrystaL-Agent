use crate::{
    Model::{Assessment, Finding, Normalized},
    Privacy,
};
use uuid::Uuid;

// Giữ bộ quy tắc hiện có ở mức heuristic; không xem điểm số là xác nhận mã độc.
pub fn analyze(event: &Normalized, instance_id: &str) -> Assessment {
    let mut findings = Vec::new();
    let mut add = |rule: &str, points: i32, severity: &str, reason: &str| {
        findings.push(Finding {
            finding_id: Uuid::new_v4().to_string(),
            rule_id: rule.into(),
            points,
            severity: severity.into(),
            reason: reason.into(),
            event_ids: vec![event.event_id.clone()],
        });
    };
    if event.secret_indicator {
        add(
            "secret_in_commandline",
            35,
            "high",
            "Command line có tham số giống thông tin xác thực; giá trị đã được che.",
        );
    }
    if let Some(p) = &event.process {
        let cmd = p.command_line.as_deref().unwrap_or("").to_ascii_lowercase();
        let path = p
            .image_path
            .as_deref()
            .unwrap_or("")
            .replace('/', "\\")
            .to_ascii_lowercase();
        let parent = p.parent_image.as_deref().unwrap_or("").to_ascii_lowercase();
        if cmd.contains("-enc ") || cmd.contains("-encodedcommand") {
            add(
                "powershell_encoded",
                30,
                "high",
                "Phát hiện tham số lệnh PowerShell dạng mã hóa.",
            );
        }
        if cmd.contains("-windowstyle hidden") || cmd.contains("-w hidden") {
            add(
                "hidden_window",
                10,
                "low",
                "Tiến trình yêu cầu chạy cửa sổ ẩn.",
            );
        }
        if [
            "\\users\\public\\",
            "\\appdata\\local\\temp\\",
            "\\windows\\temp\\",
            "\\downloads\\",
        ]
        .iter()
        .any(|x| path.contains(x))
        {
            add(
                "unusual_execution_path",
                15,
                "medium",
                "Tệp chạy từ thư mục người dùng có thể ghi.",
            );
        }
        let parent_script = [
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "msaccess.exe",
            "msedge.exe",
            "chrome.exe",
            "firefox.exe",
        ]
        .iter()
        .any(|x| parent.ends_with(x));
        let child_script = [
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
        ]
        .iter()
        .any(|x| path.ends_with(x) || cmd.contains(x));
        if parent_script && child_script {
            add(
                "suspicious_parent_child",
                25,
                "high",
                "Ứng dụng văn phòng hoặc trình duyệt tạo tiến trình chạy script.",
            );
        }
    }
    if let Some(n) = &event.network
        && matches!(n.remote_port, 4444 | 1337 | 5555 | 6666 | 31337)
    {
        add(
            "suspicious_port",
            15,
            "medium",
            "Kết nối dùng cổng cần được xem xét thêm.",
        );
    }
    let score = findings.iter().map(|f| f.points).sum::<i32>().min(100);
    let severity = if score >= 85 {
        "critical"
    } else if score >= 70 {
        "high"
    } else if score >= 40 {
        "medium"
    } else if score >= 1 {
        "low"
    } else {
        "info"
    }
    .to_owned();
    Assessment {
        assessment_id: Uuid::new_v4().to_string(),
        score,
        severity: severity.clone(),
        confidence: if instance_id.is_empty() { 0.8 } else { 1.0 },
        track: matches!(severity.as_str(), "high" | "critical" | "medium"),
        findings,
    }
}

pub fn has_secret(event: &Normalized) -> bool {
    event.secret_indicator
        || event
            .process
            .as_ref()
            .and_then(|p| p.command_line.as_deref())
            .is_some_and(Privacy::contains_secret)
}
