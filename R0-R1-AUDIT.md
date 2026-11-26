# R0 / R1 — Rust baseline audit and storage integrity

Ngày kiểm toán: 2026-11-26. Workspace: `D:\DACN\Agent\CrystaL-Rust-Codex`.
Branch: `fix/rust-r1-store-integrity`. Baseline xác minh: `914f2ee6748108dd342012e44a81212465910571`; working tree ban đầu sạch.
Rustc/Cargo 1.100.0, Windows MSVC. Không đổi Cargo.toml, Cargo.lock hoặc toolchain.

## R0: kiến trúc và mức độ hoàn thiện

Đã đọc các implementation, module wiring, model/DTO, README, events.yaml và cấu hình. Các nhận định hành vi Windows collection/service là static audit; không cài service hoặc thu thập dữ liệu thật trong đợt này. Không có đặc tả dự án độc lập hay baseline phiên bản trước trong yêu cầu: đối chiếu yêu cầu người dùng, README, events.yaml và cấu hình; không khẳng định hồi quy lịch sử khi chưa có bằng chứng.

Luồng thực tế:

1. `main.rs:11` tải Config, phân luồng CLI; service chuyển sang AgentRuntime qua Windows SCM.
2. `AgentRuntime.rs:34` mở writer, lấy agent-id, ensure_agent, tạo ProcessGraph trong RAM. Vòng lặp retention mỗi ngày, Event Log mỗi vòng, snapshot theo interval, ngủ 2 giây.
3. `WindowsEventCollector.rs:21` gộp channel/event IDs, đọc checkpoint, chạy wevtutil với RecordID lớn hơn checkpoint, giới hạn 500/channel; trả cả batch raw. `:109` chạy PowerShell CIM/TCP snapshot, so sánh PID trong RAM.
4. `AgentRuntime.rs:138` normalize → resolve process/parent → Risk::analyze → chọn entity tracking/IP.
5. `EventNormalizer.rs:14` parse XML hoặc payload, map process/network, redact normalized command line. Không sửa raw envelope.
6. `BehaviorAnalyst.rs:8` tính điểm từng event theo heuristic process/port/secret. Không có correlation authentication theo cửa sổ thời gian.
7. `CategoryLogStore.rs:56` chọn Auth/Network/Sysmon, dedupe cuối file, append JSONL vào primary/fallback. Archive đứng trước persist.
8. `JsonFileStore::commit_event` gộp raw, normalized/assessment, entity và checkpoint vào một document; write temporary → sync → replace main. Chỉ checkpoint Event Log nếu archive thành công; archive lỗi vẫn lưu event, không tiến checkpoint, dừng batch để retry.
9. `status` và `process trace` đọc snapshot. Sau R1 chỉ đọc main đã commit, không đọc/promote/delete temporary. Snapshot giữ nguyên đến khi mở lại.

| Nhóm | Đã triển khai | Giới hạn / phần chỉ có facade |
|---|---|---|
| Config | env, .env, event-group parser, retention/interval | parser YAML thủ công; queue_size và track_medium chưa được dùng |
| Collector | wevtutil, process delta, TCP snapshot, cancellation/timeout | chưa kiểm thử live; không phải subscription/queue bền vững |
| Normalize/Privacy | XML, process/TCP/DNS facts, regex che secret | không bảo vệ raw; không phải bộ redaction tổng quát |
| Risk | heuristic stateless process/port | không có detector Brute Force, Network Login hoặc RDP correlation |
| ProcessGraph | PID/GUID resolution, parent placeholders | chỉ RAM; không hydrate sau restart |
| Store/Repository | JSON state, entity transitions, retention, JSONL fallback | toàn document trong RAM và rewrite; không phải database transaction giữa hai kho |
| Service/Controller | SCM, validate-sources, trace delegation | BruteForce/NetworkLogin chỉ lọc event groups rồi validate source |
| RawStore/Tracking/DTO | alias JsonStore/TrackedEntity/trace types, EventSourceStatus | không có raw-store hoặc tracking engine độc lập |

## Findings R0

Các dòng dưới đây tham chiếu **baseline SHA** để bằng chứng không thay đổi theo patch. P0: mất dữ liệu diện rộng/khẩn cấp; P1: correctness/security nghiêm trọng; P2: độ tin cậy/chức năng; P3: kiểm chứng/khả năng vận hành. Không có P0 được xác nhận.

| ID | Mức | File:dòng baseline, bằng chứng và ảnh hưởng | Kết quả |
|---|---|---|---|
| S01 | P1 | `src/Store/JsonFileStore.rs:104,109,292`: mỗi open giữ doc riêng, save truncate cùng temp, không khóa; writer B có thể ghi mất event/checkpoint của A | R1: OS exclusive lock suốt vòng đời writer; writer thứ hai fail trước đọc/recovery |
| S02 | P1 | `src/Agent/AgentRuntime.rs:214`, `src/main.rs:47`, `JsonFileStore.rs:110-136`: lệnh đọc tạo directory/main, promote hoặc xóa temp; có thể can thiệp commit đang chạy | R1: JsonSnapshot + RepositoryReader; CLI chỉ đọc main |
| S03 | P1 | `JsonFileStore.rs:314-316,117-126`: `.ok()` xóa khác biệt I/O error, missing, invalid JSON; có thể chọn temp cũ khi main bị denied/sharing error | R1: mọi lỗi I/O trừ NotFound trả lỗi; không reset hoặc thay main khi không đọc được |
| S04 | P1 | `JsonFileStore.rs:183-214,292-304`: sửa RAM trước save; save lỗi, lần retry dedupe có thể trả Ok mà dữ liệu chưa được lưu | R1: mọi mutation kiểm tra writer; save lỗi làm writer không được ghi tiếp cho đến reopen/recovery |
| S05 | P1 | `CategoryLogStore.rs:121-139`, `AgentRuntime.rs:177-209`: append không sync trước khi checkpoint được sync; có thể checkpoint vượt log bền vững | R1: sync_all cả append và dedupe acknowledgment; sidecar lock và dedupe lại dưới khóa |
| S06 | P1 | `AgentRuntime.rs:15,209`, `JsonFileStore.rs:216-230`, `EventNormalizer.rs:14-85`: persist nguyên raw.xml/payload; command line có secret vẫn nằm trong JSON dù normalized đã redact | Backlog privacy, ngoài R1; không đưa raw mẫu nhạy cảm vào report |
| S07 | P2 | `JsonFileStore.rs:158-167`: save_checkpoint chấp nhận ID thấp hơn | R1: monotonic, replay ID cũ là no-op |
| S08 | P2 | `JsonFileStore.rs:293,319-320`: recovery dùng wall clock; clock quay lại làm temp commit mới trông cũ hơn main | R1: timestamp commit tăng tối thiểu 1ns so với document trước |
| S09 | P2 | `JsonFileStore.rs:58-75,314-316`: nhận schema tương lai, bỏ field lạ rồi rewrite mất dữ liệu không hiểu | R1: từ chối schema không hỗ trợ, giữ nguyên file |
| S10 | P1 | `JsonFileStore.rs:329-350`: Windows MoveFileExW chỉ thử một lần; regression concurrent reader/writer thực tế gặp Access denied | R1: đóng temp handle trước rename; retry lỗi sharing/access trong tối đa khoảng 1 giây, giữ temp và báo lỗi nếu hết hạn |
| S11 | P2 | `JsonFileStore.rs:308-311`: set_extension("json.tmp") làm a.json và a.backup dùng cùng temporary, dù khóa main khác nhau | R1: nối .tmp vào toàn tên file; pbra.json.tmp hiện tại giữ nguyên |
| B01 | P1 | `Service/BruteForce/BruteForceService.rs:5`, `Service/NetworkLogin/NetworkLoginService.rs:5`, `Risk/BehaviorAnalyst.rs:8-133`: chỉ lọc group, risk không đọc chuỗi auth; events.yaml yêu cầu ghép chuỗi login | Backlog Brute Force / Network Login / RDP; không refactor |
| B02 | P2 | `Collector/WindowsEventCollector.rs:58-73`: lỗi wevtutil ngoài các nhánh đặc biệt bị continue im lặng; `AgentRuntime.rs:98-105` chỉ ghi health lỗi, không ghi health thành công | Backlog collector/observability |
| B03 | P2 | `Collector/WindowsEventCollector.rs:136-158`: snapshot đầu không xuất process hiện tại; PID reuse không thấy nếu PID vẫn tồn tại; delta RAM cập nhật trước persist | Backlog collector; snapshot có thể mất khi lỗi ingest, ngoài cam kết R1 concurrent storage |
| B04 | P2 | `ProcessGraph/ProcessGraph.rs:22-25,51-65`, `AgentRuntime.rs:64`: PID có thể bị gộp, state mất sau restart; trace có thể đứt liên kết | Backlog process identity; không đổi thuật toán trace |
| B05 | P2 | `CategoryLogStore.rs:82-90,153-179`: chỉ dedupe dòng cuối; A,B rồi replay A vẫn thêm A. Lookup lỗi ở primary thoát trước thử fallback | Backlog archive replay/fallback; R1 bảo vệ writer và độ bền, không hứa exactly-once toàn archive |
| B06 | P2 | `JsonFileStore.rs:292-304`, `CategoryLogStore.rs:181-218`: rewrite toàn state mỗi event, read_last_line có thể giữ một dòng không giới hạn; log nhóm không retention | Backlog storage scalability/capacity, rủi ro OOM/disk full |
| B07 | P2 | `Config/AgentConfiguration.rs:27,33,68,74`, `Risk/BehaviorAnalyst.rs:130`: queue_size, track_medium không được áp dụng | Backlog configuration correctness |
| B08 | P2 | `Service/WindowsServiceManager.rs:35,66-74`: exit code luôn 0, bỏ lỗi run_until; SCM có thể báo dừng thành công khi writer bị từ chối/lỗi | Backlog service error reporting |
| B09 | P2 | `Privacy/SensitiveDataRedactor.rs:4-14`: regex chỉ nhận secret có dấu :/=, không bao quát bearer cách bằng space hoặc secret quoted có space; `EventNormalizer.rs:38-43,66-77` vẫn giữ event_data command line khi collect_cmdline=false | Backlog privacy/config semantics |
| B10 | P3 | `Service/EventSource/EventSourceService.rs:24-29`: sample_found dựa exit status query channel, không lọc event_ids hoặc xác nhận nội dung có event | Backlog source validation |
| B11 | P3 | `Store/JsonFileStore.rs:617`, `CategoryLogStore.rs:275`; không có test ở module khác | Backlog coverage cho normalize/risk/privacy/graph/collector/config/service |

## R1: contract và regression tests

Writer mở khóa sidecar `pbra.json.lock` trước đọc/recovery; giữ handle đến Drop hoặc process exit. File lock để lại có chủ ý, không dùng sự tồn tại file làm bằng chứng khóa. Parent được canonicalize để aliases directory dùng cùng sidecar. Contention trả lỗi ngay, không xếp hàng hoặc merge stale documents. FileLogArchive cũng khóa sidecar theo file log, bảo vệ append và lần kiểm tra dedupe thứ hai. Không thay đổi collector, detector, service lifecycle hoặc dependency.

Read-only type không implement Repository (write trait), không expose inner writer. RepositoryReader chỉ có stats/trace; Controller và Service Process chỉ đổi bound nhận trait đọc. Reader không tạo directory/lock/main, không dọn temporary và không enroll agent. Main thiếu/corrupt trả lỗi; operator cần writer hợp lệ để recovery. Reader tồn tại trước commit giữ snapshot cũ, mở reader mới lấy commit mới.

Recovery writer: main + temp valid chọn timestamp mới hơn; main invalid/missing + temp valid promote; main valid + temp invalid/stale bỏ temp; cả hai invalid trả lỗi; cả hai missing mới tạo document. I/O error và schema không hỗ trợ trả lỗi. Commit event cập nhật checkpoint cùng document sau archive. Khi save thất bại, RAM chưa chắc phản ánh main; handle bị chặn mọi mutation để tránh báo thành công giả, giữ khóa cho đến drop.

Regression mapping (tên test trong `src/Store/JsonFileStore.rs`, trừ khi chỉ rõ):

| Findings / contract | Tests |
|---|---|
| S01, S07; ownership, aliases, checkpoint không lùi | writer_exclusion_and_release_preserve_checkpoint |
| S01; khóa liên process và release khi exit bỏ qua Drop | cross_process_exclusion_and_exit_release + child_writer_probe |
| S01, S10; snapshot đọc trong lúc 25 event/checkpoint được commit; reopen không mất dữ liệu | concurrent_snapshots_preserve_all_committed_events |
| S02; API read không tạo/sửa/xóa state/temp | readers_never_recover_delete_or_create_files |
| S02; CLI status và trace khi thiếu state hoặc writer đang giữ khóa | tests/storage_cli.rs::status_and_trace_do_not_mutate_storage |
| S03; corrupt main/temp không reset; lỗi mở release khóa | corrupt_state_is_not_replaced_with_empty_storage |
| S03; lỗi I/O không được biến thành missing hoặc promote temp | io_error_is_not_treated_as_missing_state |
| S04; lỗi ghi temp, retry cùng checkpoint/event phải tiếp tục báo lỗi | failed_commit_requires_reopen_before_retry |
| Recovery mới/cũ/incomplete/missing | recovers_newer_valid_temporary_state; valid_main_discards_incomplete_or_stale_temporary_state; temporary_only_state_is_recovered_by_writer_only |
| S08, S09 | commit_timestamp_increases_when_clock_goes_backwards; unsupported_schema_is_preserved |
| S11; state khác tên không chia sẻ temp | different_state_names_have_independent_temporary_files |
| S05; archive lock + release + dedupe dưới khóa | CategoryLogStore::archive_lock_prevents_interleaved_writes_and_releases |
| Dedupe cũ giữ nguyên | repeated_archived_snapshot_does_not_add_another_record; CategoryLogStore::appending_same_event_twice_writes_one_line |

Tests xác nhận behavior; chưa có fault injection mô phỏng mất điện vật lý để chứng minh fsync trên thiết bị lưu trữ. Fixture lỗi I/O dùng directory thay file, không thay ACL máy. Child process exit xác nhận OS release khóa mà không chạy destructor.

## Kiểm thử

Mọi build chạy tuần tự với `CARGO_BUILD_JOBS=1`, `CARGO_INCREMENTAL=0`, `CARGO_TARGET_DIR=D:\DACN\Agent\BuildCache\CrystaL-Codex`.

Baseline do operator cung cấp: check/test/fmt/clippy/release PASS, 3 tests. Đã chạy lại baseline test: exit 0, 3 passed, 0 failed. Lần đầu trong sandbox exit 1 vì không được tạo thư mục cache; chạy lại có quyền phù hợp, không đổi đường dẫn hoặc toolchain.

Lần kiểm tra R1 đầu: check 0; test 101 (13 passed, 1 failed do Windows Access denied lúc concurrent replace); fmt 0; clippy 0; release 0. Lỗi được xử lý bằng bounded retry và regression giữ nguyên. Lần tiếp theo cả 5 checks exit 0, 17 tests pass. Sau đó bổ sung regression cho xung đột tên temporary; kết quả bản cuối ghi bên dưới.

| Lệnh cuối, chạy theo thứ tự | Exit | Kết quả |
|---|---|---|
| `cargo check --locked --all-targets -j 1` | 0 | PASS |
| `cargo test --locked --all-targets -j 1` | 0 | PASS: 17 library + 1 integration = 18; 0 failed; binary 0 tests |
| `cargo fmt --all -- --check` | 0 | PASS |
| `cargo clippy --locked --all-targets -j 1` | 0 | PASS, không có Clippy warning |
| `cargo build --locked --release -j 1` | 0 | PASS |

Test count: trước 3, sau 18 (+15, gồm child-process helper; các child probe chạy thêm không cộng lại vào tổng). `git diff --check` PASS. Starship in cảnh báo TERM=dumb ở shell elevated, không ảnh hưởng exit của Cargo. Không chạy nhiều build đồng thời.

## File bàn giao

- `R0-R1-AUDIT.md`: audit, evidence, backlog, validation, giới hạn.
- `src/Store/JsonFileStore.rs`: writer ownership, recovery, read snapshot, commit failure handling và regression tests.
- `src/Store/CategoryLogStore.rs`: archive ownership, flush và regression test.
- `src/Store/StoreModule.rs`: export JsonSnapshot.
- `src/Repository/Repository.rs`: tách read/write traits.
- `src/Agent/AgentRuntime.rs`, `src/main.rs`: dùng snapshot ở status/trace.
- `src/Controller/Process/ProcessController.rs`, `src/Service/Process/ProcessTraceService.rs`: đổi bound sang read trait, không thay thuật toán.
- `tests/storage_cli.rs`: kiểm tra read-only CLI trên subprocess.

Tổng findings: 22 (P0: 0, P1: 8, P2: 12, P3: 2). S01–S11 đã xử lý trong R1; B01–B11 là backlog chưa sửa. Commit SHA đầy đủ được cung cấp trong thông báo bàn giao; không nhúng SHA của chính commit vào nội dung commit.

## Residual risks

- Khóa bảo vệ các writer tuân thủ protocol; binary cũ, tool bên ngoài, hardlink/file symlink alias hoặc quyền sửa/xóa sidecar vẫn có thể phá invariant. Không hỗ trợ nhiều agent-id dùng chung data_dir nhưng json_path khác. Không thay ACL trong R1; cần đánh giá deployment permissions riêng.
- Schema 1 vẫn cho phép fields thiếu theo format cũ; không có checksum chống tamper hoặc semantic validation toàn bộ document. Timestamp legacy bị chỉnh tay có thể ảnh hưởng lựa chọn recovery.
- Retry Windows có giới hạn; reader/antivirus giữ file lâu hơn khoảng 1 giây vẫn làm commit báo lỗi, cần restart writer để recovery. Không silent reset dữ liệu.
- JSON state và category logs không cùng một transaction; có thể có duplicate archive sau crash/replay không ở cuối file. Không hứa exactly-once liên kho hoặc bảo đảm ổ đĩa không nói sai về flush.
- Những backlog P1/P2 ngoài R1 còn nguyên, nhất là raw privacy, auth detection, collector deltas và RAM/disk growth. Không kiểm thử service trên SCM thật hoặc policy/permission của nguồn event.
- Không nâng/hạ Rust, sửa dependency/Cargo.lock, push, merge, sửa main/upstream hoặc thu thập dữ liệu production.
