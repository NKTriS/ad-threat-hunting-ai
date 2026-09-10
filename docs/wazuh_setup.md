# Checklist dựng AD Lab và Wazuh

Tài liệu này chuẩn bị cho giai đoạn 1 và 2. Chỉ thực hiện trong lab cô lập, thuộc
quyền quản lý của nhóm. Không expose Domain Controller, Wazuh hoặc Ollama ra
Internet.

## 1. Sơ đồ tối thiểu

| Máy | Vai trò | Telemetry |
| --- | --- | --- |
| `DC01` | AD DS, DNS | Security Event Log, Sysmon, Wazuh Agent |
| `TEST01` | Windows client join domain | Security Event Log, Sysmon, Wazuh Agent |
| `WAZUH01` | Manager, Indexer, Dashboard | Nhận và lưu alert từ hai agent |

Ghi lại IP, phiên bản hệ điều hành, snapshot và thời gian hệ thống trong tài liệu
lab riêng. Không commit password, token hoặc private IP thật nếu repository được
công khai.

## 2. Audit policy cần xác minh

Áp dụng bằng Group Policy phù hợp với lab rồi xác minh policy đã xuống máy:

- `Audit Logon` để thu Event ID `4624` và `4625`.
- `Audit Kerberos Service Ticket Operations` trên Domain Controller để thu
  Event ID `4769`.
- `Audit Process Creation` để thu Event ID `4688`.
- Bật `Include command line in process creation events` nếu dùng `4688` cho
  Domain Account Discovery.

Sysmon Event ID `1` là nguồn process creation bổ sung, không phải kết luận tấn
công. Microsoft mô tả Sysmon event là telemetry quan sát và cần correlation để
diễn giải.

## 3. Cấu hình Wazuh Agent

Wazuh Agent mặc định đã theo dõi các kênh `Security`, `System` và `Application`.
Không thêm lại block `Security` nếu cấu hình hiện tại đã có. Để thu Sysmon, chép
block trong `wazuh/agent/sysmon_eventchannel.xml.example` vào bên trong thẻ
`<ossec_config>` của:

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Sau khi kiểm tra XML, khởi động lại agent từ PowerShell chạy với quyền quản trị:

```powershell
Restart-Service -Name wazuh
```

## 4. Tiêu chí xác minh trước scenario

1. Dashboard hiển thị cả agent `DC01` và `TEST01` ở trạng thái active.
2. Event Security bình thường từ mỗi máy xuất hiện trong Wazuh.
3. Sysmon Event ID `1` xuất hiện với `Image`, `CommandLine`, `ParentImage` và
   `User` khi các trường đó được Sysmon ghi nhận.
4. Event ID `4625`, `4769` và `4688` test hợp lệ xuất hiện đúng host/channel.
5. Timestamp giữa ba máy không lệch đáng kể.
6. Một alert đã sanitize được lưu dạng JSONL để chạy parser của repository.

Không bắt đầu attack scenario nếu chưa xác minh telemetry. Trường nào khác với
sample phải được lưu làm fixture regression trước khi sửa mapping parser.

## 5. Đưa alert vào pipeline

Trên Wazuh Manager, alert JSON mặc định nằm tại:

```text
/var/ossec/logs/alerts/alerts.json
```

Chỉ trích đoạn thời gian của scenario, sanitize dữ liệu nhạy cảm và lưu mỗi alert
trên một dòng JSON. Chạy:

```powershell
python -m ai.cli correlate `
  --alerts <duong-dan-alerts-da-sanitize.jsonl> `
  --output data/incidents.json
```

Đối chiếu Incident với thời gian scenario và ground truth trước khi gọi RAG/LLM.

## Nguồn chính thức

- [Wazuh: Windows event channel collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html#windows-event-channel)
- [Wazuh: Windows agent installation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
- [Microsoft: Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Microsoft: Advanced security audit policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings)
