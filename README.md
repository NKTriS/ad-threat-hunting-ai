# AD Threat Hunting AI

Đồ án xây dựng hệ thống phân tích và phát hiện các kỹ thuật tấn công Windows Active Directory dựa trên Threat Hunting và AI.

## Mục tiêu

- Xây dựng Active Directory lab phục vụ mô phỏng tấn công.
- Thu thập Windows Event Log và Sysmon bằng Wazuh.
- Xây dựng detection rules và threat hunting queries.
- Chuẩn hóa, correlation các sự kiện thành Incident JSON.
- Dùng LLM hỗ trợ phân tích kỹ thuật tấn công, mức độ rủi ro, bằng chứng và khuyến nghị.

## Phạm vi chính

- Password Spraying.
- Kerberoasting.
- Active Directory Discovery.
- AI-assisted Incident Analysis với structured JSON output.

## Luồng hệ thống

```text
AD Lab -> Windows Telemetry -> Wazuh -> Detection / Threat Hunting
       -> Normalization -> Correlation -> Incident JSON -> LLM Analysis
```

AI không thay thế detection. Hệ thống phát hiện và tổng hợp bằng chứng trước, sau đó mới gửi Incident JSON cho LLM phân tích.

## Tài liệu

- [Đề xuất đồ án](Proposal%20Đồ%20án%20tốt%20nghiệp.md)

## Trạng thái

Dự án đang ở giai đoạn thiết kế kiến trúc và chuẩn bị môi trường lab.
