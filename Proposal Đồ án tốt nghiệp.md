# PROPOSAL ĐỒ ÁN TỐT NGHIỆP

## 1. Tên đề tài

**Xây dựng hệ thống phân tích và phát hiện các kỹ thuật tấn công Windows Active Directory dựa trên Threat Hunting và AI**

## 2. Định hướng đề tài

Đề tài tập trung xây dựng một hệ thống hỗ trợ phát hiện và phân tích các kỹ thuật tấn công trong môi trường Windows Active Directory. Hệ thống sử dụng dữ liệu Windows Event Log và Sysmon làm nguồn dữ liệu, kết hợp phương pháp Threat Hunting để chủ động tìm kiếm các dấu hiệu bất thường và sử dụng AI để hỗ trợ phân tích, tương quan và giải thích các hoạt động đáng ngờ.

Đề tài hướng tới mô phỏng quy trình phân tích của một SOC Analyst: từ thu thập dữ liệu, tìm kiếm dấu hiệu tấn công, xác định các sự kiện liên quan đến phân tích và đánh giá mức độ rủi ro.

## 3. Mục tiêu

Xây dựng một hệ thống có khả năng:

- Thu thập và phân tích dữ liệu hoạt động trên Windows Active Directory.
- Chủ động tìm kiếm các dấu hiệu của một số kỹ thuật tấn công bằng Threat Hunting.
- Tương quan các sự kiện liên quan để xác định hoạt động đáng ngờ.
- Sử dụng AI/LLM hỗ trợ phân tích, giải thích và xác định kỹ thuật tấn công.
- Hỗ trợ analyst trong quá trình điều tra và đánh giá sự cố.

## 4. Phạm vi thực hiện

Đề tài tập trung vào một số kỹ thuật tấn công Active Directory có thể quan sát thông qua Windows telemetry, dự kiến gồm:

- Password Spraying.
- Kerberoasting.
- Active Directory Discovery.
- Lateral Movement.
- Persistence.

Phạm vi được giới hạn ở một số kỹ thuật tiêu biểu nhằm đảm bảo khả năng hoàn thành trong thời gian thực hiện đồ án.

## 5. Kiến trúc dự kiến

```text
Windows Active Directory
          ↓
Windows Event Log + Sysmon
          ↓
       SIEM / Log
          ↓
    Threat Hunting
          ↓
  Suspicious Events
          ↓
AI Analysis & Correlation
          ↓
Technique / Risk / Explanation
          ↓
      Analyst
```

## 6. Các nội dung thực hiện

### 6.1. Nghiên cứu Active Directory và kỹ thuật tấn công

Tìm hiểu cơ chế hoạt động của Active Directory và lựa chọn các kỹ thuật tấn công phù hợp với phạm vi đề tài. Xác định dấu hiệu và telemetry có thể sử dụng để phát hiện từng kỹ thuật.

### 6.2. Xây dựng môi trường và thu thập dữ liệu

Triển khai môi trường Active Directory gồm Domain Controller và các máy Windows. Cấu hình Windows Event Log và Sysmon để thu thập thông tin về đăng nhập, tài khoản, tiến trình và hoạt động mạng.

### 6.3. Xây dựng cơ chế Threat Hunting

Xây dựng các giả thuyết và truy vấn Threat Hunting để chủ động tìm kiếm các dấu hiệu tấn công trong dữ liệu thu thập được.

### 6.4. Phân tích và tương quan sự kiện

Liên kết các sự kiện theo thời gian, tài khoản, máy tính và nguồn kết nối để xác định các hoạt động hoặc chuỗi hành vi đáng ngờ.

### 6.5. Tích hợp AI

Sử dụng AI/LLM để hỗ trợ phân tích các sự kiện đáng ngờ, xác định kỹ thuật tấn công có khả năng xảy ra, giải thích nguyên nhân và đưa ra mức độ rủi ro.

### 6.6. Kiểm thử và đánh giá

Thực hiện các kịch bản kiểm thử tương ứng với các kỹ thuật được lựa chọn, đối chiếu kết quả với MITRE ATT&CK và đánh giá khả năng phát hiện, tương quan và hỗ trợ phân tích của hệ thống.

## 7. Kết quả dự kiến

Sau khi hoàn thành, đề tài dự kiến tạo ra:

- Một môi trường Active Directory phục vụ thực nghiệm.
- Hệ thống thu thập và phân tích Windows telemetry.
- Bộ truy vấn Threat Hunting cho các kỹ thuật tấn công được lựa chọn.
- Thành phần AI hỗ trợ phân tích và tương quan sự kiện.
- Kết quả đánh giá khả năng phát hiện và hỗ trợ điều tra.

## 8. Kế hoạch thực hiện dự kiến

**Giai đoạn 1:** Nghiên cứu Active Directory, kỹ thuật tấn công và Windows telemetry.

**Giai đoạn 2:** Xây dựng môi trường, thu thập và chuẩn hóa dữ liệu.

**Giai đoạn 3:** Xây dựng Threat Hunting và cơ chế phát hiện.

**Giai đoạn 4:** Tích hợp AI và chức năng tương quan/phân tích sự kiện.

**Giai đoạn 5:** Kiểm thử, đánh giá, hoàn thiện hệ thống và báo cáo.

## 9. Kết quả mong muốn

Đề tài hướng tới một hệ thống có khả năng hỗ trợ analyst **chủ động tìm kiếm, phát hiện và hiểu các hành vi tấn công trong Active Directory**, trong đó Threat Hunting là phương pháp chính để tìm kiếm dấu hiệu tấn công và AI đóng vai trò hỗ trợ phân tích, tương quan và giải thích kết quả.