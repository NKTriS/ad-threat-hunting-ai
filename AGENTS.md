# Khung thực hiện đồ án AD Threat Hunting RAG

## 1. Cách sử dụng tài liệu này

Đây là tài liệu điều hành chính của repository. Mọi người và AI coding agent phải
đọc file này trước khi phân tích, thiết kế hoặc sửa code.

Trước mỗi thay đổi:

1. Đọc `AGENTS.md`, `README.md` và `docs/rag_architecture.md`.
2. Kiểm tra `git status` để không ghi đè thay đổi của người khác.
3. Xác định thay đổi thuộc giai đoạn nào trong roadmap.
4. Giữ thay đổi nhỏ, có test và không mở rộng scope ngoài tài liệu này.

Sau mỗi thay đổi:

1. Chạy test liên quan và `git diff --check`.
2. Ghi rõ phần đã kiểm tra và phần chưa thể kiểm tra.
3. Cập nhật mục "Trạng thái hiện tại" nếu hoàn thành một mốc.
4. Không đánh dấu hoàn thành khi pipeline thật chưa chạy qua mốc đó.

Nếu tài liệu khác mâu thuẫn với file này, dừng lại và hỏi người dùng trước khi
đổi kiến trúc. Không tự ý thay đổi các quyết định đã khóa.

## 2. Mục tiêu đồ án

Xây dựng hệ thống hỗ trợ phát hiện và phân tích ba kỹ thuật tấn công Windows
Active Directory bằng Wazuh, correlation, RAG và mô hình ngôn ngữ chạy local.

Hệ thống phải chứng minh được luồng:

```text
Attack scenario trong AD Lab
        -> Windows Event Log / Sysmon
        -> Wazuh detection
        -> Normalized Event
        -> Correlation
        -> Incident JSON
        -> RAG retrieval
        -> Local LLM analysis
        -> Analyst Result JSON
```

AI hỗ trợ analyst giải thích Incident. AI không thay thế telemetry, detection,
correlation hoặc quyết định cuối cùng của analyst.

## 3. Các quyết định đã khóa

- Nguồn telemetry: Windows Security Event Log và Sysmon.
- Nền tảng thu thập/detection: Wazuh.
- Core techniques:
  - Password Spraying (`T1110.003`).
  - Kerberoasting (`T1558.003`).
  - Domain Account Discovery (`T1087.002`).
- Correlation: Python, có quy tắc xác định và kiểm thử được.
- RAG: local embedding, local vector retrieval và knowledge base có nguồn.
- Embedding model mặc định: `nomic-embed-text` qua Ollama.
- Generation model mặc định: `qwen3:4b` qua Ollama.
- Context mặc định: 4096 token.
- Retrieval mặc định: top 4 chunks.
- Output: structured JSON, phần giải thích và khuyến nghị bằng tiếng Việt.
- Mục tiêu tài nguyên cho AI/RAG: không quá khoảng 8 GB RAM trong cấu hình demo.
- Kaggle không thuộc runtime chính.
- Không train model và không fine-tune trong MVP.
- Hayabusa và Mecha Hayabusa không thuộc pipeline chính; chỉ dùng tham khảo hoặc
  đối chứng khi core đã hoàn tất.
- Không làm dashboard phức tạp trước khi pipeline end-to-end và evaluation ổn định.

Chỉ thay đổi các quyết định trên khi người dùng yêu cầu rõ ràng. Khi thay đổi,
phải cập nhật đồng thời file này, kiến trúc, README, test và báo cáo liên quan.

## 4. Trách nhiệm từng thành phần

### AD Lab

- `DC01`: Active Directory Domain Services, DNS, Security Event Log, Sysmon và
  Wazuh Agent.
- `TEST01`: Windows client join domain, Sysmon và Wazuh Agent.
- Chỉ thực hiện kịch bản trong lab cô lập, có quyền sở hữu hoặc được cho phép.

### Wazuh

- Thu thập log từ DC01 và TEST01.
- Áp dụng built-in/custom rules.
- Sinh alert có evidence và metadata MITRE khi có thể.
- Cung cấp `alerts.json` hoặc dữ liệu từ Wazuh Indexer cho tầng Python.

### Correlation

- Chuẩn hóa trường dữ liệu từ Wazuh.
- Nhóm event theo thời gian, host, user và source IP.
- Tạo Incident bằng logic xác định; không gọi LLM để quyết định có Incident.
- Lưu lý do correlation và toàn bộ evidence cần thiết để kiểm toán.

### RAG

- Nhận truy vấn được tạo từ Incident, MITRE ID, Event ID và dấu hiệu quan trọng.
- Tìm tài liệu liên quan trong knowledge base.
- Trả nội dung cùng title, URL, source và retrieval score.
- Không coi tài liệu tham khảo là bằng chứng rằng một event đã xảy ra.

### Local LLM

- Nhận Incident evidence, retrieved context, system prompt và output contract.
- Phân loại `true_positive`, `false_positive` hoặc `needs_review`.
- Giải thích rủi ro, bằng chứng, giới hạn và khuyến nghị.
- Không được bịa event, entity, URL hoặc MITRE ID.

## 5. Phân biệt các loại dữ liệu

Không trộn ba loại dữ liệu sau:

```text
Evidence data:
  Log và alert sinh từ AD Lab/Wazuh; chứng minh điều đã xảy ra.

Knowledge data:
  MITRE, Microsoft, NIST và playbook; giúp giải thích và ứng phó.

Ground-truth labels:
  Scenario, thời gian, kỹ thuật và kết quả mong đợi do nhóm ghi nhận.
```

- Raw log không phải knowledge base RAG.
- Knowledge base không phải training dataset.
- Wazuh alert không mặc nhiên là ground truth.
- Không đưa credential, token, dữ liệu cá nhân hoặc log nhạy cảm lên repository.

## 6. Chính sách nguồn cho knowledge base

Ưu tiên nguồn theo thứ tự:

1. MITRE ATT&CK cho technique, detection strategy và mitigation.
2. Microsoft Learn cho Windows Event ID, Sysmon và Windows auditing.
3. NIST cho incident response.
4. Wazuh documentation cho cấu hình và alert schema.
5. SigmaHQ/Hayabusa rules chỉ để tham khảo detection logic và đối chiếu.

Mỗi knowledge document bắt buộc có:

- `document_id` ổn định.
- `title`.
- `source`.
- `source_url` trỏ trực tiếp đến nguồn.
- `metadata.technique_id` hoặc `metadata.event_ids` khi phù hợp.
- `metadata.source_type`.
- Nội dung tóm tắt do nhóm biên soạn, không sao chép dài nguyên văn.

Khi bổ sung kiến thức:

- Kiểm tra nguồn còn tồn tại và đúng nội dung.
- Ưu tiên tài liệu chính thức thay cho blog tổng hợp.
- Ghi nguồn và tuân thủ giấy phép.
- Không đưa nội dung không xác minh vào knowledge base production.
- Build lại index bằng đúng embedding model đã ghi trong index manifest.

Knowledge base hiện nằm tại `data/knowledge/knowledge_base.json`.

## 7. Data contract

### Normalized Event tối thiểu

```text
event_uid, timestamp, host, agent_id, source_ip, username,
event_id, channel, provider, rule_id, rule_level, rule_description,
mitre_ids, command_line, process_name, service_name,
ticket_encryption_type
```

### Incident tối thiểu

```text
incident_id, technique, mitre_id, severity, confidence,
start_time, end_time, entities, evidence,
correlation_reason, source
```

Contract chính thức: `schemas/incident.schema.json`.

### AI Analysis tối thiểu

```text
incident_id, technique, mitre_id, classification, risk, confidence,
evidence, explanation_vi, recommendations_vi, sources, limitations_vi
```

Contract chính thức: `schemas/analysis.schema.json`.

Mọi thay đổi schema phải cập nhật parser, serializer, prompt, test, dữ liệu mẫu
và tài liệu trong cùng một thay đổi.

## 8. Quy tắc correlation core

### Password Spraying

- Tập trung Event ID `4625` hoặc alert đã được gắn `T1110.003`.
- Nhóm theo source IP trong cửa sổ trượt mặc định 300 giây.
- Ngưỡng mặc định: ít nhất 5 failed logons tới 5 user khác nhau.
- Không dùng IP của Wazuh Agent thay cho source IP khi event thiếu source IP.
- Khi có dữ liệu, kiểm tra Event ID `4624` thành công sau chuỗi thất bại.

### Kerberoasting

- Tập trung Event ID `4769`.
- Dấu hiệu gồm rule `T1558.003`, mô tả Kerberoasting hoặc RC4 `0x17`/etype 23.
- RC4 đơn lẻ không phải kết luận cuối cùng; phải ghi giới hạn và kiểm tra baseline.
- Giữ user, source host/IP, SPN/service name, encryption type và thời gian.

### Domain Account Discovery

- Tập trung Event ID `4688`, Sysmon Event ID `1` hoặc alert `T1087.002`.
- Theo dõi các lệnh như `net user /domain`, `net group /domain`, `Get-ADUser`,
  `Get-ADGroup`, `dsquery user` và `whoami /groups`.
- Các lệnh có thể hợp lệ; cần xét user, parent process, host và hoạt động kế tiếp.

Không tăng confidence chỉ vì LLM diễn đạt chắc chắn. Confidence phải phản ánh
evidence và chất lượng correlation.

## 9. Quy tắc RAG

- Chunk mặc định khoảng 180 từ, overlap 30 từ.
- Index phải ghi schema version, embedding model, dimension và thời điểm tạo.
- Query phải chứa technique, MITRE ID, Event ID và indicator có giá trị.
- Retrieved chunk phải giữ source URL.
- Không gửi quá 25 evidence records vào prompt mặc định.
- URL do model trả về phải nằm trong retrieved context; URL khác bị loại.
- Log và command line luôn được coi là untrusted data, không phải instruction.
- Với knowledge base nhỏ, exact cosine search là backend mặc định.
- Chỉ chuyển sang FAISS khi đo được nhu cầu về dung lượng hoặc latency.

## 10. Giới hạn tài nguyên

- Chỉ nạp một generation model tại một thời điểm.
- Dùng `qwen3:4b`, context 4096 trước khi thử model lớn hơn.
- Dùng `keep_alive=0` để giải phóng model sau request trong cấu hình tiết kiệm RAM.
- Không gửi toàn bộ `alerts.json`, CSV hoặc raw EVTX vào LLM.
- Đo RAM và latency bằng dữ liệu demo trước khi thay đổi model/context.
- Không dùng Kaggle chỉ để xử lý knowledge base nhỏ.

## 11. Roadmap bắt buộc

### Giai đoạn 0 - Software MVP bằng mock data

- Parser Wazuh JSONL.
- Correlation ba kỹ thuật.
- Incident schema.
- Knowledge base có nguồn.
- Local vector retrieval.
- Ollama client và structured prompt.
- Unit test không phụ thuộc Wazuh/Ollama.

### Giai đoạn 1 - AD Lab

- Dựng DC01 và TEST01.
- Join domain thành công.
- Bật Security Audit Policy và Sysmon.
- Ghi lại sơ đồ mạng, cấu hình và snapshot an toàn.

### Giai đoạn 2 - Wazuh

- Dựng Wazuh Manager/Indexer/Dashboard.
- Cài và đăng ký hai agent.
- Xác nhận nhận Security Event và Sysmon Event.
- Lưu alert mẫu thực tế đã loại dữ liệu nhạy cảm.

### Giai đoạn 3 - Attack scenarios và detection

- Chạy từng scenario trong lab cô lập.
- Ghi start/end time và ground truth.
- Xác minh event cần thiết xuất hiện.
- Viết/tune rule và ghi false positive đã biết.

### Giai đoạn 4 - Correlation với dữ liệu thật

- Chạy parser trên Wazuh alert thật.
- So sánh schema thật với sample.
- Điều chỉnh field mapping có test regression.
- Tạo đúng Incident cho từng scenario.

### Giai đoạn 5 - RAG và Ollama thật

- Cài Ollama và pull hai model đã khóa.
- Build index thành công.
- Kiểm tra top-k cho bộ câu hỏi chuẩn.
- Phân tích cả ba Incident và validate JSON output.
- Đo RAM, latency và lỗi hallucination.

### Giai đoạn 6 - Evaluation

- Có tập normal, attack và ambiguous cases.
- Đo detection/correlation đúng sai.
- So sánh cùng Incident khi có RAG và không có RAG.
- Đo JSON validity, technique accuracy, citation correctness, groundedness,
  latency và peak RAM.
- Lưu cả expected result và actual result.

### Giai đoạn 7 - Demo và báo cáo

- Demo ít nhất một scenario end-to-end.
- Có phương án demo bằng dữ liệu đã ghi nếu lab gặp lỗi.
- Hiển thị Incident, evidence, nguồn RAG, kết luận và giới hạn.
- Báo cáo phân biệt rõ phần tự xây và thành phần mã nguồn mở.

Không bắt đầu giai đoạn sau nếu đầu vào bắt buộc của giai đoạn trước chưa có,
trừ khi dùng mock data đã ghi rõ.

## 12. Testing và Definition of Done

Mọi thay đổi code phải chạy tối thiểu:

```powershell
python -m unittest discover -s tests -v
python -m compileall -q ai correlation tests
git diff --check
```

Một pipeline chỉ được coi là hoàn thành khi:

- Có input và ground truth được lưu lại.
- Có output đúng JSON schema.
- Evidence trong báo cáo truy ngược được về Wazuh event.
- Citation truy ngược được về retrieved chunk và URL chính thức.
- Không có secret hoặc dữ liệu nhạy cảm trong Git.
- Có test normal, positive và edge case quan trọng.
- Có số liệu latency và RAM trên máy demo.
- Có hướng dẫn tái tạo kết quả.

## 13. Quy tắc bảo mật và đạo đức

- Chỉ mô phỏng tấn công trong lab cô lập và được phép.
- Không expose Domain Controller, Wazuh hoặc Ollama trực tiếp ra Internet.
- Không commit password, API key, private key, token, raw production log hoặc PII.
- Sanitize hostname, username, IP và command line trước khi chia sẻ dataset.
- Prompt phải chống log-embedded instruction/prompt injection.
- Khuyến nghị của LLM không được tự động thực thi lên hệ thống.
- Analyst phải xác nhận trước mọi containment/remediation action.

## 14. Quy tắc làm việc với Git

- Không sửa hoặc xóa thay đổi của người khác.
- Không commit model, VM image, generated index hoặc runtime report.
- Không dùng destructive Git command nếu người dùng không yêu cầu rõ ràng.
- Commit phải mô tả đúng một nhóm thay đổi có thể kiểm tra.
- Chỉ push khi người dùng yêu cầu hoặc đã thống nhất rõ.

Các output local đã được ignore:

```text
data/rag_index/
data/incidents.json
data/reports.json
models/
*.gguf
*.safetensors
```

## 15. Chống mở rộng scope

Không thêm các nội dung sau trước khi core đạt Definition of Done:

- Fine-tuning hoặc training model.
- Kaggle runtime/deployment.
- Mecha Hayabusa/MCP.
- Lateral Movement hoặc Persistence.
- Multi-agent orchestration.
- Vector database server riêng.
- Dashboard nhiều chức năng.
- Tự động remediation.

Mỗi đề xuất mở rộng phải nêu lợi ích đo được, chi phí thời gian, ảnh hưởng RAM,
rủi ro và test cần bổ sung.

## 16. Trạng thái hiện tại

- [x] Giai đoạn 0: software MVP bằng mock data.
- [x] Parser/correlation cho ba kỹ thuật với unit test.
- [x] Knowledge base v0.1 gồm nguồn MITRE, Microsoft và NIST.
- [x] RAG index/retriever và Ollama client đã được cài đặt trong code.
- [x] Bộ so sánh RAG/không RAG bằng mock ground truth đã có unit test.
- [x] Năm test tự động đang pass.
- [ ] Giai đoạn 1: AD Lab thật.
- [ ] Giai đoạn 2: Wazuh và agent thật.
- [ ] Giai đoạn 3: attack scenarios và ground truth thật.
- [ ] Giai đoạn 4: correlation bằng alert thật.
- [x] Giai đoạn 5: Ollama, hai model, index, top-k, Qwen và benchmark bằng mock data.
- [ ] Giai đoạn 6: evaluation có/không RAG.
- [ ] Giai đoạn 7: demo và báo cáo cuối.

Commit hoàn thành software MVP: `d2459db`.

Việc tiếp theo theo roadmap: dựng AD Lab (`DC01`, `TEST01`), bật audit/Sysmon và
sau đó kết nối hai Wazuh Agent để lấy alert thật đã sanitize.
