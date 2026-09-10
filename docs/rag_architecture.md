# Kiến trúc Wazuh + Local RAG

## Pipeline chính

```text
Windows Event Log / Sysmon
        -> Wazuh Agent
        -> Wazuh Manager rules
        -> alerts.json
        -> Normalization
        -> Correlation
        -> Incident JSON
        -> Vector retrieval
        -> Incident + reference context
        -> Ollama / Qwen3 4B
        -> Analysis JSON
```

Detection và correlation tạo giả thuyết Incident trước khi gọi LLM. LLM không
được dùng để quyết định trực tiếp trên toàn bộ raw log.

## RAG

Knowledge base v0.1 gồm các bản tóm tắt có nguồn từ MITRE ATT&CK, Microsoft
Learn và NIST. Mỗi đoạn giữ URL nguồn trong metadata. Ollama dùng
`nomic-embed-text` để tạo embedding; retriever dùng cosine similarity và lấy bốn
đoạn gần nhất. Với bộ tài liệu nhỏ, exact search dễ kiểm thử và tiêu thụ ít RAM.
Request sinh báo cáo đặt `think=false` và `keep_alive=0` để Qwen chỉ trả output
JSON cần thiết rồi giải phóng model khỏi bộ nhớ sau mỗi lần gọi. Output được giới
hạn 768 token; timeout mặc định là 600 giây để hỗ trợ cấu hình chỉ offload được
một phần model lên GPU. `schemas/analysis.schema.json` được truyền trực tiếp vào
Ollama structured output, không chỉ mô tả bằng prompt.

## Kiểm soát hallucination

- Log và command line được coi là dữ liệu không tin cậy, không phải chỉ thị.
- Prompt giới hạn model vào Incident và tài liệu đã truy xuất.
- URL do model trả về bị lọc theo danh sách URL thực sự có trong context.
- Kết quả có `classification`, `confidence` và `limitations_vi`.
- Prompt cung cấp duration đã tính sẵn, cấm suy diễn mật khẩu, attack tooling và
  containment không qua analyst xác nhận.
- Prompt có `observed_summary` xác định để model không tuyên bố thiếu Event ID,
  provider, channel, encryption type hoặc command line thực tế đã có.
- Analyst vẫn phải xác nhận kết luận trước khi xử lý sự cố.

## Evaluation có/không RAG

Hai chế độ dùng cùng Incident, generation model, context size và output contract.
Điểm khác biệt duy nhất là chế độ RAG nhận bốn chunk được truy xuất, còn baseline
nhận danh sách tài liệu rỗng. `evaluation/ground_truth.sample.json` chỉ là nhãn
cho mock scenario; ground truth của lab thật phải được ghi riêng theo từng lần
thử nghiệm.

CLI tự động đo incident recall, schema validity, technique/MITRE/classification
accuracy, retrieval Recall@k/MRR và tính hợp lệ của citation. Evidence
groundedness có thêm bước cảnh báo Event ID/MITRE ID không có trong context. Đây
chỉ là bộ lọc sơ bộ; mức hữu ích của giải thích tiếng Việt, khuyến nghị và phát
biểu sai vẫn phải được analyst review.

## Mở rộng sau MVP

- Đọc alert theo thời gian thực từ Wazuh Indexer thay cho file JSONL.
- Chuyển exact vector search sang FAISS khi knowledge base tăng lớn.
- Bổ sung reranking và đánh giá retrieval Recall@k.
- Bổ sung bộ evaluation từ alert thật, gồm normal và ambiguous cases.
