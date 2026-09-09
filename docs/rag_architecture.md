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

## Kiểm soát hallucination

- Log và command line được coi là dữ liệu không tin cậy, không phải chỉ thị.
- Prompt giới hạn model vào Incident và tài liệu đã truy xuất.
- URL do model trả về bị lọc theo danh sách URL thực sự có trong context.
- Kết quả có `classification`, `confidence` và `limitations_vi`.
- Analyst vẫn phải xác nhận kết luận trước khi xử lý sự cố.

## Mở rộng sau MVP

- Đọc alert theo thời gian thực từ Wazuh Indexer thay cho file JSONL.
- Chuyển exact vector search sang FAISS khi knowledge base tăng lớn.
- Bổ sung reranking và đánh giá retrieval Recall@k.
- So sánh báo cáo có RAG và không RAG trên cùng bộ Incident.
