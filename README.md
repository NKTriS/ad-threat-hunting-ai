# AD Threat Hunting RAG

MVP phân tích sự cố Active Directory theo pipeline:

```text
Windows/Sysmon -> Wazuh -> Correlation -> Incident JSON
               -> Local RAG -> Ollama/Qwen -> Analysis JSON
```

Ba kỹ thuật core:

- Password Spraying (`T1110.003`).
- Kerberoasting (`T1558.003`).
- Domain Account Discovery (`T1087.002`).

## Yêu cầu

- Python 3.10 trở lên.
- Ollama chạy tại `http://127.0.0.1:11434`.
- Model sinh nội dung `qwen3:4b`.
- Model embedding `nomic-embed-text`.

Không cần Kaggle và không fine-tune model.

## Cài model

```powershell
ollama pull qwen3:4b
ollama pull nomic-embed-text
```

## Chạy bằng dữ liệu mẫu

### 1. Tạo Incident từ Wazuh alerts

```powershell
python -m ai.cli correlate `
  --alerts data/sample_alerts.jsonl `
  --output data/incidents.json
```

Kết quả mẫu phải có ba Incident tương ứng ba kỹ thuật core.

### 2. Tạo RAG index

```powershell
python -m ai.cli build-index
```

Index được ghi vào `data/rag_index/index.json`. Knowledge base gốc nằm tại
`data/knowledge/knowledge_base.json` và mỗi tài liệu đều có URL nguồn.

### 3. Phân tích bằng local LLM

```powershell
python -m ai.cli analyze
```

Báo cáo được ghi vào `data/reports.json` với evidence, classification, risk,
khuyến nghị tiếng Việt và nguồn RAG.

## Dùng alert thật từ Wazuh

Trên Wazuh Manager, alert mặc định nằm tại:

```text
/var/ossec/logs/alerts/alerts.json
```

Chép một đoạn alert của lab vào file JSONL rồi truyền đường dẫn đó cho lệnh
`correlate`. Không commit log thật, credential, token hoặc thông tin nhạy cảm.

## Chạy test

```powershell
python -m unittest discover -s tests -v
```

Test không gọi Ollama, nên có thể kiểm tra normalization, correlation, retrieval
và hợp đồng output trước khi cài model.

## Tài liệu

- [Kiến trúc RAG](docs/rag_architecture.md)
- [Đề xuất đồ án](Proposal%20Đồ%20án%20tốt%20nghiệp.md)
