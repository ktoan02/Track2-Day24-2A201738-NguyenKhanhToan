# DPIA-lite (1 trang)

## 1. Dữ liệu gì
- **Thông tin PII nhạy cảm**: Số CCCD (12 chữ số), Số điện thoại, Số tài khoản ngân hàng, Email, Họ tên từ data store (`data/customers.json`) thông qua tool `read_customer`.
- **Dữ liệu hỗ trợ khách hàng**: Nội dung ticket hỗ trợ từ corpus (`corpus/*.md`) thông qua tool `search_docs`.
## 2. Mục đích gì
- Tổng hợp, phân loại và hỗ trợ giải đáp các ticket khiếu nại/đối soát của khách hàng dựa trên truy vấn người dùng.
## 3. Chảy đi đâu
- **Nội bộ hệ thống**: Dữ liệu di chuyển giữa Run A (`search_docs`) và Run B (`read_customer`), được ghi vết audit append-only vào `reports/ledger.jsonl`.
- **Egress Network**: Tool `http_post` (trỏ tới `localhost:9999`) đã bị chặn hoàn toàn bởi `agent/policy.py` đối với dữ liệu nhạy cảm (`classification="restricted"`).
- **Model Provider**: Khi chạy ở chế độ `--mock`, toàn bộ dữ liệu ở lại local. Khi chạy `--model claude-...`, prompt text được truyền sang API của Anthropic (chuyển dữ liệu xuyên biên giới theo NĐ 356/2025).

<!-- Toàn bộ nơi dữ liệu này có thể đi tới: log nội bộ, sink (trong lab),
và — nếu dùng --model claude-... — cả API của model provider. Đây là
chuyển dữ liệu xuyên biên giới theo NĐ 356/2025 nếu provider ở nước
ngoài; ghi rõ có hay không, và agent có egress control nào chặn việc này
khi không cần thiết. -->
