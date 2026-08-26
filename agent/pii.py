"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Regex patterns
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
BANK_RE = re.compile(r"(?i)(?:STK|số tài khoản|so tai khoan)\s*(\d{8,16})\b")
PHONE_RE = re.compile(r"\b0\d{9}\b")
CCCD_RE = re.compile(r"\b\d{12}\b")

def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    occupied: list[tuple[int, int]] = []
    def _add_entity(ent_type: str, start: int, end: int):
        # Tránh trùng lặp vị trí (overlap)
        for s, e in occupied:
            if max(start, s) < min(end, e):
                return
        entities.append({"type": ent_type, "start": start, "end": end})
        occupied.append((start, end))
    # 1. Detect EMAIL
    for m in EMAIL_RE.finditer(text):
        _add_entity("EMAIL", m.start(), m.end())
    # 2. Detect VN_BANK_ACCOUNT (sau STK)
    for m in BANK_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        _add_entity("VN_BANK_ACCOUNT", start, end)
    # 3. Detect VN_PHONE
    for m in PHONE_RE.finditer(text):
        _add_entity("VN_PHONE", m.start(), m.end())
    # 4. Detect VN_CCCD (12 chữ số)
    for m in CCCD_RE.finditer(text):
        _add_entity("VN_CCCD", m.start(), m.end())
    # Sắp xếp theo start position
    entities.sort(key=lambda x: x["start"])
    return entities
def redact(text: str) -> str:
    entities = detect(text)
    # Thay thế từ cuối về đầu để không làm lệch offset ký tự
    result = list(text)
    for ent in sorted(entities, key=lambda x: x["start"], reverse=True):
        start, end = ent["start"], ent["end"]
        replacement = f"[REDACTED_{ent['type']}]"
        result[start:end] = list(replacement)
    return "".join(result)
