"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
def _compute_hash(entry: dict) -> str:
    # Loại bỏ field 'hash' để tính hash cho nội dung còn lại
    data = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
def append(entry: dict, path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    
    prev_hash = "0" * 64
    if path.exists() and path.stat().st_size > 0:
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        if lines:
            last_entry = json.loads(lines[-1])
            prev_hash = last_entry.get("hash", "0" * 64)
    record = dict(entry)
    record["prev_hash"] = prev_hash
    record["hash"] = _compute_hash(record)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record
def verify(path: Path) -> bool:
    if not path.exists():
        return True
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        return True
    expected_prev_hash = "0" * 64
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except Exception:
            return False
        # 1. Kiểm tra reason non-empty
        reason = record.get("reason")
        if not reason or not str(reason).strip():
            return False
        # 2. Kiểm tra prev_hash
        if record.get("prev_hash") != expected_prev_hash:
            return False
        # 3. Kiểm tra hash integrity
        stored_hash = record.get("hash")
        computed_hash = _compute_hash(record)
        if stored_hash != computed_hash:
            return False
        expected_prev_hash = stored_hash
    return True
