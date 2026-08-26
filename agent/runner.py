"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path

import hashlib
import json
import re
import time

from agent import ledger, policy, tools
from agent.policy import PolicyContext


REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
def _hash_args(args: dict) -> str:
    raw = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    run_id = f"run-{int(time.time()*1000)}"
    # -------------------------------------------------------------
    # RUN A: Search docs (Internal data, Egress = False)
    # -------------------------------------------------------------
    ctx_a = PolicyContext(
        data_classification="internal",
        request_purpose="search_docs",
        agent_owner="run_a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_a, reason_a = policy.check(ctx_a)
    ledger.append(
        {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "agent_id": "agent-run-a",
            "run_id": run_id,
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": ctx_a.data_classification,
            "decision": "allow" if allow_a else "deny",
            "reason": reason_a,
        },
        ledger_path,
    )
    if not allow_a:
        return "Tác vụ bị từ chối bởi chính sách an toàn."
    docs = tools.search_docs(message)
    # -------------------------------------------------------------
    # Parse trusted ticket IDs từ tên file (vd: ticket-007.md -> 7)
    # -------------------------------------------------------------
    trusted_ticket_ids: set[int] = set()
    for d in docs:
        filename = d.get("id", "")
        nums = re.findall(r"\d+", filename)
        if nums:
            trusted_ticket_ids.add(int(nums[0]))
    # -------------------------------------------------------------
    # RUN B: Map ticket_id -> customer_id qua customers.json (Trusted Metadata)
    # -------------------------------------------------------------
    customers_file = DATA_DIR / "customers.json"
    customers_data = json.loads(customers_file.read_text(encoding="utf-8")) if customers_file.exists() else []
    target_customer_ids: set[str] = set()
    for cust in customers_data:
        related = cust.get("related_tickets", [])
        if any(tid in related for tid in trusted_ticket_ids):
            target_customer_ids.add(cust["customer_id"])
    # Đọc dữ liệu private của khách hàng hợp lệ
    for cid in sorted(target_customer_ids):
        ctx_b = PolicyContext(
            data_classification="restricted",
            request_purpose="read_customer_details",
            agent_owner="run_b",
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_b, reason_b = policy.check(ctx_b)
        ledger.append(
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "agent_id": "agent-run-b",
                "run_id": run_id,
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": cid}),
                "classification": ctx_b.data_classification,
                "decision": "allow" if allow_b else "deny",
                "reason": reason_b,
            },
            ledger_path,
        )
        if allow_b:
            tools.read_customer(cid)
    # -------------------------------------------------------------
    # Check Injection & Block Exfiltration (http_post)
    # -------------------------------------------------------------
    for d in docs:
        text = d.get("text", "")
        injected = llm.find_injection(text)
        if injected:
            # Attacker cố gắng trigger egress POST dữ liệu nhạy cảm
            ctx_egress = PolicyContext(
                data_classification="restricted",
                request_purpose="exfiltrate_data",
                agent_owner="run_b",
                delegation_depth=1,
                egress_enabled=True, # Attacker kích hoạt egress network
            )
            allow_e, reason_e = policy.check(ctx_egress)
            ledger.append(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "agent_id": "agent-run-b",
                    "run_id": run_id,
                    "tool": "http_post",
                    "args_hash": _hash_args({"url": injected.target_url}),
                    "classification": ctx_egress.data_classification,
                    "decision": "allow" if allow_e else "deny",
                    "reason": reason_e,
                },
                ledger_path,
            )
            # Vì policy return DENY -> KHÔNG gọi tools.http_post
    return llm.summarize(docs)
