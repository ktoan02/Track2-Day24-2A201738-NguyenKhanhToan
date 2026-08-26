# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement                                         | Control                              | Evidence                                                            |
| --------------------------------------------------- | ------------------------------------ | ------------------------------------------------------------------- |
| Luật 91/2025 — quyền yêu cầu xoá              | Chưa implement (xem stretch#3)      | —                                                                  |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho LLM API call | `reports/dpia-lite.md` §3                                        |
| ASI03 — privilege abuse                            | Per-agent identity + Policy check    | `agent/policy.py` L31-L43, `agent/runner.py` L81-L87            |
| ASI01 — goal hijack                                | Trifecta split                       | `reports/attack-after.log` L23-L28, `agent/runner.py` L108-L148 |
| ISO 42001 Clause 5-6                                | Policy-as-code có review            | git log agent/policy.py                                             |
