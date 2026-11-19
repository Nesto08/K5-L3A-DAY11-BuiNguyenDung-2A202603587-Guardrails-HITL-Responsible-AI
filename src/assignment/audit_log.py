"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time

def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}
        self._inputs: dict[str, dict] = {}

    
    def record_input(self, *, user_id: str, text: str, request_id: str | None = None, ):
        """Store input and start timestamp."""

        key = request_id or user_id

        self._open[key] = time.monotonic()

        self._inputs[key] = {
            "user_id": user_id,
            "request_id": request_id,
            "input": text,
            "timestamp": utc_now_iso(),
        }

    def record_output(self, *, user_id: str, text: str, blocked: bool = False, layer: str | None = None, request_id: str | None = None,):
        """Store output, decision, and latency."""

        key = request_id or user_id

        # Lấy dữ liệu request đã ghi trước đó
        input_data = self._inputs.pop(key, {})

        # Tính thời gian xử lý
        start_time = self._open.pop(key, None)

        latency_ms = None
        if start_time is not None:
            latency_ms = round(
                (time.monotonic() - start_time) * 1000, 2
            )

        # Tạo bản ghi audit
        log_entry = {
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "request_id": request_id,
            "input": input_data.get("input", ""),
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        }

        # Thêm vào danh sách nhật ký
        self.logs.append(log_entry)

    def export_json(self, filepath: str | None = None):
        """Export audit logs to JSON."""

        path = Path(filepath or default_audit_log_path())

        # Tạo thư mục nếu chưa tồn tại
        path.parent.mkdir(parents=True, exist_ok=True)

        # Ghi nhật ký vào JSON
        with path.open("w", encoding="utf-8") as f:
            json.dump(
                self.logs,
                f,
                ensure_ascii=False,
                indent=2,
            )

        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
