"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """TODO: store input + start timestamp keyed by request_id/user_id."""
        key = request_id or user_id
        self._open[key] = time.time()
        self.logs.append(
            {
                "event": "input",
                "timestamp": utc_now_iso(),
                "request_id": request_id,
                "user_id": user_id,
                "text_preview": text[:500],
            }
        )

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """TODO: store output, layer decision, latency; append to self.logs."""
        key = request_id or user_id
        started = self._open.pop(key, None)
        latency_ms = None
        if started is not None:
            latency_ms = round((time.time() - started) * 1000, 2)

        self.logs.append(
            {
                "event": "output",
                "timestamp": utc_now_iso(),
                "request_id": request_id,
                "user_id": user_id,
                "blocked": blocked,
                "layer": layer,
                "latency_ms": latency_ms,
                "text_preview": text[:500],
            }
        )

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        # TODO: ensure parent dirs exist, dump self.logs with indent=2
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, indent=2), encoding="utf-8")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
