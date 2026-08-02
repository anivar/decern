# SPDX-License-Identifier: Apache-2.0
"""AuthZEN 1.0 Access Evaluation client for the decern PDP."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

Entity = Dict[str, Any]  # {"type": ..., "id": ...}
Action = Union[str, Dict[str, Any]]


class DecernError(Exception):
    """Transport failure or non-2xx response from the PDP."""


@dataclass
class Decision:
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    context: Optional[Dict[str, Any]] = None


class Client:
    """Client for a decern PDP speaking AuthZEN 1.0 Access Evaluation."""

    def __init__(self, base_url: str = "http://127.0.0.1:8080", timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # --- HTTP ---------------------------------------------------------------

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        req = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode()
        except urllib.error.HTTPError as e:
            raise DecernError(f"{method} {path} -> {e.code} {e.reason}") from e
        except urllib.error.URLError as e:
            raise DecernError(f"{method} {path} failed: {e.reason}") from e
        return raw

    # --- API ----------------------------------------------------------------

    def evaluate(
        self,
        subject: Entity,
        action: Action,
        resource: Entity,
        context: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        act = {"name": action} if isinstance(action, str) else action
        body: Dict[str, Any] = {"subject": subject, "action": act, "resource": resource}
        if context is not None:
            body["context"] = context
        raw = self._request("POST", "/access/v1/evaluation", body)
        resp = json.loads(raw)
        ctx = resp.get("context") or None
        reasons = list(ctx.get("reasons", [])) if ctx else []
        errors = list(ctx.get("errors", [])) if ctx else []
        return Decision(
            allowed=bool(resp.get("decision", False)),
            reasons=reasons,
            errors=errors,
            context=ctx,
        )

    def pubkey(self) -> str:
        return json.loads(self._request("GET", "/pubkey"))["kid"]

    def healthy(self) -> bool:
        try:
            return self._request("GET", "/healthz").strip() == "ok"
        except DecernError:
            return False
