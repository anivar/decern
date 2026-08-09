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


_MAX_ERROR_BODY_LEN = 512

# Caps how much of a non-2xx response body the client buffers. base_url can
# point at an intermediary (see deployment guidance), so an error body's
# size isn't bounded by decern-serve's own behavior.
_MAX_ERROR_BODY_BYTES = 64 * 1024  # 64 KiB


class DecernError(Exception):
    """Transport failure or non-2xx response from the PDP."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        body: str = "",
        truncated: bool = False,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        self.truncated = truncated


@dataclass
class Decision:
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    context: Optional[Dict[str, Any]] = None


class Client:
    """Client for a decern PDP speaking AuthZEN 1.0 Access Evaluation."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        timeout: float = 5.0,
        *,
        token: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token = token

    # --- HTTP ---------------------------------------------------------------

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        if self.token is not None:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode()
        except urllib.error.HTTPError as e:
            raise self._build_http_error(method, path, e) from e
        except urllib.error.URLError as e:
            raise DecernError(f"{method} {path} failed: {e.reason}") from e

    @staticmethod
    def _build_http_error(method: str, path: str, e: urllib.error.HTTPError) -> DecernError:
        truncated = False
        try:
            # Read one byte past the cap so truncation can be detected
            # without buffering more of an unbounded stream than needed.
            raw_bytes = e.read(_MAX_ERROR_BODY_BYTES + 1)
            if len(raw_bytes) > _MAX_ERROR_BODY_BYTES:
                raw_bytes = raw_bytes[:_MAX_ERROR_BODY_BYTES]
                truncated = True
            raw_body = raw_bytes.decode("utf-8", errors="replace")
        except (OSError, ValueError):
            raw_body = ""

        body_str = raw_body.strip()
        if len(body_str) > _MAX_ERROR_BODY_LEN:
            trunc = body_str[:_MAX_ERROR_BODY_LEN]
            truncated = True
        else:
            trunc = body_str
        if truncated and trunc:
            trunc += "..."

        msg = f"{method} {path} -> {e.code} {e.reason}"
        if trunc:
            msg += f": {trunc}"

        return DecernError(msg, status_code=e.code, body=raw_body, truncated=truncated)

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
