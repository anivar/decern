# SPDX-License-Identifier: Apache-2.0
"""Tests for the decern client. No network/server required."""

import json
import unittest
from unittest import mock

from decern import Client, Decision, DecernError


class FakeTransport:
    """Records requests and returns a queued raw response string."""

    def __init__(self, raw="{}"):
        self.raw = raw
        self.calls = []

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        return self.raw


def client_with(raw="{}"):
    c = Client()
    t = FakeTransport(raw)
    c._request = t  # inject fake transport
    return c, t


class TestEvaluateBody(unittest.TestCase):
    def test_builds_exact_authzen_body(self):
        c, t = client_with('{"decision": true}')
        c.evaluate(
            {"type": "Principal", "id": "corp"},
            "Read",
            {"type": "Resource", "id": "claim1"},
            {"now": 100},
        )
        method, path, body = t.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/access/v1/evaluation")
        self.assertEqual(
            body,
            {
                "subject": {"type": "Principal", "id": "corp"},
                "action": {"name": "Read"},
                "resource": {"type": "Resource", "id": "claim1"},
                "context": {"now": 100},
            },
        )

    def test_action_dict_passthrough_and_context_omitted(self):
        c, t = client_with('{"decision": false}')
        c.evaluate(
            {"type": "Principal", "id": "corp"},
            {"name": "Write", "extra": 1},
            {"type": "Resource", "id": "r"},
        )
        _, _, body = t.calls[0]
        self.assertEqual(body["action"], {"name": "Write", "extra": 1})
        self.assertNotIn("context", body)


class TestResponseParsing(unittest.TestCase):
    def test_allow_with_reasons(self):
        c, _ = client_with(json.dumps({"decision": True, "context": {"reasons": ["policy0"]}}))
        d = c.evaluate({"id": "a"}, "Read", {"id": "b"})
        self.assertIsInstance(d, Decision)
        self.assertTrue(d.allowed)
        self.assertEqual(d.reasons, ["policy0"])
        self.assertEqual(d.errors, [])

    def test_deny_with_errors(self):
        c, _ = client_with(json.dumps({"decision": False, "context": {"errors": ["no_policy"]}}))
        d = c.evaluate({"id": "a"}, "Read", {"id": "b"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.errors, ["no_policy"])
        self.assertEqual(d.reasons, [])

    def test_bare_decision(self):
        c, _ = client_with('{"decision": true}')
        d = c.evaluate({"id": "a"}, "Read", {"id": "b"})
        self.assertTrue(d.allowed)
        self.assertIsNone(d.context)


class TestPubkeyHealth(unittest.TestCase):
    def test_pubkey(self):
        c, _ = client_with('{"kid": "deadbeef"}')
        self.assertEqual(c.pubkey(), "deadbeef")

    def test_healthy_ok(self):
        c, _ = client_with("ok")
        self.assertTrue(c.healthy())

    def test_healthy_bad_body(self):
        c, _ = client_with("nope")
        self.assertFalse(c.healthy())

    def test_healthy_transport_error(self):
        c = Client()
        c._request = mock.Mock(side_effect=DecernError("boom"))
        self.assertFalse(c.healthy())


class TestHttpError(unittest.TestCase):
    def test_http_error_attaches_status_and_body(self):
        import io
        import urllib.error

        body = b'{"error": "denied"}'
        err = urllib.error.HTTPError(
            "http://127.0.0.1:8080/access/v1/evaluation",
            403,
            "Forbidden",
            {},
            io.BytesIO(body),
        )

        with mock.patch("urllib.request.urlopen", side_effect=err):
            c = Client()
            with self.assertRaises(DecernError) as cm:
                c.evaluate({"id": "a"}, "Read", {"id": "b"})

            e = cm.exception
            self.assertEqual(e.status_code, 403)
            self.assertEqual(e.body, '{"error": "denied"}')
            self.assertIn("403 Forbidden: ", str(e))
            self.assertIn('{"error": "denied"}', str(e))

    def test_http_error_empty_body(self):
        import io
        import urllib.error

        err = urllib.error.HTTPError(
            "http://127.0.0.1:8080/access/v1/evaluation",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(b""),
        )

        with mock.patch("urllib.request.urlopen", side_effect=err):
            c = Client()
            with self.assertRaises(DecernError) as cm:
                c.evaluate({"id": "a"}, "Read", {"id": "b"})

            e = cm.exception
            self.assertEqual(e.status_code, 503)
            self.assertEqual(e.body, "")
            self.assertEqual(str(e), "POST /access/v1/evaluation -> 503 Service Unavailable")

    def test_http_error_body_truncation(self):
        import io
        import urllib.error

        long_body = "x" * 600
        err = urllib.error.HTTPError(
            "http://127.0.0.1:8080/access/v1/evaluation",
            400,
            "Bad Request",
            {},
            io.BytesIO(long_body.encode("utf-8")),
        )

        with mock.patch("urllib.request.urlopen", side_effect=err):
            c = Client()
            with self.assertRaises(DecernError) as cm:
                c.evaluate({"id": "a"}, "Read", {"id": "b"})

            e = cm.exception
            self.assertEqual(e.status_code, 400)
            self.assertEqual(e.body, long_body)
            self.assertIn("...", str(e))
            self.assertTrue(str(e).endswith("..."))


if __name__ == "__main__":
    unittest.main()
