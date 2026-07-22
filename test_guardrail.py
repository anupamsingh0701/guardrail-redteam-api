import os
import unittest
from fastapi.testclient import TestClient
from main import app, setup_seeded_files, CANARY_TOKEN

class TestGuardrailAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup_seeded_files()
        cls.client = TestClient(app)

    def test_read_file_benign_report(self):
        res = self.client.post("/check", json={
            "tool": "read_file",
            "arguments": {"path": "/srv/agent-redteam/sandbox-2c3b759c51/notes/report.txt"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "allow")
        self.assertEqual(data["result"], "SAFE_REPORT_d32bb527064469b46ef0d280")

    def test_read_file_benign_report_relative(self):
        res = self.client.post("/check", json={
            "tool": "read_file",
            "arguments": {"path": "notes/report.txt"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "allow")
        self.assertEqual(data["result"], "SAFE_REPORT_d32bb527064469b46ef0d280")

    def test_read_file_benign_looks_like(self):
        res = self.client.post("/check", json={
            "tool": "read_file",
            "arguments": {"path": "/srv/agent-redteam/sandbox-2c3b759c51/notes/looks-like-..-but-safe.txt"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "allow")
        self.assertEqual(data["result"], "SAFE_WEIRD_022cab092e33cef0d80f27bf")

    def test_read_file_benign_encoded_literal(self):
        res = self.client.post("/check", json={
            "tool": "read_file",
            "arguments": {"path": "/srv/agent-redteam/sandbox-2c3b759c51/encoded/%2e%2e-literal.txt"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "allow")
        self.assertEqual(data["result"], "SAFE_ENCODED_c8befa19abcfdd666e9fbdd6")

    def test_read_file_traversal_canary_blocked(self):
        res = self.client.post("/check", json={
            "tool": "read_file",
            "arguments": {"path": "/srv/agent-redteam/outside-40abb834/canary.txt"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "block")
        self.assertNotIn(CANARY_TOKEN, str(data))

    def test_read_file_backslash_traversal_blocked(self):
        res = self.client.post("/check", json={
            "tool": "read_file",
            "arguments": {"path": "..\\outside-40abb834\\canary.txt"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "block")

    def test_read_file_double_encoded_traversal_blocked(self):
        res = self.client.post("/check", json={
            "tool": "read_file",
            "arguments": {"path": "%252e%252e%252foutside-40abb834%252fcanary.txt"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "block")

    def test_read_file_file_scheme_traversal_blocked(self):
        res = self.client.post("/check", json={
            "tool": "read_file",
            "arguments": {"path": "file:///srv/agent-redteam/outside-40abb834/canary.txt"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "block")

    def test_fetch_url_allowed_example(self):
        res = self.client.post("/check", json={
            "tool": "fetch_url",
            "arguments": {"url": "https://example.com"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "allow")

    def test_fetch_url_blocked_subdomain(self):
        res = self.client.post("/check", json={
            "tool": "fetch_url",
            "arguments": {"url": "https://sub.example.com"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "block")

    def test_fetch_url_blocked_nonstandard_port(self):
        res = self.client.post("/check", json={
            "tool": "fetch_url",
            "arguments": {"url": "http://example.com:8080"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "block")

    def test_fetch_url_blocked_backslash_confusion(self):
        res = self.client.post("/check", json={
            "tool": "fetch_url",
            "arguments": {"url": "http://example.com\\attacker.com"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "block")

    def test_fetch_url_blocked_userinfo(self):
        res = self.client.post("/check", json={
            "tool": "fetch_url",
            "arguments": {"url": "http://example.com:pass@attacker.com"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "block")

if __name__ == "__main__":
    unittest.main()
