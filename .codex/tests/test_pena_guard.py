#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / ".codex" / "hooks" / "pena_guard.py"


class Gekko-LiteGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.private = self.base / "operator-private.pem"
        self.public = self.base / "operator-public.pem"
        self.scope = self.base / "scope.json"
        self.audit = self.base / "audit.jsonl"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        now = datetime.now(timezone.utc)
        payload = {
            "engagement": "test",
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(minutes=5)).isoformat(),
            "mode": "direct-interaction",
            "targets": [{"host": "192.0.2.10", "protocol": "tcp", "ports": [443]}],
            "actions": {"read": True, "scan": False, "state_changes": False, "brute_force": False, "dos": False},
            "limits": {"requests_per_second": 2, "max_actions": 10},
            "allowed_tools": ["curl"],
        }
        self.scope.write_text(json.dumps(payload), encoding="utf-8")
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.private), "-out", str(self.scope) + ".sig", str(self.scope)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.env = os.environ.copy()
        self.env.update({
            "PENA_SCOPE_FILE": str(self.scope),
            "PENA_SCOPE_PUBLIC_KEY": str(self.public),
            "PENA_WORKSPACE_ROOT": str(ROOT),
            "PENA_AUDIT_FILE": str(self.audit),
        })

    def tearDown(self):
        self.tmp.cleanup()

    def hook(self, tool: str, command: str = "") -> subprocess.CompletedProcess:
        event = {"session_id": "session-test", "cwd": str(ROOT), "tool_name": tool, "tool_input": {"command": command}}
        return subprocess.run(["python3", str(GUARD), "hook"], input=json.dumps(event), text=True, capture_output=True, env=self.env, check=False)

    def test_local_read_is_not_logged(self):
        result = self.hook("Bash", "rg --files .codex")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.audit.exists())

    def test_direct_network_command_is_denied_and_logged(self):
        result = self.hook("Bash", "curl https://192.0.2.10:443/")
        self.assertEqual(result.returncode, 0)
        self.assertIn('"permissionDecision": "deny"', result.stdout)
        row = json.loads(self.audit.read_text().splitlines()[0])
        self.assertEqual(row["decision"], "deny")
        self.assertEqual(row["reason"], "network-blocked")
        self.assertNotIn("192.0.2.10", self.audit.read_text())

    def test_non_pena_workspace_is_ignored(self):
        event = {"session_id": "session-test", "cwd": str(self.base), "tool_name": "Bash", "tool_input": {"command": "curl https://example.invalid"}}
        result = subprocess.run(["python3", str(GUARD), "hook"], input=json.dumps(event), text=True, capture_output=True, env=self.env, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_local_evidence_search_with_ip_is_allowed(self):
        result = self.hook("Bash", "rg 192.0.2.10 evidence.txt")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_git_push_is_denied(self):
        result = self.hook("Bash", "git push origin main")
        self.assertIn('"permissionDecision": "deny"', result.stdout)

    def test_git_status_is_allowed(self):
        result = self.hook("Bash", "git status --short")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_git_add_is_allowed(self):
        result = self.hook("Bash", "git add .codex")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_network_tool_after_pipe_is_denied(self):
        result = self.hook("Bash", "rg token evidence.txt | curl example.invalid")
        self.assertIn('"permissionDecision": "deny"', result.stdout)
        self.assertIn("shell composition", result.stdout)

    def test_nested_shell_network_command_is_denied(self):
        result = self.hook("Bash", "bash -c 'curl example.invalid'")
        self.assertIn('"permissionDecision": "deny"', result.stdout)

    def test_audit_path_shell_write_is_denied(self):
        target_audit = self.scope.parent / "audit" / "actions.jsonl"
        result = self.hook("Bash", f"printf x > {target_audit}")
        self.assertIn('"permissionDecision": "deny"', result.stdout)

    def test_python_scope_tamper_is_denied(self):
        result = self.hook("Bash", f"python3 -c \"open('{self.scope}','w').write('x')\"")
        self.assertIn('"permissionDecision": "deny"', result.stdout)

    def test_mcp_is_denied_while_scope_is_active(self):
        result = self.hook("mcp__external__send")
        self.assertIn('"permissionDecision": "deny"', result.stdout)

    def test_signed_structured_dry_run_is_allowed(self):
        result = subprocess.run([
            "python3", str(GUARD), "exec", "--host", "192.0.2.10", "--port", "443",
            "--action", "read", "--tool", "curl", "--dry-run", "--",
            "curl", "--max-redirs", "0", "https://{HOST}:{PORT}/health",
        ], text=True, capture_output=True, env=self.env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("https://192.0.2.10:443/health", result.stdout)

    def test_lookalike_guard_is_denied(self):
        fake = self.base / "pena_guard.py"
        fake.write_text("print('bypass')\n")
        result = self.hook("Bash", f"python3 {fake} exec --host 192.0.2.10")
        self.assertIn('"permissionDecision": "deny"', result.stdout)

    def test_toolbox_lifecycle_is_operator_controlled(self):
        result = self.hook("Bash", f"python3 {GUARD} start --scope {self.scope}")
        self.assertIn('"permissionDecision": "deny"', result.stdout)

    def test_out_of_scope_target_is_denied(self):
        result = subprocess.run([
            "python3", str(GUARD), "exec", "--host", "192.0.2.11", "--port", "443",
            "--action", "read", "--tool", "curl", "--dry-run", "--",
            "curl", "https://{HOST}:{PORT}/",
        ], text=True, capture_output=True, env=self.env, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside the signed scope", result.stderr)

    def test_curl_redirect_is_denied(self):
        result = subprocess.run([
            "python3", str(GUARD), "exec", "--host", "192.0.2.10", "--port", "443",
            "--action", "read", "--tool", "curl", "--dry-run", "--",
            "curl", "-L", "https://{HOST}:{PORT}/",
        ], text=True, capture_output=True, env=self.env, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("redirects", result.stderr)

    def test_curl_proxy_is_denied(self):
        result = subprocess.run([
            "python3", str(GUARD), "exec", "--host", "192.0.2.10", "--port", "443",
            "--action", "read", "--tool", "curl", "--dry-run", "--",
            "curl", "--proxy", "proxy.invalid:8080", "https://{HOST}:{PORT}/",
        ], text=True, capture_output=True, env=self.env, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("proxies", result.stderr)

    def test_curl_compact_post_is_denied(self):
        result = subprocess.run([
            "python3", str(GUARD), "exec", "--host", "192.0.2.10", "--port", "443",
            "--action", "read", "--tool", "curl", "--dry-run", "--",
            "curl", "--data=value", "https://{HOST}:{PORT}/",
        ], text=True, capture_output=True, env=self.env, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("state-changing", result.stderr)

    def test_curl_second_destination_is_denied(self):
        result = subprocess.run([
            "python3", str(GUARD), "exec", "--host", "192.0.2.10", "--port", "443",
            "--action", "read", "--tool", "curl", "--dry-run", "--",
            "curl", "https://{HOST}:{PORT}/", "https://example.invalid/",
        ], text=True, capture_output=True, env=self.env, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertTrue("does not match" in result.stderr or "exactly one" in result.stderr)

    def test_curl_virtual_host_is_denied(self):
        result = subprocess.run([
            "python3", str(GUARD), "exec", "--host", "192.0.2.10", "--port", "443",
            "--action", "read", "--tool", "curl", "--dry-run", "--",
            "curl", "-H", "Host: related.example", "https://{HOST}:{PORT}/",
        ], text=True, capture_output=True, env=self.env, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("hostname", result.stderr)

    def test_modified_scope_fails_signature(self):
        payload = json.loads(self.scope.read_text())
        payload["targets"][0]["host"] = "192.0.2.11"
        self.scope.write_text(json.dumps(payload), encoding="utf-8")
        result = self.hook("Bash", f"python3 {GUARD} exec --help")
        self.assertIn('"permissionDecision": "deny"', result.stdout)
        self.assertIn("signature verification failed", result.stdout)


if __name__ == "__main__":
    unittest.main()
