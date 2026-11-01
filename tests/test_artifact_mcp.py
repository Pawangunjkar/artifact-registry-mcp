"""
Comprehensive Unit Tests for artifact-registry-mcp.

Author: Pawan Gunjkar (pawangunjkar@gmail.com)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Ensure parent directory is in sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ["ARTIFACT_DISABLE_AUTOCONNECT"] = "1"

from artifact_client import (
    ArtifactClient,
    calculate_file_checksums,
    format_bytes,
)
from credential_store import CredentialStore, ArtifactCredentials
from server import (
    mcp,
    artifact_connect,
    artifact_status,
    artifact_disconnect,
    artifact_list_sessions,
    artifact_save_credentials,
    artifact_list_repositories,
    artifact_search_binaries,
    artifact_get_docker_image_tags_and_digests,
    artifact_verify_checksum_integrity,
    artifact_upload_binary,
    artifact_promote_release,
    artifact_cleanup_old_snapshots,
)


class CredentialStoreTests(unittest.TestCase):
    """Test CredentialStore methods and caching."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = CredentialStore(cache_dir=self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_and_get_credentials(self):
        self.store.save_credentials(
            session_name="test-nexus",
            registry_type="nexus",
            base_url="http://nexus.example.com:8081",
            username="ci-user",
            token_or_password="mypassword",
        )
        creds = self.store.get_credentials("test-nexus")
        self.assertIsNotNone(creds)
        self.assertEqual(creds.registry_type, "nexus")
        self.assertEqual(creds.base_url, "http://nexus.example.com:8081")
        self.assertEqual(creds.username, "ci-user")
        self.assertEqual(creds.token_or_password, "mypassword")

    def test_masked_dict(self):
        creds = ArtifactCredentials(
            registry_type="nexus",
            base_url="http://nexus:8081",
            username="admin",
            token_or_password="verysecrettoken123",
        )
        masked = creds.masked_dict()
        self.assertEqual(masked["token_or_password"], "****n123")

    def test_delete_credentials(self):
        self.store.save_credentials(
            session_name="temp-session",
            registry_type="artifactory",
            base_url="http://artifactory:8082",
        )
        self.assertIsNotNone(self.store.get_credentials("temp-session"))
        deleted = self.store.delete_credentials("temp-session")
        self.assertTrue(deleted)
        self.assertIsNone(self.store.get_credentials("temp-session"))

    def test_env_var_resolution(self):
        with mock.patch.dict(os.environ, {
            "ARTIFACT_REGISTRY_TYPE": "artifactory",
            "ARTIFACT_REGISTRY_URL": "https://jfrog.corp/artifactory",
            "ARTIFACT_REGISTRY_USER": "deployer",
            "ARTIFACT_REGISTRY_TOKEN": "tokenABC",
        }):
            creds = self.store.get_credentials("default")
            self.assertIsNotNone(creds)
            self.assertEqual(creds.registry_type, "artifactory")
            self.assertEqual(creds.base_url, "https://jfrog.corp/artifactory")
            self.assertEqual(creds.username, "deployer")


class UtilitiesTests(unittest.TestCase):
    """Test utility and helper functions."""

    def test_format_bytes(self):
        self.assertEqual(format_bytes(500), "500 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1024 * 1024 * 5), "5.00 MB")
        self.assertEqual(format_bytes(1024 * 1024 * 1024 * 2.5), "2.50 GB")
        self.assertEqual(format_bytes(None), "Unknown size")

    def test_calculate_file_checksums(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"Hello World Artifact MCP Supply Chain")
            temp_path = f.name

        try:
            checksums = calculate_file_checksums(temp_path)
            self.assertIn("sha256", checksums)
            self.assertIn("sha1", checksums)
            self.assertIn("md5", checksums)
            expected_sha = hashlib.sha256(b"Hello World Artifact MCP Supply Chain").hexdigest()
            self.assertEqual(checksums["sha256"], expected_sha)
        finally:
            os.unlink(temp_path)


class ArtifactToolLifecycleTests(unittest.TestCase):
    """Test core MCP tools and confirmation gates."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = CredentialStore(cache_dir=self.temp_dir.name)
        self.client = ArtifactClient(credential_store=self.store)

        import server
        from artifact_client import ArtifactSession
        self.mock_session = ArtifactSession(
            name="default",
            registry_type="nexus",
            base_url="http://nexus:8081",
            username="admin",
            token_or_password="pwd",
            client=mock.MagicMock(),
        )
        server._client._sessions["default"] = self.mock_session

    def tearDown(self):
        import server
        server._client._sessions.clear()
        self.temp_dir.cleanup()

    def test_all_12_tools_registered(self):
        tool_names = [t.name for t in mcp._tool_manager.list_tools()]
        expected = [
            "artifact_connect",
            "artifact_status",
            "artifact_disconnect",
            "artifact_list_sessions",
            "artifact_save_credentials",
            "artifact_list_repositories",
            "artifact_search_binaries",
            "artifact_get_docker_image_tags_and_digests",
            "artifact_verify_checksum_integrity",
            "artifact_upload_binary",
            "artifact_promote_release",
            "artifact_cleanup_old_snapshots",
        ]
        self.assertEqual(len(tool_names), 12)
        for exp in expected:
            self.assertIn(exp, tool_names)

    def test_confirmation_gate_upload_binary(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"dummy jar content")
            jar_path = f.name

        try:
            # When confirm=False, must return Confirmation Required preview
            resp = asyncio.run(artifact_upload_binary(
                repository="maven-releases",
                local_file_path=jar_path,
                target_path="com/corp/test/1.0/test-1.0.jar",
                confirm=False,
            ))
            self.assertIn("Confirmation Required", resp)
            self.assertIn("Local SHA256", resp)
            self.assertIn("Re-call with `confirm=true`", resp)
        finally:
            os.unlink(jar_path)

    def test_confirmation_gate_promote_release(self):
        # When confirm=False, must return Confirmation Required preview
        resp = asyncio.run(artifact_promote_release(
            source_repo="libs-staging-local",
            target_repo="libs-release-local",
            artifact_or_build_name="auth-service",
            version="1.0.0",
            confirm=False,
        ))
        self.assertIn("Confirmation Required", resp)
        self.assertIn("Promote artifact from staging to release", resp)
        self.assertIn("Re-call with `confirm=true`", resp)

    def test_snapshot_cleanup_simulation_dry_run(self):
        import server
        with mock.patch.object(server._client, "cleanup_old_snapshots") as mock_cleanup:
            mock_cleanup.return_value = "### 🔍 Safe Snapshot Cleanup Simulation (`dry_run=True`)"
            resp = asyncio.run(artifact_cleanup_old_snapshots(
                repository="libs-snapshot-local",
                component_name="payment-service",
                keep_latest_n=3,
                dry_run=True,
            ))
            self.assertIn("Simulation", resp)

    def test_snapshot_cleanup_destructive_gate(self):
        # When dry_run=False and confirm=False, must gate with confirmation
        # Set up a fake connected session
        self.client._sessions["mock_sess"] = mock.MagicMock(
            registry_type="artifactory",
            base_url="http://artifactory:8082",
        )
        with mock.patch("server._client", self.client):
            with mock.patch.object(self.client, "cleanup_old_snapshots") as mock_cleanup:
                mock_cleanup.return_value = "🔒 Confirmation Required: Permanent Snapshot Deletion"
                resp = asyncio.run(artifact_cleanup_old_snapshots(
                    repository="libs-snapshot-local",
                    component_name="payment-service",
                    keep_latest_n=3,
                    dry_run=False,
                    confirm=False,
                    session_name="mock_sess",
                ))
                self.assertIn("Confirmation Required", resp)

    def test_verify_checksum_integrity_format_guard(self):
        # Invalid sha256 string (not 64 chars) should be rejected
        resp = asyncio.run(artifact_verify_checksum_integrity(
            artifact_path_or_url="libs-release-local/app.jar",
            expected_sha256="invalid-short-hash",
        ))
        self.assertIn("Invalid expected_sha256", resp)


class AgensiZipValidationTests(unittest.TestCase):
    """Validate that Agensi build produces a compliant zip archive."""

    def test_agensi_zip_builds_and_passes(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("build_agensi_zip", ROOT / "scripts" / "build_agensi_zip.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        ret = mod.main()
        self.assertEqual(ret, 0)
        self.assertTrue((ROOT / "dist" / "artifact-registry-mcp-pro.zip").is_file())


if __name__ == "__main__":
    unittest.main()
