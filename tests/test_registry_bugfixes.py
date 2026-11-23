"""
Regression tests for registry correctness fixes (cleanup, verification, promotion, Docker digests).

Author: Pawan Gunjkar (pawangunjkar@gmail.com)

Every test runs against an in-memory fake registry built on httpx.MockTransport,
so no network or real Nexus/Artifactory instance is needed.
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

import httpx

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ["ARTIFACT_DISABLE_AUTOCONNECT"] = "1"

from artifact_mcp.artifact_client import (  # noqa: E402
    ArtifactClient,
    ArtifactSession,
    _parse_ts,
    is_snapshot_version,
)
from artifact_mcp.credential_store import CredentialStore  # noqa: E402

SHA_A = hashlib.sha256(b"artifact-a").hexdigest()
SHA_B = hashlib.sha256(b"artifact-b").hexdigest()


def make_client(registry_type: str, handler) -> tuple[ArtifactClient, list[httpx.Request]]:
    calls: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    base = "http://registry.test" + ("/artifactory" if registry_type == "artifactory" else "")
    http = httpx.AsyncClient(base_url=base, transport=httpx.MockTransport(recording))
    tmp = tempfile.mkdtemp()
    client = ArtifactClient(credential_store=CredentialStore(cache_dir=tmp))
    client._sessions["default"] = ArtifactSession(
        name="default",
        registry_type=registry_type,
        base_url=base,
        username="ci",
        token_or_password="x",
        client=http,
    )
    return client, calls


def run(coro):
    return asyncio.run(coro)


class HelperTests(unittest.TestCase):
    def test_snapshot_detection(self):
        self.assertTrue(is_snapshot_version("1.0-SNAPSHOT"))
        self.assertTrue(is_snapshot_version("2.3.1-20240105.101500-7"))
        self.assertFalse(is_snapshot_version("1.0.0"))
        self.assertFalse(is_snapshot_version("2024.01.05"))

    def test_parse_timestamps(self):
        a = _parse_ts("2024-01-02T10:00:00.123Z")
        b = _parse_ts("2024-01-02T11:00:00.123+01:00")
        self.assertAlmostEqual(a, b, places=3)
        self.assertGreater(_parse_ts("2024-01-03T00:00:00.000+0000"), a)
        self.assertEqual(_parse_ts(""), 0.0)
        self.assertEqual(_parse_ts("not-a-date"), 0.0)


class NexusCleanupTests(unittest.TestCase):
    def _components(self):
        def comp(cid, version, stamp, n_assets=3):
            return {
                "id": cid,
                "name": "billing",
                "version": version,
                "assets": [{"lastModified": stamp, "fileSize": 100} for _ in range(n_assets)],
            }
        return [
            comp("rel-1", "1.0.0", "2024-01-01T00:00:00.000+00:00"),
            comp("s1", "1.1-20240101.000000-1", "2024-01-01T00:00:00.000+00:00"),
            comp("s2", "1.1-20240102.000000-2", "2024-01-02T00:00:00.000+00:00"),
            comp("s3", "1.1-20240103.000000-3", "2024-01-03T00:00:00.000+00:00"),
            {"id": "other", "name": "billing-ui", "version": "9-SNAPSHOT", "assets": []},
        ]

    def test_counts_versions_and_never_selects_releases(self):
        page_one = self._components()[:3]
        page_two = self._components()[3:]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/service/rest/v1/search":
                if request.url.params.get("continuationToken") == "next":
                    return httpx.Response(200, json={"items": page_two, "continuationToken": None})
                return httpx.Response(200, json={"items": page_one, "continuationToken": "next"})
            if request.method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(404)

        client, calls = make_client("nexus", handler)
        preview = run(client.cleanup_old_snapshots("maven-snapshots", "billing", keep_latest_n=1))
        self.assertIn("Snapshot Versions Found**: 3", preview)
        self.assertNotIn("1.0.0", preview)

        result = run(client.cleanup_old_snapshots(
            "maven-snapshots", "billing", keep_latest_n=1, dry_run=False, confirm=True
        ))
        self.assertIn("Versions Deleted**: 2 / 2", result)
        deleted = sorted(r.url.path for r in calls if r.method == "DELETE")
        self.assertEqual(deleted, ["/service/rest/v1/components/s1", "/service/rest/v1/components/s2"])

    def test_keep_latest_must_be_positive(self):
        client, _ = make_client("nexus", lambda r: httpx.Response(200, json={"items": []}))
        self.assertIn("at least 1", run(client.cleanup_old_snapshots("r", "c", keep_latest_n=0)))


class ArtifactoryCleanupTests(unittest.TestCase):
    def test_groups_by_version_folder(self):
        results = [
            {"path": "com/corp/billing/1.0.0", "name": "billing-1.0.0.jar", "size": 10, "modified": "2024-01-01T00:00:00.000Z"},
            {"path": "com/corp/billing/2.0-SNAPSHOT", "name": "a.jar", "size": 10, "modified": "2024-01-05T00:00:00.000Z"},
            {"path": "com/corp/billing/2.0-SNAPSHOT", "name": "a.pom", "size": 1, "modified": "2024-01-05T00:00:00.000Z"},
            {"path": "com/corp/billing/1.9-SNAPSHOT", "name": "b.jar", "size": 10, "modified": "2024-01-03T00:00:00.000Z"},
            {"path": "com/corp/billing-ui/3.0-SNAPSHOT", "name": "c.jar", "size": 10, "modified": "2024-01-09T00:00:00.000Z"},
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/api/search/aql"):
                return httpx.Response(200, json={"results": results})
            if request.method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(404)

        client, calls = make_client("artifactory", handler)
        result = run(client.cleanup_old_snapshots(
            "libs-snapshot-local", "billing", keep_latest_n=1, dry_run=False, confirm=True
        ))
        self.assertIn("Versions Deleted**: 1 / 1", result)
        deleted = [r.url.path for r in calls if r.method == "DELETE"]
        self.assertEqual(deleted, ["/artifactory/libs-snapshot-local/com/corp/billing/1.9-SNAPSHOT"])


class VerifyChecksumTests(unittest.TestCase):
    def test_nexus_same_checksum_elsewhere_is_not_a_match(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/service/rest/v1/search/assets":
                return httpx.Response(200, json={"items": [
                    {"path": "com/other/thing-1.0.jar", "checksum": {"sha256": SHA_A}},
                ]})
            if request.url.path == "/repository/releases/com/corp/app-1.0.jar":
                return httpx.Response(200, content=b"artifact-b")
            return httpx.Response(404)

        client, _ = make_client("nexus", handler)
        result = run(client.verify_checksum_integrity("releases/com/corp/app-1.0.jar", SHA_A))
        self.assertIn("ATTESTATION FAILED", result)
        self.assertIn(SHA_B, result)

    def test_nexus_exact_path_match_passes(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/service/rest/v1/search/assets":
                return httpx.Response(200, json={"items": [
                    {"path": "/com/corp/app-1.0.jar", "checksum": {"sha256": SHA_A}, "fileSize": 10},
                ]})
            return httpx.Response(404)

        client, _ = make_client("nexus", handler)
        result = run(client.verify_checksum_integrity(
            "http://registry.test/repository/releases/com/corp/app-1.0.jar", SHA_A
        ))
        self.assertIn("ATTESTATION PASSED", result)

    def test_artifactory_missing_path_fails_even_if_checksum_exists(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.startswith("/artifactory/api/search/checksum"):
                return httpx.Response(200, json={"results": [{"uri": "somewhere"}]})
            return httpx.Response(404)

        client, _ = make_client("artifactory", handler)
        result = run(client.verify_checksum_integrity("libs-release-local/app.jar", SHA_A))
        self.assertIn("not found", result)
        self.assertNotIn("PASSED", result)

    def test_artifactory_metadata_without_sha256_falls_back_to_hashing(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/artifactory/api/storage/libs-release-local/app.jar":
                return httpx.Response(200, json={"checksums": {"sha1": "x"}, "size": "10"})
            if request.url.path == "/artifactory/libs-release-local/app.jar":
                return httpx.Response(200, content=b"artifact-a")
            return httpx.Response(404)

        client, _ = make_client("artifactory", handler)
        result = run(client.verify_checksum_integrity("libs-release-local/app.jar", SHA_A))
        self.assertIn("ATTESTATION PASSED", result)
        self.assertIn("downloaded and hashed", result)


class PromoteTests(unittest.TestCase):
    def test_nexus_copies_only_requested_version_and_checks_uploads(self):
        components = [
            {"name": "cart", "version": "1.5.0", "assets": [
                {"path": "com/corp/cart/1.5.0/cart-1.5.0.jar", "downloadUrl": "http://registry.test/repository/staging/com/corp/cart/1.5.0/cart-1.5.0.jar",
                 "checksum": {"sha256": SHA_A}},
                {"path": "com/corp/cart/1.5.0/cart-1.5.0.jar.sha1", "checksum": {}},
            ]},
            {"name": "cart", "version": "1.5.0-rc1", "assets": [{"path": "com/corp/cart/1.5.0-rc1/x.jar"}]},
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/service/rest/v1/search":
                self.assertEqual(request.url.params.get("version"), "1.5.0")
                self.assertEqual(request.url.params.get("group"), "com.corp")
                return httpx.Response(200, json={"items": components})
            if request.method == "GET" and request.url.path.startswith("/repository/staging/"):
                return httpx.Response(200, content=b"artifact-a")
            if request.method == "PUT":
                return httpx.Response(201)
            return httpx.Response(404)

        client, calls = make_client("nexus", handler)
        result = run(client.promote_release("staging", "releases", "com/corp/cart", "1.5.0", confirm=True))
        self.assertIn("Promotion Completed", result)
        puts = [r.url.path for r in calls if r.method == "PUT"]
        self.assertEqual(puts, ["/repository/releases/com/corp/cart/1.5.0/cart-1.5.0.jar"])

    def test_nexus_failed_upload_is_reported(self):
        components = [{"name": "cart", "version": "1.5.0", "assets": [
            {"path": "cart/1.5.0/cart.jar", "checksum": {"sha256": SHA_A}},
        ]}]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/service/rest/v1/search":
                return httpx.Response(200, json={"items": components})
            if request.method == "GET":
                return httpx.Response(200, content=b"artifact-a")
            if request.method == "PUT":
                return httpx.Response(400, text="Repository does not allow updating assets")
            return httpx.Response(404)

        client, _ = make_client("nexus", handler)
        result = run(client.promote_release("staging", "releases", "cart", "1.5.0", confirm=True))
        self.assertIn("promotion incomplete", result)
        self.assertNotIn("Completed Successfully", result)

    def test_artifactory_never_copies_whole_component_folder(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.startswith("/artifactory/api/storage/"):
                return httpx.Response(404)
            return httpx.Response(200, json={"messages": []})

        client, calls = make_client("artifactory", handler)
        result = run(client.promote_release("stage", "prod", "cart", "1.5.0", confirm=True))
        self.assertIn("was not found", result)
        self.assertFalse([r for r in calls if "/api/copy/" in r.url.path])

    def test_artifactory_dry_run_error_blocks_copy(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.startswith("/artifactory/api/storage/"):
                return httpx.Response(200, json={})
            if "/api/copy/" in request.url.path:
                return httpx.Response(200, json={"messages": [{"level": "ERROR", "message": "no permission"}]})
            return httpx.Response(404)

        client, calls = make_client("artifactory", handler)
        result = run(client.promote_release("stage", "prod", "cart", "1.5.0", confirm=True))
        self.assertIn("dry run failed", result)
        copies = [r for r in calls if "/api/copy/" in r.url.path]
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].url.params.get("dry"), "1")


class UploadTests(unittest.TestCase):
    def test_artifactory_upload_streams_file_and_verifies(self):
        received: dict[str, bytes] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "PUT":
                received["body"] = request.read()
                received["length"] = request.headers.get("Content-Length", "").encode()
                return httpx.Response(201)
            if request.url.path.startswith("/artifactory/api/storage/"):
                return httpx.Response(200, json={"checksums": {"sha256": SHA_A}, "size": "10"})
            return httpx.Response(404)

        with tempfile.NamedTemporaryFile("wb", delete=False) as fh:
            fh.write(b"artifact-a")
            local = fh.name
        try:
            client, _ = make_client("artifactory", handler)
            result = run(client.upload_binary("libs-release-local", local, "com/corp/app.jar", confirm=True))
        finally:
            os.unlink(local)
        self.assertEqual(received["body"], b"artifact-a")
        self.assertEqual(received["length"], b"10")
        self.assertIn("Upload Successful and Verified", result)

    def test_upload_reports_failed_verification(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "PUT":
                return httpx.Response(201)
            if request.url.path.startswith("/artifactory/api/storage/"):
                return httpx.Response(200, json={"checksums": {"sha256": SHA_B}})
            return httpx.Response(404)

        with tempfile.NamedTemporaryFile("wb", delete=False) as fh:
            fh.write(b"artifact-a")
            local = fh.name
        try:
            client, _ = make_client("artifactory", handler)
            result = run(client.upload_binary("libs-release-local", local, "app.jar", confirm=True))
        finally:
            os.unlink(local)
        self.assertIn("verification did NOT pass", result)


class DockerDigestTests(unittest.TestCase):
    def test_nexus_sorted_newest_first_with_explicit_host(self):
        digest_old = "a" * 64
        digest_new = "b" * 64
        assets = [
            {"path": "v2/payments/manifests/1.0", "checksum": {"sha256": digest_old}, "lastModified": "2024-01-01T00:00:00.000+00:00"},
            {"path": "v2/payments/manifests/2.0", "checksum": {"sha256": digest_new}, "lastModified": "2024-02-01T00:00:00.000+00:00"},
            {"path": "v2/payments-ui/manifests/9.9", "checksum": {"sha256": "c" * 64}, "lastModified": "2024-03-01T00:00:00.000+00:00"},
        ]
        client, _ = make_client("nexus", lambda r: httpx.Response(200, json={"items": assets}))
        result = run(client.get_docker_image_tags_and_digests(
            "docker-hosted", "payments", registry_host="docker.corp:8443"
        ))
        self.assertIn(f"docker.corp:8443/payments@sha256:{digest_new}", result)
        self.assertNotIn("9.9", result)
        self.assertIn("k8s_trigger_deployment_rollout(", result)
        self.assertLess(result.index("`2.0`"), result.index("`1.0`"))

    def test_artifactory_unordered_tags_need_explicit_tag(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/api/search/aql"):
                return httpx.Response(400)
            if request.url.path.endswith("/tags/list"):
                return httpx.Response(200, json={"tags": ["1.0", "2.0"]})
            if request.method == "HEAD":
                return httpx.Response(200, headers={"Docker-Content-Digest": "sha256:" + "d" * 64})
            return httpx.Response(404)

        client, _ = make_client("artifactory", handler)
        result = run(client.get_docker_image_tags_and_digests("docker-local", "payments"))
        self.assertIn("No handoff generated", result)
        chosen = run(client.get_docker_image_tags_and_digests("docker-local", "payments", tag="2.0"))
        self.assertIn("registry.test/docker-local/payments@sha256:" + "d" * 64, chosen)


if __name__ == "__main__":
    unittest.main()
