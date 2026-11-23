"""
HTTP Client for Sonatype Nexus Repository 3 and JFrog Artifactory.

Author: Pawan Gunjkar (pawangunjkar@gmail.com)

Handles all HTTP communication with artifact registries:
- Sonatype Nexus 3 REST API v1 (/service/rest/v1/...) & Docker v2 registry API
- JFrog Artifactory REST API (/artifactory/api/...) & AQL (Artifactory Query Language)
- Multi-session connection and credential caching
- Checksum computation, attestation, and verification (SHA256, SHA1, MD5)
- Confirmation-gated uploads, promotions, and snapshot pruning
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx

try:
    from artifact_mcp.credential_store import CredentialStore, ArtifactCredentials
except ImportError:
    from credential_store import CredentialStore, ArtifactCredentials


# Constants
DEFAULT_TIMEOUT = 30
MAX_OUTPUT_SIZE = 30_000


def calculate_file_checksums(file_path: Path | str) -> dict[str, str]:
    """Calculate SHA256, SHA1, and MD5 for a local file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Local file not found: {file_path}")

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def format_bytes(size: int | float | None) -> str:
    """Format bytes into human-readable string (KB, MB, GB)."""
    if size is None or size < 0:
        return "Unknown size"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.2f} PB"


@dataclass
class ArtifactSession:
    """Active HTTP session with an artifact registry."""
    name: str
    registry_type: str  # 'nexus' or 'artifactory'
    base_url: str
    username: str
    token_or_password: str
    client: httpx.AsyncClient
    version: str = "unknown"
    online: bool = True
    storage_info: dict[str, Any] = field(default_factory=dict)


class ArtifactClient:
    """
    Unified client for Sonatype Nexus 3 and JFrog Artifactory.

    Manages sessions, connection health, repositories, searches,
    Docker digests, checksum verification, uploads, promotions, and cleanup.
    """

    def __init__(self, credential_store: Optional[CredentialStore] = None):
        self._credentials = credential_store or CredentialStore()
        self._sessions: dict[str, ArtifactSession] = {}

    @property
    def credential_store(self) -> CredentialStore:
        return self._credentials

    def session(self, session_name: str = "default") -> ArtifactSession:
        """Get an active session or raise KeyError with guidance."""
        if session_name not in self._sessions:
            creds = self._credentials.get_credentials(session_name)
            if creds:
                raise KeyError(
                    f"Session '{session_name}' is not currently connected, but saved credentials exist.\n"
                    f"Call artifact_connect(session_name='{session_name}') to reconnect."
                )
            available = list(self._sessions.keys())
            raise KeyError(
                f"No active session named '{session_name}'. "
                f"Active sessions: {available or 'none'}. "
                f"Call artifact_connect(registry_type='...', base_url='...', token_or_password='...') first."
            )
        return self._sessions[session_name]

    async def connect(
        self,
        registry_type: str = "",
        base_url: str = "",
        token_or_password: str = "",
        username: str = "",
        session_name: str = "default",
        ssl_verify: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        save_credentials: bool = True,
    ) -> str:
        """
        Connect to Sonatype Nexus 3 or JFrog Artifactory and create a named session.

        Probes system status and version to verify connectivity and credentials.
        """
        if session_name in self._sessions:
            await self.disconnect(session_name)

        if not base_url or not registry_type:
            creds = self._credentials.get_credentials(session_name)
            if creds:
                registry_type = creds.registry_type
                base_url = creds.base_url
                username = creds.username or username
                token_or_password = creds.token_or_password or token_or_password
                ssl_verify = creds.ssl_verify
                timeout = creds.timeout
            else:
                return (
                    f"❌ No credentials found for session '{session_name}'.\n\n"
                    f"Please provide registry connection parameters:\n"
                    f"  • registry_type: 'nexus' (Sonatype Nexus 3) or 'artifactory' (JFrog Artifactory)\n"
                    f"  • base_url: Base URL (e.g. http://localhost:8081 or http://localhost:8082/artifactory)\n"
                    f"  • token_or_password: Password, API Token, or Access Token\n"
                    f"  • username: Username (e.g. 'admin' or 'ci-agent')\n\n"
                    f"Example:\n"
                    f"  artifact_connect(registry_type='nexus', base_url='http://nexus:8081', username='admin', token_or_password='secret')\n"
                    f"  artifact_connect(registry_type='artifactory', base_url='https://artifactory.corp/artifactory', token_or_password='cmV...')"
                )

        reg_type = registry_type.strip().lower()
        if reg_type not in ("nexus", "artifactory"):
            return f"❌ Unsupported registry_type '{registry_type}'. Must be 'nexus' or 'artifactory'."

        url = base_url.strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            return f"❌ base_url must start with http:// or https:// (got '{base_url}')."

        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "artifact-mcp/1.0.0",
        }
        auth: Optional[tuple[str, str]] = None

        if reg_type == "artifactory":
            if token_or_password and not username:
                headers["Authorization"] = f"Bearer {token_or_password}"
            elif username and token_or_password:
                auth = (username, token_or_password)
        else:
            if username and token_or_password:
                auth = (username, token_or_password)
            elif token_or_password and not username:
                auth = ("admin", token_or_password)

        client = httpx.AsyncClient(
            base_url=url,
            auth=auth,
            headers=headers,
            verify=ssl_verify,
            timeout=timeout,
            follow_redirects=True,
        )

        version = "unknown"
        storage_details: dict[str, Any] = {}

        try:
            if reg_type == "nexus":
                resp = await client.get("/service/rest/v1/status")
                if resp.status_code != 200:
                    await client.aclose()
                    return (
                        f"❌ Nexus health probe failed: HTTP {resp.status_code} {resp.reason_phrase}\n"
                        f"Target URL: {url}/service/rest/v1/status\n"
                        f"Response: {resp.text[:300]}"
                    )

                server_hdr = resp.headers.get("Server", "")
                if "Nexus" in server_hdr:
                    version = server_hdr.replace("Nexus/", "").strip()
                else:
                    version = "Nexus Repository 3"

                repo_resp = await client.get("/service/rest/v1/repositories")
                if repo_resp.status_code == 200:
                    repos = repo_resp.json()
                    storage_details["repository_count"] = len(repos)
                elif repo_resp.status_code == 401:
                    await client.aclose()
                    return f"❌ Authentication failed for user '{username}' on Nexus at {url} (HTTP 401 Unauthorized)."

            else:  # artifactory
                ping_resp = await client.get("/api/system/ping")
                if ping_resp.status_code != 200 or ping_resp.text.strip() != "OK":
                    await client.aclose()
                    return (
                        f"❌ Artifactory ping failed: HTTP {ping_resp.status_code}\n"
                        f"Target URL: {url}/api/system/ping\n"
                        f"Response: {ping_resp.text[:300]}"
                    )

                ver_resp = await client.get("/api/system/version")
                if ver_resp.status_code == 200:
                    ver_data = ver_resp.json()
                    version = ver_data.get("version", "7.x")
                    storage_details["revision"] = ver_data.get("revision", "")

                store_resp = await client.get("/api/storageinfo")
                if store_resp.status_code == 200:
                    storage_details["storage_summary"] = store_resp.json().get("binariesSummary", {})

            session = ArtifactSession(
                name=session_name,
                registry_type=reg_type,
                base_url=url,
                username=username,
                token_or_password=token_or_password,
                client=client,
                version=version,
                online=True,
                storage_info=storage_details,
            )
            self._sessions[session_name] = session

            if save_credentials:
                self._credentials.save_credentials(
                    session_name=session_name,
                    registry_type=reg_type,
                    base_url=url,
                    username=username,
                    token_or_password=token_or_password,
                    ssl_verify=ssl_verify,
                    timeout=timeout,
                )

            disp_type = "Sonatype Nexus Repository 3" if reg_type == "nexus" else "JFrog Artifactory"
            user_disp = username if username else "(token authenticated)"
            repo_count_str = f"  • Repositories Detected: {storage_details.get('repository_count', 'available')}\n" if "repository_count" in storage_details else ""

            return (
                f"✅ Connected to {disp_type} successfully!\n"
                f"  • Session: {session_name}\n"
                f"  • Base URL: {url}\n"
                f"  • User: {user_disp}\n"
                f"  • Version: {version}\n"
                f"{repo_count_str}"
                f"  • Connection Health: ONLINE (HTTP 200 OK)\n"
                f"  • Credentials cached for future use"
            )

        except httpx.HTTPStatusError as exc:
            await client.aclose()
            return f"❌ Registry HTTP error {exc.response.status_code}: {exc.response.text[:300]}"
        except httpx.ConnectError:
            await client.aclose()
            return f"❌ Connection refused. Unable to connect to {url}. Verify the host is reachable."
        except httpx.TimeoutException:
            await client.aclose()
            return f"❌ Connection timed out after {timeout} seconds connecting to {url}."
        except Exception as exc:
            await client.aclose()
            return f"❌ Failed to connect to registry: {type(exc).__name__}: {str(exc)}"

    async def disconnect(self, session_name: str = "default") -> str:
        """Disconnect and close the client for a session."""
        if session_name not in self._sessions:
            return f"⚠️ Session '{session_name}' is not currently active."

        session = self._sessions.pop(session_name)
        try:
            await session.client.aclose()
        except Exception:
            pass
        return f"✅ Disconnected session '{session_name}' ({session.registry_type.capitalize()} at {session.base_url})."

    async def status(self, session_name: str = "default") -> str:
        """Check connection health, authenticated user, registry version, and storage quota."""
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        reg_name = "Sonatype Nexus 3" if session.registry_type == "nexus" else "JFrog Artifactory"
        client = session.client
        health_status = "UNKNOWN"
        latency_ms = 0.0
        extra_info: list[str] = []

        t0 = time.perf_counter()
        try:
            if session.registry_type == "nexus":
                resp = await client.get("/service/rest/v1/status")
                latency_ms = (time.perf_counter() - t0) * 1000
                if resp.status_code == 200:
                    health_status = "HEALTHY (ONLINE)"
                else:
                    health_status = f"DEGRADED (HTTP {resp.status_code})"

                blob_resp = await client.get("/service/rest/v1/blobstores")
                if blob_resp.status_code == 200:
                    blob_data = blob_resp.json()
                    extra_info.append(f"  • Blob Stores Configured: {len(blob_data)}")
                    for bs in blob_data[:3]:
                        bs_name = bs.get("name", "default")
                        bs_type = bs.get("type", "File")
                        blob_count = bs.get("blobCount", "N/A")
                        extra_info.append(f"    - [{bs_type}] {bs_name}: {blob_count} blobs")

                repo_resp = await client.get("/service/rest/v1/repositories")
                if repo_resp.status_code == 200:
                    repos = repo_resp.json()
                    extra_info.append(f"  • Active Repositories: {len(repos)}")

            else:  # artifactory
                resp = await client.get("/api/system/ping")
                latency_ms = (time.perf_counter() - t0) * 1000
                if resp.status_code == 200 and resp.text.strip() == "OK":
                    health_status = "HEALTHY (ONLINE)"
                else:
                    health_status = f"DEGRADED (HTTP {resp.status_code})"

                store_resp = await client.get("/api/storageinfo")
                if store_resp.status_code == 200:
                    store_data = store_resp.json()
                    bins = store_data.get("binariesSummary", {})
                    extra_info.append(f"  • Storage Binaries Size: {bins.get('binariesSize', 'N/A')}")
                    extra_info.append(f"  • Total Artifacts Count: {bins.get('artifactsCount', 'N/A')}")
                    extra_info.append(f"  • Total Storage Space: {bins.get('totalSpace', 'N/A')}")
                    extra_info.append(f"  • Free Storage Space: {bins.get('freeSpace', 'N/A')}")

                repo_resp = await client.get("/api/repositories")
                if repo_resp.status_code == 200:
                    extra_info.append(f"  • Total Repositories: {len(repo_resp.json())}")

        except Exception as exc:
            health_status = f"UNREACHABLE ({type(exc).__name__}: {exc})"

        user_disp = session.username or "(token authenticated)"
        extra_text = "\n".join(extra_info) if extra_info else "  • Detailed storage quota: Not available"

        return (
            f"### Artifact Registry Status: {reg_name}\n"
            f"  • Session Name: `{session.name}`\n"
            f"  • Base URL: {session.base_url}\n"
            f"  • Registry Type: `{session.registry_type}`\n"
            f"  • Authenticated User: `{user_disp}`\n"
            f"  • Version: `{session.version}`\n"
            f"  • Health Status: **{health_status}**\n"
            f"  • API Ping Latency: {latency_ms:.1f} ms\n"
            f"#### Storage & Repository Metrics:\n"
            f"{extra_text}"
        )

    def list_sessions(self) -> dict[str, Any]:
        """List all active and cached sessions."""
        cached = self._credentials.list_sessions()
        result: dict[str, Any] = {}
        for name, data in cached.items():
            is_active = name in self._sessions
            result[name] = {
                **data,
                "is_active": is_active,
                "version": self._sessions[name].version if is_active else "not connected",
            }
        for name, sess in self._sessions.items():
            if name not in result:
                result[name] = {
                    "registry_type": sess.registry_type,
                    "base_url": sess.base_url,
                    "username": sess.username,
                    "token_or_password": "****" + sess.token_or_password[-4:] if len(sess.token_or_password) > 4 else "****",
                    "is_active": True,
                    "version": sess.version,
                }
        return result

    async def list_repositories(
        self,
        format_filter: str = "",
        type_filter: str = "",
        session_name: str = "default",
    ) -> str:
        """
        List repositories filtered by format and type.

        Formats: maven2, docker, npm, pypi, helm, raw/generic
        Types: hosted/local, proxy/remote, group/virtual
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        fmt = format_filter.strip().lower()
        typ = type_filter.strip().lower()

        fmt_synonyms = {
            "maven": "maven2",
            "generic": "raw",
            "oci": "docker",
        }
        fmt = fmt_synonyms.get(fmt, fmt)

        type_synonyms_nexus = {
            "local": "hosted",
            "remote": "proxy",
            "virtual": "group",
        }
        type_synonyms_artifactory = {
            "hosted": "local",
            "proxy": "remote",
            "group": "virtual",
        }

        client = session.client
        repos_output: list[dict[str, str]] = []

        try:
            if session.registry_type == "nexus":
                resp = await client.get("/service/rest/v1/repositories")
                if resp.status_code != 200:
                    return f"❌ Nexus API error (HTTP {resp.status_code}): {resp.text[:300]}"
                raw_repos = resp.json()

                target_type = type_synonyms_nexus.get(typ, typ)

                for r in raw_repos:
                    r_name = r.get("name", "")
                    r_format = r.get("format", "").lower()
                    r_type = r.get("type", "").lower()
                    r_url = r.get("url", f"{session.base_url}/repository/{r_name}")
                    r_online = "Online" if r.get("online", True) else "Offline"

                    if fmt and fmt not in r_format:
                        continue
                    if target_type and target_type != r_type:
                        continue

                    repos_output.append({
                        "name": r_name,
                        "registry": "Nexus 3",
                        "format": r_format,
                        "type": r_type,
                        "status": r_online,
                        "url": r_url,
                    })

            else:  # artifactory
                params = {}
                target_type = type_synonyms_artifactory.get(typ, typ).upper()
                if target_type:
                    params["type"] = target_type
                if fmt:
                    art_fmt = "maven" if fmt == "maven2" else ("generic" if fmt == "raw" else fmt)
                    params["packageType"] = art_fmt

                resp = await client.get("/api/repositories", params=params)
                if resp.status_code != 200:
                    return f"❌ Artifactory API error (HTTP {resp.status_code}): {resp.text[:300]}"
                raw_repos = resp.json()

                for r in raw_repos:
                    r_name = r.get("key", "")
                    r_format = r.get("packageType", "generic").lower()
                    r_type = r.get("type", "LOCAL").lower()
                    r_url = r.get("url", f"{session.base_url}/{r_name}")

                    norm_format = "maven2" if r_format == "maven" else ("raw" if r_format == "generic" else r_format)

                    if fmt and fmt != norm_format and fmt not in norm_format:
                        continue
                    if typ and typ != r_type and type_synonyms_artifactory.get(typ, typ) != r_type:
                        continue

                    repos_output.append({
                        "name": r_name,
                        "registry": "Artifactory",
                        "format": norm_format,
                        "type": r_type,
                        "status": "Online",
                        "url": r_url,
                    })

        except Exception as exc:
            return f"❌ Error listing repositories: {type(exc).__name__}: {str(exc)}"

        if not repos_output:
            filter_desc = []
            if format_filter:
                filter_desc.append(f"format='{format_filter}'")
            if type_filter:
                filter_desc.append(f"type='{type_filter}'")
            filters_str = f" with {', '.join(filter_desc)}" if filter_desc else ""
            return f"No repositories found{filters_str} in {session.registry_type.capitalize()} ({session.base_url})."

        lines = [
            f"### Repositories in {session.registry_type.capitalize()} ({len(repos_output)} found)\n",
            "| Repository Key / Name | Registry | Format | Type | Status | URL |",
            "|-----------------------|----------|--------|------|--------|-----|",
        ]
        for repo in sorted(repos_output, key=lambda x: x["name"]):
            lines.append(
                f"| `{repo['name']}` | {repo['registry']} | `{repo['format']}` | `{repo['type']}` | {repo['status']} | {repo['url']} |"
            )

        return "\n".join(lines)

    async def search_binaries(
        self,
        name: str,
        group_or_repo: str = "",
        version: str = "",
        sha256: str = "",
        session_name: str = "default",
    ) -> str:
        """
        Search components and artifacts across Nexus or Artifactory.

        Returns download URLs, exact versions, timestamps, and SHA256/SHA1/MD5 checksums.
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        client = session.client
        results: list[dict[str, Any]] = []

        try:
            if session.registry_type == "nexus":
                params: dict[str, str] = {}
                if name:
                    params["name"] = f"*{name}*"
                if group_or_repo:
                    params["repository"] = group_or_repo
                if version:
                    params["version"] = version
                if sha256:
                    params["sha256"] = sha256

                resp = await client.get("/service/rest/v1/search/assets", params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])
                    for item in items:
                        checksums = item.get("checksum", {})
                        results.append({
                            "name": item.get("path", "").split("/")[-1] or name,
                            "path": item.get("path", ""),
                            "repository": item.get("repository", group_or_repo),
                            "format": item.get("format", ""),
                            "download_url": item.get("downloadUrl", ""),
                            "file_size": item.get("fileSize"),
                            "sha256": checksums.get("sha256", ""),
                            "sha1": checksums.get("sha1", ""),
                            "md5": checksums.get("md5", ""),
                            "last_modified": item.get("lastModified", ""),
                        })
                else:
                    return f"❌ Nexus search error (HTTP {resp.status_code}): {resp.text[:300]}"

            else:  # artifactory
                aql_conditions: list[str] = []
                if name:
                    aql_conditions.append(f'{"name": {"$match": "*{name}*"}}')
                if group_or_repo:
                    aql_conditions.append(f'{"repo": "{group_or_repo}"}')
                if sha256:
                    aql_conditions.append(f'{"actual_sha256": "{sha256}"}')

                cond_str = ", ".join(aql_conditions) if aql_conditions else '{"name": {"$match": "*"}}'
                aql_query = f'items.find({{{cond_str}}}).include("name", "repo", "path", "actual_sha256", "actual_md5", "sha1", "created", "modified", "size")'

                aql_resp = await client.post(
                    "/api/search/aql",
                    content=aql_query,
                    headers={"Content-Type": "text/plain"},
                )

                if aql_resp.status_code == 200:
                    aql_items = aql_resp.json().get("results", [])
                    for item in aql_items:
                        repo_k = item.get("repo", "")
                        item_path = item.get("path", "")
                        file_name = item.get("name", "")
                        full_path = f"{item_path}/{file_name}".lstrip("/")
                        dl_url = f"{session.base_url}/{repo_k}/{full_path}"
                        results.append({
                            "name": file_name,
                            "path": full_path,
                            "repository": repo_k,
                            "format": "artifactory",
                            "download_url": dl_url,
                            "file_size": item.get("size"),
                            "sha256": item.get("actual_sha256", ""),
                            "sha1": item.get("sha1", ""),
                            "md5": item.get("actual_md5", ""),
                            "last_modified": item.get("modified") or item.get("created", ""),
                        })
                else:
                    params = {"name": name}
                    if group_or_repo:
                        params["repos"] = group_or_repo
                    quick_resp = await client.get("/api/search/artifact", params=params)
                    if quick_resp.status_code == 200:
                        raw_items = quick_resp.json().get("results", [])
                        for r in raw_items:
                            uri = r.get("uri", "")
                            path_part = uri.split("/api/storage/")[-1] if "/api/storage/" in uri else uri
                            parts = path_part.split("/", 1)
                            repo_k = parts[0] if parts else group_or_repo
                            sub_path = parts[1] if len(parts) > 1 else ""
                            file_name = sub_path.split("/")[-1] if sub_path else name
                            results.append({
                                "name": file_name,
                                "path": sub_path,
                                "repository": repo_k,
                                "format": "artifactory",
                                "download_url": f"{session.base_url}/{repo_k}/{sub_path}",
                                "file_size": None,
                                "sha256": "",
                                "sha1": "",
                                "md5": "",
                                "last_modified": "",
                            })

        except Exception as exc:
            return f"❌ Error executing search: {type(exc).__name__}: {str(exc)}"

        if not results:
            return (
                f"No artifacts found matching query (name='{name}', repo='{group_or_repo}', "
                f"version='{version}', sha256='{sha256}') in {session.registry_type.capitalize()}."
            )

        lines = [
            f"### Artifact Search Results ({len(results)} matches in {session.registry_type.capitalize()})\n"
        ]
        for idx, res in enumerate(results[:25], 1):
            size_str = format_bytes(res["file_size"])
            sha256_disp = f"`{res['sha256']}`" if res["sha256"] else "*(not indexed)*"
            sha1_disp = f"`{res['sha1']}`" if res["sha1"] else "*(not indexed)*"
            lines.append(f"#### {idx}. `{res['name']}`")
            lines.append(f"  • **Repository**: `{res['repository']}`")
            lines.append(f"  • **Path**: `{res['path']}`")
            lines.append(f"  • **Size**: {size_str}")
            lines.append(f"  • **Download URL**: {res['download_url']}")
            lines.append(f"  • **SHA256**: {sha256_disp}")
            lines.append(f"  • **SHA1**: {sha1_disp}")
            if res.get("last_modified"):
                lines.append(f"  • **Modified**: {res['last_modified']}")
            lines.append("")

        if len(results) > 25:
            lines.append(f"*(Truncated: showing first 25 of {len(results)} items)*")

        return "\n".join(lines)

    async def get_docker_image_tags_and_digests(
        self,
        repository: str,
        image_name: str,
        limit: int = 20,
        session_name: str = "default",
        tag: str = "",
        registry_host: str = "",
    ) -> str:
        """
        Query Docker/OCI repositories to resolve an immutable sha256:... image digest.

        Tags are listed newest first when the registry exposes modification times.
        The k8s-mcp handoff uses `tag` when given, otherwise the newest resolved tag.
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        client = session.client
        clean_img = image_name.strip().strip("/")
        repo_clean = repository.strip().strip("/")
        wanted_tag = tag.strip()
        limit = max(1, min(int(limit or 20), 100))
        if not clean_img or not repo_clean:
            return "❌ repository and image_name are required."

        entries: list[dict[str, Any]] = []
        ordered_by_time = False
        notes: list[str] = []

        try:
            if session.registry_type == "artifactory":
                entries, ordered_by_time, notes = await self._artifactory_docker_tags(
                    client, repo_clean, clean_img, wanted_tag, limit
                )
            else:
                entries, ordered_by_time, notes = await self._nexus_docker_tags(
                    client, repo_clean, clean_img, wanted_tag, limit
                )
        except Exception as exc:
            return f"❌ Error querying Docker digests: {type(exc).__name__}: {str(exc)}"

        if not entries:
            target = f"tag '{wanted_tag}' of " if wanted_tag else ""
            return (
                f"No Docker tags/digests found for {target}image '{clean_img}' in repository '{repo_clean}' "
                f"({session.registry_type.capitalize()})."
            )

        host, host_note = _docker_registry_host(session, repo_clean, registry_host)
        if host_note:
            notes.append(host_note)

        lines = [
            f"### Docker / OCI Image Manifests: `{clean_img}` in `{repo_clean}`\n",
            "| Image Tag | Immutable Digest (`sha256:...`) | Last Modified | Status |",
            "|-----------|----------------------------------|---------------|--------|",
        ]
        for entry in entries:
            resolved = _DIGEST_RE.fullmatch(entry["digest"] or "") is not None
            status = "✅ Resolved" if resolved else "⚠️ Unresolved"
            lines.append(
                f"| `{entry['tag']}` | `{entry['digest'] or 'unknown'}` | {entry.get('modified') or '?'} | {status} |"
            )

        resolved_entries = [e for e in entries if _DIGEST_RE.fullmatch(e["digest"] or "")]
        chosen: Optional[dict[str, Any]] = None
        if wanted_tag:
            chosen = next((e for e in resolved_entries if e["tag"] == wanted_tag), None)
        elif ordered_by_time and resolved_entries:
            chosen = resolved_entries[0]

        if notes:
            lines.append("")
            lines.extend(f"ℹ️ {note}" for note in notes)

        if chosen is None:
            lines.extend([
                "",
                "No handoff generated: the registry does not report tag modification times, or the requested "
                "tag has no resolvable digest. Re-call with `tag='<tag>'` to choose one explicitly.",
            ])
            return "\n".join(lines)

        immutable_ref = f"{host}/{clean_img}@{chosen['digest']}"
        workload = clean_img.split("/")[-1]
        lines.extend([
            "",
            f"#### 🚀 Handoff to `k8s-mcp` Rollout (tag `{chosen['tag']}`):",
            "Use the resolved immutable digest to guarantee deterministic container deployment:",
            "```yaml",
            "spec:",
            "  containers:",
            f"  - name: {workload}",
            f"    image: \"{immutable_ref}\"",
            "```",
            "**Recommended k8s-mcp tool call** (returns a plan first; confirm after review):",
            "```python",
            "k8s_trigger_deployment_rollout(",
            "    namespace='<namespace>',",
            "    resource_type='deployment',",
            f"    resource_name='{workload}',",
            f"    image_tag='{immutable_ref}',",
            "    confirm=False,",
            ")",
            "```",
        ])
        return "\n".join(lines)

    async def _artifactory_docker_tags(
        self,
        client: httpx.AsyncClient,
        repo: str,
        image: str,
        wanted_tag: str,
        limit: int,
    ) -> tuple[list[dict[str, Any]], bool, list[str]]:
        notes: list[str] = []
        modified: dict[str, str] = {}
        aql_digests: dict[str, str] = {}

        aql_query = {
            "repo": repo,
            "path": {"$match": f"{image}/*"},
            "name": {"$in": ["manifest.json", "list.manifest.json"]},
        }
        aql = (
            f"items.find({json.dumps(aql_query)})"
            '.include("name", "path", "modified", "actual_sha256")'
        )
        aql_resp = await client.post("/api/search/aql", content=aql, headers={"Content-Type": "text/plain"})
        if aql_resp.status_code == 200:
            for item in aql_resp.json().get("results", []):
                item_path = item.get("path", "")
                if not item_path.startswith(f"{image}/"):
                    continue
                tag_name = item_path[len(image) + 1:]
                if "/" in tag_name or not tag_name:
                    continue
                # A multi-arch list manifest wins over the single-arch manifest for the same tag.
                if item.get("name") == "list.manifest.json" or tag_name not in modified:
                    modified[tag_name] = item.get("modified", "")
                    sha = item.get("actual_sha256", "")
                    if sha:
                        aql_digests[tag_name] = f"sha256:{sha}"

        tags: list[str] = []
        tags_resp = await client.get(f"/api/docker/{repo}/v2/{image}/tags/list")
        if tags_resp.status_code == 200:
            tags = list(tags_resp.json().get("tags") or [])
        elif modified:
            tags = list(modified)
            notes.append("Docker tags/list API unavailable; tags came from AQL manifest search.")

        if wanted_tag:
            tags = [t for t in tags if t == wanted_tag]

        ordered = bool(modified) and all(t in modified for t in tags)
        if ordered:
            tags.sort(key=lambda t: _parse_ts(modified.get(t)), reverse=True)
        else:
            notes.append("Tag modification times unavailable; tags are listed in registry order, not by age.")
        tags = tags[:limit]

        entries: list[dict[str, Any]] = []
        for tag_name in tags:
            head_resp = await client.head(
                f"/api/docker/{repo}/v2/{image}/manifests/{tag_name}",
                headers={"Accept": _DOCKER_MANIFEST_ACCEPT},
            )
            digest = head_resp.headers.get("Docker-Content-Digest", "") if head_resp.status_code == 200 else ""
            if not digest and tag_name in aql_digests:
                digest = aql_digests[tag_name]
            entries.append({"tag": tag_name, "digest": digest, "modified": modified.get(tag_name, "")})
        return entries, ordered, notes

    async def _nexus_docker_tags(
        self,
        client: httpx.AsyncClient,
        repo: str,
        image: str,
        wanted_tag: str,
        limit: int,
    ) -> tuple[list[dict[str, Any]], bool, list[str]]:
        notes: list[str] = []
        prefix = f"v2/{image}/manifests/"
        items, error = await _nexus_collect(
            client,
            "/service/rest/v1/search/assets",
            {"repository": repo, "format": "docker", "name": image},
        )
        if error:
            notes.append(f"Nexus asset search reported: {error}")

        by_tag: dict[str, dict[str, Any]] = {}
        for item in items:
            path_str = (item.get("path") or "").lstrip("/")
            if not path_str.startswith(prefix):
                continue
            tag_name = path_str[len(prefix):]
            if not tag_name or "/" in tag_name or tag_name.startswith("sha256:"):
                continue
            if wanted_tag and tag_name != wanted_tag:
                continue
            sha = (item.get("checksum") or {}).get("sha256", "")
            by_tag[tag_name] = {
                "tag": tag_name,
                "digest": f"sha256:{sha}" if sha else "",
                "modified": item.get("lastModified") or "",
            }

        entries = list(by_tag.values())
        ordered = bool(entries) and all(e["modified"] for e in entries)
        if ordered:
            entries.sort(key=lambda e: _parse_ts(e["modified"]), reverse=True)
        else:
            notes.append("Tag modification times unavailable; tags are listed in registry order, not by age.")
        return entries[:limit], ordered, notes

    async def verify_checksum_integrity(
        self,
        artifact_path_or_url: str,
        expected_sha256: str,
        session_name: str = "default",
    ) -> str:
        """
        Compare the SHA256 produced by CI with the SHA256 of the artifact stored at the given path.

        The registry's checksum metadata for that exact path is used. When it is missing, the
        artifact is streamed and hashed. A file elsewhere in the registry with the same checksum
        never counts as a match.
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        clean_expected = expected_sha256.strip().lower()
        if not _SHA256_HEX_RE.fullmatch(clean_expected):
            return f"❌ Invalid expected_sha256 '{expected_sha256}'. Must be a 64-character hexadecimal SHA256 string."

        rel = _relative_artifact_path(session, artifact_path_or_url)
        if "/" not in rel:
            return (
                f"❌ artifact_path_or_url must be '<repository>/<path/to/file>' or a full URL "
                f"(got '{artifact_path_or_url}')."
            )
        repo, item_path = rel.split("/", 1)

        client = session.client
        actual_sha256 = ""
        file_size: Optional[int] = None
        method = ""

        try:
            if session.registry_type == "artifactory":
                resp = await client.get(f"/api/storage/{repo}/{item_path}")
                if resp.status_code == 404:
                    return f"❌ Artifact not found in Artifactory: `{rel}`. Nothing was verified."
                if resp.status_code == 200:
                    data = resp.json()
                    actual_sha256 = (data.get("checksums") or {}).get("sha256", "")
                    file_size = int(data["size"]) if data.get("size") else None
                    method = "registry checksum metadata"
                download_path = f"/{repo}/{item_path}"
            else:  # nexus
                items, _ = await _nexus_collect(
                    client,
                    "/service/rest/v1/search/assets",
                    {"repository": repo, "sha256": clean_expected},
                    max_items=200,
                )
                for item in items:
                    if (item.get("path") or "").lstrip("/") == item_path:
                        actual_sha256 = (item.get("checksum") or {}).get("sha256", "")
                        file_size = item.get("fileSize")
                        method = "registry checksum metadata"
                        break
                download_path = f"/repository/{repo}/{item_path}"

            if not actual_sha256:
                digest, size, status = await _stream_sha256(client, download_path)
                if status == 404:
                    return (
                        f"❌ Artifact not found in {session.registry_type.capitalize()}: `{rel}`. "
                        f"Nothing was verified."
                    )
                if digest is None:
                    return (
                        f"❌ Checksum resolution failed for `{rel}` (HTTP {status}). "
                        f"Verify the repository, path, and read permissions."
                    )
                actual_sha256, file_size, method = digest, size, "downloaded and hashed"

        except Exception as exc:
            return f"❌ Error retrieving remote checksum: {type(exc).__name__}: {str(exc)}"

        actual_sha256 = actual_sha256.strip().lower()
        if clean_expected == actual_sha256:
            return (
                f"✅ **ATTESTATION PASSED: Checksum Integrity Verified**\n\n"
                f"  • **Artifact Path**: `{rel}`\n"
                f"  • **Registry**: {session.registry_type.capitalize()} ({session.base_url})\n"
                f"  • **Expected SHA256**: `{clean_expected}`\n"
                f"  • **Registry SHA256**: `{actual_sha256}`\n"
                f"  • **File Size**: {format_bytes(file_size)}\n"
                f"  • **Verification Method**: {method}\n"
                f"  • **Verification Verdict**: **MATCH**\n\n"
                f"🎉 **Proceed with Kubernetes deployment via `k8s-mcp`**."
            )
        return (
            f"🛑 **ATTESTATION FAILED: Checksum Integrity Mismatch!**\n\n"
            f"  • **Artifact Path**: `{rel}`\n"
            f"  • **Registry**: {session.registry_type.capitalize()} ({session.base_url})\n"
            f"  • **Expected SHA256 (from CI build)**: `{clean_expected}`\n"
            f"  • **Actual Stored SHA256 (in registry)**: `{actual_sha256}`\n"
            f"  • **Verification Method**: {method}\n"
            f"  • **Verification Verdict**: **MISMATCH (wrong build, corruption, or tampering)**\n\n"
            f"⚠️ **ABORT DEPLOYMENT: Do NOT deploy this artifact to Kubernetes/OpenShift cluster!**"
        )

    async def upload_binary(
        self,
        repository: str,
        local_file_path: str,
        target_path: str,
        maven_coords: dict[str, str] | None = None,
        confirm: bool = False,
        session_name: str = "default",
    ) -> str:
        """
        Confirmation-Gated Mutating Tool:
        Computes local SHA256, streams the build artifact to Nexus or Artifactory,
        and verifies the remote checksum.
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        local_path = Path(local_file_path)
        if not local_path.is_file():
            return f"❌ Local file does not exist: '{local_file_path}'"

        checksums = calculate_file_checksums(local_path)
        local_sha256 = checksums["sha256"]
        file_size = local_path.stat().st_size
        target_clean = target_path.strip().lstrip("/")
        repo_clean = repository.strip().strip("/")

        if not confirm:
            preview = (
                f"🔒 **Confirmation Required: Binary Upload**\n\n"
                f"  • **Action**: Upload binary to artifact registry\n"
                f"  • **Registry**: {session.registry_type.capitalize()} ({session.base_url})\n"
                f"  • **Target Repository**: `{repo_clean}`\n"
                f"  • **Target Path**: `{target_clean}`\n"
                f"  • **Source File**: `{local_path.resolve()}`\n"
                f"  • **File Size**: {format_bytes(file_size)} ({file_size} bytes)\n"
                f"  • **Local SHA256**: `{local_sha256}`\n"
            )
            if maven_coords:
                preview += f"  • **Maven Coordinates**: {json.dumps(maven_coords)}\n"
            preview += (
                f"\n⚠️ This is a mutating supply-chain action. Re-call with `confirm=true` to upload."
            )
            return preview

        client = session.client
        t0 = time.perf_counter()
        verify_path = f"{repo_clean}/{target_clean}"

        try:
            if session.registry_type == "artifactory":
                headers = {
                    "X-Checksum-Sha256": local_sha256,
                    "X-Checksum-Sha1": checksums["sha1"],
                    "X-Checksum-Md5": checksums["md5"],
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(file_size),
                }
                resp = await client.put(
                    f"/{repo_clean}/{target_clean}",
                    content=_aiter_file(local_path),
                    headers=headers,
                )
                if resp.status_code not in (200, 201):
                    return f"❌ Artifactory upload failed (HTTP {resp.status_code}): {resp.text[:300]}"

            else:  # nexus
                if maven_coords:
                    group_id = maven_coords.get("groupId", "")
                    artifact_id = maven_coords.get("artifactId", "")
                    version = maven_coords.get("version", "")
                    if not (group_id and artifact_id and version):
                        return "❌ maven_coords needs groupId, artifactId, and version for a Nexus component upload."
                    extension = maven_coords.get("packaging") or local_path.suffix.lstrip(".") or "jar"
                    form_data = {
                        "maven2.groupId": group_id,
                        "maven2.artifactId": artifact_id,
                        "maven2.version": version,
                        "maven2.asset1.extension": extension,
                    }
                    if maven_coords.get("classifier"):
                        form_data["maven2.asset1.classifier"] = maven_coords["classifier"]
                    with open(local_path, "rb") as fh:
                        resp = await client.post(
                            "/service/rest/v1/components",
                            params={"repository": repo_clean},
                            data=form_data,
                            files={"maven2.asset1": (local_path.name, fh, "application/octet-stream")},
                        )
                    if resp.status_code not in (200, 201, 204):
                        return f"❌ Nexus component upload failed (HTTP {resp.status_code}): {resp.text[:300]}"
                    classifier = f"-{maven_coords['classifier']}" if maven_coords.get("classifier") else ""
                    verify_path = (
                        f"{repo_clean}/{group_id.replace('.', '/')}/{artifact_id}/{version}/"
                        f"{artifact_id}-{version}{classifier}.{extension}"
                    )
                else:
                    resp = await client.put(
                        f"/repository/{repo_clean}/{target_clean}",
                        content=_aiter_file(local_path),
                        headers={"Content-Type": "application/octet-stream", "Content-Length": str(file_size)},
                    )
                    if resp.status_code not in (200, 201, 204):
                        return f"❌ Nexus direct upload failed (HTTP {resp.status_code}): {resp.text[:300]}"

            duration_s = time.perf_counter() - t0

            verify_result = await self.verify_checksum_integrity(
                artifact_path_or_url=verify_path,
                expected_sha256=local_sha256,
                session_name=session_name,
            )
            verified = "ATTESTATION PASSED" in verify_result
            header = (
                "✅ **Binary Upload Successful and Verified!**"
                if verified
                else "⚠️ **Upload request accepted, but post-upload verification did NOT pass.**"
            )
            return (
                f"{header}\n\n"
                f"  • **Repository**: `{repo_clean}`\n"
                f"  • **Stored Path**: `{verify_path}`\n"
                f"  • **Registry**: {session.registry_type.capitalize()} ({session.base_url})\n"
                f"  • **Uploaded Size**: {format_bytes(file_size)}\n"
                f"  • **Upload Duration**: {duration_s:.2f} seconds\n"
                f"  • **Local SHA256**: `{local_sha256}`\n\n"
                f"#### Post-Upload Integrity Verification:\n"
                f"{verify_result}"
            )

        except Exception as exc:
            return f"❌ Failed to upload binary: {type(exc).__name__}: {str(exc)}"

    async def promote_release(
        self,
        source_repo: str,
        target_repo: str,
        artifact_or_build_name: str,
        version: str,
        confirm: bool = False,
        session_name: str = "default",
    ) -> str:
        """
        Confirmation-Gated Mutating Tool:
        Copies exactly one version of a component from a staging repository to a release
        repository without rebuilding. Nothing outside that version is touched.
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        src_repo = source_repo.strip().strip("/")
        tgt_repo = target_repo.strip().strip("/")
        name = artifact_or_build_name.strip().strip("/")
        ver = version.strip().strip("/")
        if not (src_repo and tgt_repo and name and ver):
            return "❌ source_repo, target_repo, artifact_or_build_name, and version are all required."
        if src_repo == tgt_repo:
            return "❌ source_repo and target_repo must differ."

        if not confirm:
            return (
                f"🔒 **Confirmation Required: Artifact Release Promotion**\n\n"
                f"  • **Action**: Promote artifact from staging to release\n"
                f"  • **Registry**: {session.registry_type.capitalize()} ({session.base_url})\n"
                f"  • **Source Repository (Staging)**: `{src_repo}`\n"
                f"  • **Target Repository (Production)**: `{tgt_repo}`\n"
                f"  • **Artifact / Build**: `{name}`\n"
                f"  • **Version**: `{ver}` (only this version is copied)\n\n"
                f"⚠️ This is a mutating promotion action. Re-call with `confirm=true` to execute."
            )

        client = session.client
        t0 = time.perf_counter()

        try:
            if session.registry_type == "artifactory":
                copied, detail = await self._artifactory_promote(client, src_repo, tgt_repo, name, ver)
            else:
                copied, detail = await self._nexus_promote(client, src_repo, tgt_repo, name, ver)
        except Exception as exc:
            return f"❌ Error executing artifact promotion: {type(exc).__name__}: {str(exc)}"

        if not copied:
            return detail

        duration_s = time.perf_counter() - t0
        return (
            f"✅ **Artifact Promotion Completed Successfully!**\n\n"
            f"  • **Source Repository**: `{src_repo}` (Staging)\n"
            f"  • **Destination Repository**: `{tgt_repo}` (Production Release)\n"
            f"  • **Promoted Artifact**: `{name}`\n"
            f"  • **Promoted Version**: `{ver}`\n"
            f"  • **Registry**: {session.registry_type.capitalize()} ({session.base_url})\n"
            f"  • **Promotion Duration**: {duration_s:.2f} seconds\n"
            f"{detail}\n\n"
            f"🚀 **Next Step**: Hand off version `{ver}` to `k8s-mcp` for deployment to production cluster."
        )

    async def _artifactory_promote(
        self, client: httpx.AsyncClient, src_repo: str, tgt_repo: str, name: str, ver: str
    ) -> tuple[bool, str]:
        item = f"{name}/{ver}"
        storage = await client.get(f"/api/storage/{src_repo}/{item}")
        if storage.status_code != 200:
            return False, (
                f"❌ `{src_repo}/{item}` was not found (HTTP {storage.status_code}). Nothing was copied.\n"
                f"For Maven layouts pass the full path as artifact_or_build_name, e.g. 'com/corp/{name.split('/')[-1]}'."
            )

        copy_path = f"/api/copy/{src_repo}/{item}"
        params = {"to": f"/{tgt_repo}/{item}"}
        dry = await client.post(copy_path, params={**params, "dry": "1"})
        problem = _artifactory_copy_problem(dry)
        if problem:
            return False, f"❌ Artifactory promotion dry run failed — nothing was copied.\n{problem}"

        resp = await client.post(copy_path, params={**params, "dry": "0"})
        problem = _artifactory_copy_problem(resp)
        if problem:
            return False, f"❌ Artifactory promotion copy failed.\n{problem}"
        return True, f"  • **Copied Path**: `{src_repo}/{item}` → `{tgt_repo}/{item}`"

    async def _nexus_promote(
        self, client: httpx.AsyncClient, src_repo: str, tgt_repo: str, name: str, ver: str
    ) -> tuple[bool, str]:
        params: dict[str, str] = {"repository": src_repo, "version": ver}
        parts = name.split("/")
        params["name"] = parts[-1]
        if len(parts) > 1:
            params["group"] = ".".join(parts[:-1])
        components, error = await _nexus_collect(client, "/service/rest/v1/search", params)
        if error and not components:
            return False, f"❌ Nexus search failed: {error}. Nothing was copied."
        components = [c for c in components if c.get("version") == ver and c.get("name") == parts[-1]]
        if not components:
            return False, f"❌ Component '{name}' version '{ver}' not found in Nexus repository '{src_repo}'. Nothing was copied."

        copied: list[str] = []
        failures: list[str] = []
        for component in components:
            for asset in component.get("assets") or []:
                asset_path = (asset.get("path") or "").lstrip("/")
                if not asset_path or asset_path.endswith(_CHECKSUM_SIDECARS):
                    continue
                expected = (asset.get("checksum") or {}).get("sha256", "").lower()
                with tempfile.TemporaryFile() as buffer:
                    digest, _, status = await _stream_sha256(
                        client, asset.get("downloadUrl") or f"/repository/{src_repo}/{asset_path}", sink=buffer
                    )
                    if digest is None:
                        failures.append(f"{asset_path}: download failed (HTTP {status})")
                        continue
                    if expected and digest != expected:
                        failures.append(f"{asset_path}: downloaded SHA256 does not match the source checksum")
                        continue
                    buffer.seek(0)
                    put = await client.put(
                        f"/repository/{tgt_repo}/{asset_path}",
                        content=_aiter_fileobj(buffer),
                        headers={"Content-Type": "application/octet-stream"},
                    )
                if put.status_code in (200, 201, 204):
                    copied.append(asset_path)
                else:
                    failures.append(f"{asset_path}: upload failed (HTTP {put.status_code}) {put.text[:150]}")

        if failures:
            lines = [
                f"❌ Nexus promotion incomplete: {len(copied)} asset(s) copied, {len(failures)} failed.",
                *(f"  • {f}" for f in failures[:20]),
            ]
            if copied:
                lines.append("Copied before the failure: " + ", ".join(f"`{p}`" for p in copied[:20]))
            return False, "\n".join(lines)
        if not copied:
            return False, f"❌ Component '{name}' version '{ver}' has no assets to copy."
        listing = "\n".join(f"    - `{p}`" for p in copied[:25])
        more = f"\n    - … and {len(copied) - 25} more" if len(copied) > 25 else ""
        return True, f"  • **Assets Copied ({len(copied)})**:\n{listing}{more}"

    async def cleanup_old_snapshots(
        self,
        repository: str,
        component_name: str,
        keep_latest_n: int = 5,
        dry_run: bool = True,
        confirm: bool = False,
        session_name: str = "default",
    ) -> str:
        """
        Confirmation-Gated Mutating Tool:
        Prunes old SNAPSHOT versions of one component. Release versions are never selected,
        and retention counts versions (not individual files).
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        repo = repository.strip().strip("/")
        comp = component_name.strip().strip("/")
        if not repo or not comp:
            return "❌ repository and component_name are required."
        try:
            keep = int(keep_latest_n)
        except (TypeError, ValueError):
            return "❌ keep_latest_n must be an integer."
        if keep < 1:
            return "❌ keep_latest_n must be at least 1 so the newest snapshot is always retained."

        client = session.client
        try:
            if session.registry_type == "nexus":
                versions = await self._nexus_snapshot_versions(client, repo, comp)
            else:
                versions = await self._artifactory_snapshot_versions(client, repo, comp)
        except Exception as exc:
            return f"❌ Error searching for snapshot components: {type(exc).__name__}: {str(exc)}"

        if not versions:
            return (
                f"No SNAPSHOT versions found for component '{comp}' in repository '{repo}'. "
                f"Release versions are never pruned by this tool."
            )

        versions.sort(key=lambda v: v["ts"], reverse=True)
        keep_list = versions[:keep]
        delete_list = versions[keep:]
        reclaimable_bytes = sum(v["size"] for v in delete_list)

        def describe(v: dict[str, Any]) -> str:
            return f"`{v['version']}` ({v['files']} file(s), {format_bytes(v['size'])}, modified {v['modified'] or '?'})"

        if dry_run:
            lines = [
                f"### 🔍 Safe Snapshot Cleanup Simulation (`dry_run=True`)\n",
                f"  • **Repository**: `{repo}`",
                f"  • **Component**: `{comp}`",
                f"  • **Keep Latest Versions**: `{keep}`",
                f"  • **Snapshot Versions Found**: {len(versions)}",
                f"  • **Versions to Retain**: {len(keep_list)}",
                f"  • **Versions Marked for Pruning**: {len(delete_list)}",
                f"  • **Estimated Reclaimable Space**: **{format_bytes(reclaimable_bytes)}**\n",
                "#### 🛡️ Retained Snapshot Versions (Newest):",
            ]
            lines.extend(f"  • {describe(v)} — *Retained*" for v in keep_list)
            if delete_list:
                lines.append("\n#### 🗑️ Stale Snapshot Versions Scheduled for Deletion:")
                lines.extend(f"  • {describe(v)} — *Stale*" for v in delete_list[:20])
                if len(delete_list) > 20:
                    lines.append(f"    *(and {len(delete_list) - 20} more stale versions)*")
            lines.extend([
                "",
                "ℹ️ **No files were deleted** because `dry_run=True`.",
                "To execute permanent pruning, re-call with `dry_run=false` and `confirm=true`.",
            ])
            return "\n".join(lines)

        if not delete_list:
            return f"✅ Nothing to prune: {len(versions)} snapshot version(s) found, keeping up to {keep}."

        if not confirm:
            return (
                f"🔒 **Confirmation Required: Permanent Snapshot Deletion**\n\n"
                f"  • **Action**: Prune {len(delete_list)} stale snapshot version(s)\n"
                f"  • **Repository**: `{repo}`\n"
                f"  • **Component**: `{comp}`\n"
                f"  • **Versions**: {', '.join(v['version'] for v in delete_list[:20])}\n"
                f"  • **Space to be permanently freed**: {format_bytes(reclaimable_bytes)}\n\n"
                f"⚠️ This is a DESTRUCTIVE action. Re-call with `dry_run=false` AND `confirm=true` to execute."
            )

        deleted: list[str] = []
        failures: list[str] = []
        try:
            for v in delete_list:
                for target in v["delete_targets"]:
                    del_resp = await client.delete(target)
                    if del_resp.status_code not in (200, 202, 204):
                        failures.append(f"{v['version']}: HTTP {del_resp.status_code} for {target}")
                        break
                else:
                    deleted.append(v["version"])
        except Exception as exc:
            return (
                f"❌ Error during snapshot deletion after {len(deleted)} version(s): "
                f"{type(exc).__name__}: {str(exc)}"
            )

        lines = [
            "✅ **Snapshot Pruning Completed!**" if not failures else "⚠️ **Snapshot Pruning Partially Completed**",
            "",
            f"  • **Repository**: `{repo}`",
            f"  • **Component**: `{comp}`",
            f"  • **Versions Deleted**: {len(deleted)} / {len(delete_list)}",
            f"  • **Disk Space Reclaimed**: ~{format_bytes(sum(v['size'] for v in delete_list if v['version'] in deleted))}",
            f"  • **Versions Retained**: {len(keep_list)}",
        ]
        if failures:
            lines.append("  • **Failures**:")
            lines.extend(f"    - {f}" for f in failures[:20])
        return "\n".join(lines)

    async def _nexus_snapshot_versions(
        self, client: httpx.AsyncClient, repo: str, comp: str
    ) -> list[dict[str, Any]]:
        components, error = await _nexus_collect(
            client, "/service/rest/v1/search", {"repository": repo, "name": comp}
        )
        if error and not components:
            raise RuntimeError(error)
        versions: list[dict[str, Any]] = []
        for component in components:
            version = component.get("version") or ""
            if component.get("name") != comp or not is_snapshot_version(version):
                continue
            assets = component.get("assets") or []
            stamps = [a.get("lastModified") or a.get("blobCreated") or "" for a in assets]
            newest = max(stamps, key=_parse_ts, default="")
            versions.append({
                "version": version,
                "files": len(assets),
                "size": sum(int(a.get("fileSize") or 0) for a in assets),
                "modified": newest,
                "ts": _parse_ts(newest),
                "delete_targets": [f"/service/rest/v1/components/{component['id']}"] if component.get("id") else [],
            })
        return [v for v in versions if v["delete_targets"]]

    async def _artifactory_snapshot_versions(
        self, client: httpx.AsyncClient, repo: str, comp: str
    ) -> list[dict[str, Any]]:
        query = {
            "repo": repo,
            "type": "file",
            "$or": [
                {"path": {"$match": f"{comp}/*"}},
                {"path": {"$match": f"*/{comp}/*"}},
            ],
        }
        aql = (
            f"items.find({json.dumps(query)})"
            '.include("name", "repo", "path", "size", "created", "modified").limit(50000)'
        )
        resp = await client.post("/api/search/aql", content=aql, headers={"Content-Type": "text/plain"})
        if resp.status_code != 200:
            raise RuntimeError(f"AQL search failed (HTTP {resp.status_code}): {resp.text[:200]}")

        groups: dict[str, dict[str, Any]] = {}
        for item in resp.json().get("results", []):
            folder = (item.get("path") or "").strip("/")
            segments = folder.split("/")
            if len(segments) < 2 or segments[-2] != comp:
                continue
            version = segments[-1]
            if not is_snapshot_version(version):
                continue
            stamp = item.get("modified") or item.get("created") or ""
            group = groups.setdefault(folder, {
                "version": version,
                "files": 0,
                "size": 0,
                "modified": "",
                "ts": 0.0,
                "delete_targets": [f"/{repo}/{folder}"],
            })
            group["files"] += 1
            group["size"] += int(item.get("size") or 0)
            if _parse_ts(stamp) >= group["ts"]:
                group["ts"] = _parse_ts(stamp)
                group["modified"] = stamp
        return list(groups.values())


# ============================================================
# Module helpers
# ============================================================

_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_SNAPSHOT_TIMESTAMP_RE = re.compile(r"-\d{8}\.\d{6}-\d+$")
_CHECKSUM_SIDECARS = (".md5", ".sha1", ".sha256", ".sha512", ".asc")
_DOCKER_MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
_STREAM_CHUNK = 1024 * 1024


def is_snapshot_version(version: str) -> bool:
    """True for Maven snapshot versions: 1.0-SNAPSHOT or a timestamped 1.0-20240101.120000-3."""
    value = (version or "").strip()
    return "SNAPSHOT" in value.upper() or bool(_SNAPSHOT_TIMESTAMP_RE.search(value))


def _parse_ts(value: Any) -> float:
    """Parse an ISO-8601 timestamp from Nexus or Artifactory into epoch seconds (0.0 if unknown)."""
    from datetime import datetime, timezone

    text = str(value or "").strip()
    if not text:
        return 0.0
    text = text.replace("Z", "+00:00")
    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", text)
    if match:
        fraction = (match.group(2) or "")[:7].ljust(7, "0") if match.group(2) else ""
        offset = match.group(3) or ""
        if re.fullmatch(r"[+-]\d{4}", offset):
            offset = f"{offset[:3]}:{offset[3:]}"
        text = f"{match.group(1)}{fraction}{offset}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _relative_artifact_path(session: ArtifactSession, target: str) -> str:
    """Turn a full URL or '/repo/path' into 'repo/path' for the session's registry."""
    value = (target or "").strip()
    base = session.base_url.rstrip("/")
    if value.startswith(base):
        value = value[len(base):]
    elif "://" in value:
        value = "/" + value.split("://", 1)[1].split("/", 1)[-1]
    value = value.lstrip("/")
    if session.registry_type == "nexus" and value.startswith("repository/"):
        value = value[len("repository/"):]
    if session.registry_type == "artifactory" and value.startswith("api/storage/"):
        value = value[len("api/storage/"):]
    return value


def _docker_registry_host(session: ArtifactSession, repo: str, registry_host: str) -> tuple[str, str]:
    """Pick the host used in image references. Explicit argument, then env, then a derived guess."""
    explicit = (registry_host or os.environ.get("ARTIFACT_DOCKER_REGISTRY", "")).strip()
    if explicit:
        return explicit.split("://")[-1].rstrip("/"), ""
    host = session.base_url.split("://")[-1].split("/")[0]
    if session.registry_type == "artifactory":
        return f"{host}/{repo}", (
            f"Image host derived as `{host}/{repo}` (Artifactory repository-path method). "
            "Pass registry_host or set ARTIFACT_DOCKER_REGISTRY if you use the subdomain or port method."
        )
    return host, (
        f"Image host derived as `{host}` from the Nexus URL. Nexus Docker repositories usually listen on their "
        "own connector host or port; pass registry_host or set ARTIFACT_DOCKER_REGISTRY to be exact."
    )


async def _nexus_collect(
    client: httpx.AsyncClient,
    path: str,
    params: dict[str, Any],
    max_items: int = 5000,
) -> tuple[list[dict[str, Any]], Optional[str]]:
    """Follow Nexus continuationToken pagination. Returns (items, error)."""
    items: list[dict[str, Any]] = []
    token: Optional[str] = None
    for _ in range(200):
        query = dict(params)
        if token:
            query["continuationToken"] = token
        resp = await client.get(path, params=query)
        if resp.status_code != 200:
            return items, f"HTTP {resp.status_code}: {resp.text[:200]}"
        data = resp.json()
        items.extend(data.get("items") or [])
        token = data.get("continuationToken")
        if not token or len(items) >= max_items:
            break
    return items[:max_items], None


async def _stream_sha256(
    client: httpx.AsyncClient,
    url: str,
    sink: Any = None,
) -> tuple[Optional[str], Optional[int], int]:
    """Stream a download, hashing it (and optionally writing it to `sink`). Returns (sha256, size, status)."""
    digest = hashlib.sha256()
    size = 0
    async with client.stream("GET", url) as resp:
        if resp.status_code != 200:
            return None, None, resp.status_code
        async for chunk in resp.aiter_bytes(_STREAM_CHUNK):
            digest.update(chunk)
            size += len(chunk)
            if sink is not None:
                sink.write(chunk)
        return digest.hexdigest(), size, resp.status_code


async def _aiter_file(path: Path):
    """Yield a local file in chunks so large artifacts are never fully loaded into memory."""
    with open(path, "rb") as fh:
        async for chunk in _aiter_fileobj(fh):
            yield chunk


async def _aiter_fileobj(fh: Any):
    while True:
        chunk = fh.read(_STREAM_CHUNK)
        if not chunk:
            break
        yield chunk


def _artifactory_copy_problem(resp: httpx.Response) -> str:
    """Return a readable problem description for a failed /api/copy call, or '' on success."""
    messages: list[dict[str, Any]] = []
    try:
        messages = list((resp.json() or {}).get("messages") or [])
    except Exception:
        pass
    errors = [m.get("message", "") for m in messages if str(m.get("level", "")).upper() == "ERROR"]
    if resp.status_code not in (200, 201) or errors:
        detail = "\n".join(f"  • {e}" for e in errors[:10]) or f"  • {resp.text[:300]}"
        return f"HTTP {resp.status_code}:\n{detail}"
    return ""
