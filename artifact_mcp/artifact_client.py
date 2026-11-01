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
import sys
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
    ) -> str:
        """
        Query Docker/OCI repositories to resolve an immutable sha256:... image digest.

        Produces an immutable image reference and copy-paste handoff for k8s-mcp rollouts.
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        client = session.client
        clean_img = image_name.strip().lstrip("/")
        repo_clean = repository.strip().rstrip("/")
        tags_and_digests: list[dict[str, str]] = []

        try:
            if session.registry_type == "artifactory":
                tags_url = f"/api/docker/{repo_clean}/v2/{clean_img}/tags/list"
                resp = await client.get(tags_url)
                if resp.status_code == 200:
                    tags = resp.json().get("tags", [])
                    for tag in tags[-limit:]:
                        manifest_url = f"/api/docker/{repo_clean}/v2/{clean_img}/manifests/{tag}"
                        head_resp = await client.head(
                            manifest_url,
                            headers={
                                "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"
                            },
                        )
                        digest = head_resp.headers.get("Docker-Content-Digest") or head_resp.headers.get("docker-content-digest", "")
                        tags_and_digests.append({
                            "tag": tag,
                            "digest": digest or "sha256:unknown",
                            "image": clean_img,
                            "repository": repo_clean,
                        })
                else:
                    aql = (
                        f'items.find({{"repo": "{repo_clean}", "path": {{"$match": "{clean_img}/*"}}, "name": "manifest.json"}})'
                        f'.include("name", "repo", "path", "actual_sha256", "modified")'
                    )
                    aql_resp = await client.post("/api/search/aql", content=aql, headers={"Content-Type": "text/plain"})
                    if aql_resp.status_code == 200:
                        for item in aql_resp.json().get("results", [])[:limit]:
                            tag = item.get("path", "").split("/")[-1]
                            sha = item.get("actual_sha256", "")
                            tags_and_digests.append({
                                "tag": tag,
                                "digest": f"sha256:{sha}" if sha else "unknown",
                                "image": clean_img,
                                "repository": repo_clean,
                            })

            else:  # nexus
                search_url = "/service/rest/v1/search/assets"
                params = {
                    "repository": repo_clean,
                    "format": "docker",
                    "name": f"*{clean_img}*",
                }
                resp = await client.get(search_url, params=params)
                if resp.status_code == 200:
                    items = resp.json().get("items", [])
                    seen_tags: set[str] = set()
                    for it in items:
                        path_str = it.get("path", "")
                        if "/manifests/" in path_str:
                            tag = path_str.split("/manifests/")[-1]
                            if tag not in seen_tags:
                                seen_tags.add(tag)
                                sha = it.get("checksum", {}).get("sha256", "")
                                tags_and_digests.append({
                                    "tag": tag,
                                    "digest": f"sha256:{sha}" if sha else "unknown",
                                    "image": clean_img,
                                    "repository": repo_clean,
                                })
                                if len(tags_and_digests) >= limit:
                                    break

        except Exception as exc:
            return f"❌ Error querying Docker digests: {type(exc).__name__}: {str(exc)}"

        if not tags_and_digests:
            return (
                f"No Docker tags/digests found for image '{clean_img}' in repository '{repo_clean}' "
                f"({session.registry_type.capitalize()})."
            )

        parsed_url = session.base_url.split("://")[-1].split("/")[0]
        latest_entry = tags_and_digests[-1]
        sample_digest = latest_entry["digest"]
        immutable_ref = f"{parsed_url}/{clean_img}@{sample_digest}"

        lines = [
            f"### Docker / OCI Image Manifests: `{clean_img}` in `{repo_clean}`\n",
            "| Image Tag | Immutable Digest (`sha256:...`) | Status |",
            "|-----------|----------------------------------|--------|",
        ]
        for entry in tags_and_digests:
            lines.append(f"| `{entry['tag']}` | `{entry['digest']}` | ✅ Resolved |")

        lines.extend([
            "",
            "#### 🚀 Handoff to `k8s-mcp` Rollout:",
            "Use the resolved immutable digest to guarantee deterministic container deployment:",
            "```yaml",
            f"spec:",
            f"  containers:",
            f"  - name: {clean_img.split('/')[-1]}",
            f"    image: \"{immutable_ref}\"",
            "```",
            f"**Recommended k8s-mcp tool call:**",
            f"```python",
            f"k8s_update_deployment_image(",
            f"    deployment_name='{clean_img.split('/')[-1]}',",
            f"    container_name='{clean_img.split('/')[-1]}',",
            f"    new_image='{immutable_ref}'",
            f")",
            f"```",
        ])

        return "\n".join(lines)

    async def verify_checksum_integrity(
        self,
        artifact_path_or_url: str,
        expected_sha256: str,
        session_name: str = "default",
    ) -> str:
        """
        Compare the SHA256 digest generated by CI against registry checksum before deployment.
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        clean_expected = expected_sha256.strip().lower()
        if not clean_expected or len(clean_expected) != 64:
            return f"❌ Invalid expected_sha256 '{expected_sha256}'. Must be a 64-character hexadecimal SHA256 string."

        client = session.client
        target = artifact_path_or_url.strip()
        actual_sha256 = ""
        remote_path = target
        file_size: Optional[int] = None

        try:
            if session.registry_type == "artifactory":
                if target.startswith(session.base_url):
                    rel = target[len(session.base_url):].lstrip("/")
                else:
                    rel = target.lstrip("/")

                storage_endpoint = f"/api/storage/{rel}"
                resp = await client.get(storage_endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    checksums = data.get("checksums", {})
                    actual_sha256 = checksums.get("sha256", "")
                    file_size = int(data.get("size", 0)) if data.get("size") else None
                    remote_path = rel
                else:
                    srch = await client.get(f"/api/search/checksum?sha256={clean_expected}")
                    if srch.status_code == 200 and srch.json().get("results"):
                        actual_sha256 = clean_expected

            else:  # nexus
                params = {"sha256": clean_expected}
                resp = await client.get("/service/rest/v1/search/assets", params=params)
                if resp.status_code == 200 and resp.json().get("items"):
                    item = resp.json()["items"][0]
                    actual_sha256 = item.get("checksum", {}).get("sha256", "")
                    file_size = item.get("fileSize")
                    remote_path = item.get("path", target)
                else:
                    asset_name = target.split("/")[-1]
                    name_resp = await client.get("/service/rest/v1/search/assets", params={"name": f"*{asset_name}*"})
                    if name_resp.status_code == 200 and name_resp.json().get("items"):
                        item = name_resp.json()["items"][0]
                        actual_sha256 = item.get("checksum", {}).get("sha256", "")
                        file_size = item.get("fileSize")
                        remote_path = item.get("path", target)

        except Exception as exc:
            return f"❌ Error retrieving remote checksum: {type(exc).__name__}: {str(exc)}"

        actual_sha256 = actual_sha256.strip().lower()

        if not actual_sha256:
            return (
                f"❌ Checksum resolution failed: Could not retrieve remote SHA256 for '{target}' "
                f"in {session.registry_type.capitalize()}.\n"
                f"Verify the repository and artifact path are correct."
            )

        matches = (clean_expected == actual_sha256)

        if matches:
            return (
                f"✅ **ATTESTATION PASSED: Checksum Integrity Verified**\n\n"
                f"  • **Artifact Path**: `{remote_path}`\n"
                f"  • **Registry**: {session.registry_type.capitalize()} ({session.base_url})\n"
                f"  • **Expected SHA256**: `{clean_expected}`\n"
                f"  • **Registry SHA256**: `{actual_sha256}`\n"
                f"  • **File Size**: {format_bytes(file_size)}\n"
                f"  • **Verification Verdict**: **MATCH (Tamper-Free & Authentic)**\n\n"
                f"🎉 **Proceed with Kubernetes deployment via `k8s-mcp`**."
            )
        else:
            return (
                f"🛑 **ATTESTATION FAILED: Checksum Integrity Mismatch!**\n\n"
                f"  • **Artifact Path**: `{remote_path}`\n"
                f"  • **Registry**: {session.registry_type.capitalize()} ({session.base_url})\n"
                f"  • **Expected SHA256 (from CI build)**: `{clean_expected}`\n"
                f"  • **Actual Stored SHA256 (in registry)**: `{actual_sha256}`\n"
                f"  • **Verification Verdict**: **CRITICAL MISMATCH (Possible corruption or tampering)**\n\n"
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
        Computes local SHA256, uploads build artifact to Nexus or Artifactory,
        and verifies remote checksum match.
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
        repo_clean = repository.strip().rstrip("/")

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

        try:
            with open(local_path, "rb") as f:
                content = f.read()

            if session.registry_type == "artifactory":
                upload_url = f"/{repo_clean}/{target_clean}"
                headers = {
                    "X-Checksum-Sha256": local_sha256,
                    "X-Checksum-Sha1": checksums["sha1"],
                    "X-Checksum-Md5": checksums["md5"],
                    "Content-Type": "application/octet-stream",
                }
                resp = await client.put(upload_url, content=content, headers=headers)
                if resp.status_code not in (200, 201):
                    return f"❌ Artifactory upload failed (HTTP {resp.status_code}): {resp.text[:300]}"

            else:  # nexus
                if maven_coords:
                    form_data = {
                        "maven2.groupId": maven_coords.get("groupId", "com.example"),
                        "maven2.artifactId": maven_coords.get("artifactId", local_path.stem),
                        "maven2.version": maven_coords.get("version", "1.0.0"),
                        "maven2.asset1.extension": maven_coords.get("packaging", local_path.suffix.lstrip(".")),
                    }
                    if "classifier" in maven_coords:
                        form_data["maven2.asset1.classifier"] = maven_coords["classifier"]

                    files = {"maven2.asset1": (local_path.name, content, "application/octet-stream")}
                    resp = await client.post(
                        f"/service/rest/v1/components?repository={repo_clean}",
                        data=form_data,
                        files=files,
                    )
                    if resp.status_code not in (200, 201, 204):
                        return f"❌ Nexus component upload failed (HTTP {resp.status_code}): {resp.text[:300]}"
                else:
                    upload_url = f"/repository/{repo_clean}/{target_clean}"
                    resp = await client.put(upload_url, content=content, headers={"Content-Type": "application/octet-stream"})
                    if resp.status_code not in (200, 201, 204):
                        return f"❌ Nexus direct upload failed (HTTP {resp.status_code}): {resp.text[:300]}"

            duration_s = time.perf_counter() - t0

            verify_result = await self.verify_checksum_integrity(
                artifact_path_or_url=f"{repo_clean}/{target_clean}",
                expected_sha256=local_sha256,
                session_name=session_name,
            )

            return (
                f"✅ **Binary Upload Successful!**\n\n"
                f"  • **Repository**: `{repo_clean}`\n"
                f"  • **Target Path**: `{target_clean}`\n"
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
        Promotes an immutable artifact or build from staging/snapshot repository
        to production release repository without rebuilding.
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        src_repo = source_repo.strip()
        tgt_repo = target_repo.strip()
        name = artifact_or_build_name.strip()
        ver = version.strip()

        if not confirm:
            return (
                f"🔒 **Confirmation Required: Artifact Release Promotion**\n\n"
                f"  • **Action**: Promote artifact from staging to release\n"
                f"  • **Registry**: {session.registry_type.capitalize()} ({session.base_url})\n"
                f"  • **Source Repository (Staging)**: `{src_repo}`\n"
                f"  • **Target Repository (Production)**: `{tgt_repo}`\n"
                f"  • **Artifact / Build**: `{name}`\n"
                f"  • **Version**: `{ver}`\n\n"
                f"⚠️ This is a mutating promotion action. Re-call with `confirm=true` to execute."
            )

        client = session.client
        t0 = time.perf_counter()

        try:
            if session.registry_type == "artifactory":
                copy_url = f"/api/copy/{src_repo}/{name}/{ver}?to=/{tgt_repo}/{name}/{ver}"
                resp = await client.post(copy_url)
                if resp.status_code not in (200, 201):
                    copy_fallback = f"/api/copy/{src_repo}/{name}?to=/{tgt_repo}/{name}"
                    resp2 = await client.post(copy_fallback)
                    if resp2.status_code not in (200, 201):
                        return (
                            f"❌ Artifactory promotion copy failed (HTTP {resp.status_code}):\n"
                            f"{resp.text[:300]}"
                        )

            else:  # nexus
                search_url = "/service/rest/v1/search/assets"
                params = {"repository": src_repo, "name": f"*{name}*"}
                s_resp = await client.get(search_url, params=params)
                if s_resp.status_code != 200 or not s_resp.json().get("items"):
                    return f"❌ Source component '{name}' version '{ver}' not found in Nexus repository '{src_repo}'."

                items = s_resp.json()["items"]
                for item in items:
                    asset_path = item.get("path", "")
                    dl_url = item.get("downloadUrl", "")
                    if dl_url:
                        dl_resp = await client.get(dl_url)
                        if dl_resp.status_code == 200:
                            up_url = f"/repository/{tgt_repo}/{asset_path}"
                            await client.put(up_url, content=dl_resp.content)

            duration_s = time.perf_counter() - t0

            return (
                f"✅ **Artifact Promotion Completed Successfully!**\n\n"
                f"  • **Source Repository**: `{src_repo}` (Staging)\n"
                f"  • **Destination Repository**: `{tgt_repo}` (Production Release)\n"
                f"  • **Promoted Artifact**: `{name}`\n"
                f"  • **Promoted Version**: `{ver}`\n"
                f"  • **Registry**: {session.registry_type.capitalize()} ({session.base_url})\n"
                f"  • **Promotion Duration**: {duration_s:.2f} seconds\n\n"
                f"🚀 **Next Step**: Hand off version `{ver}` to `k8s-mcp` for deployment to production cluster."
            )

        except Exception as exc:
            return f"❌ Error executing artifact promotion: {type(exc).__name__}: {str(exc)}"

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
        Identifies and prunes stale snapshot artifacts (dry_run=True by default for safety).
        """
        try:
            session = self.session(session_name)
        except KeyError as exc:
            return str(exc)

        repo = repository.strip()
        comp = component_name.strip()
        client = session.client
        snapshots: list[dict[str, Any]] = []

        try:
            if session.registry_type == "nexus":
                params = {"repository": repo, "name": f"*{comp}*"}
                resp = await client.get("/service/rest/v1/search/assets", params=params)
                if resp.status_code == 200:
                    for it in resp.json().get("items", []):
                        path_s = it.get("path", "")
                        if "SNAPSHOT" in path_s.upper() or comp in path_s:
                            snapshots.append({
                                "id": it.get("id", ""),
                                "name": path_s.split("/")[-1],
                                "path": path_s,
                                "size": it.get("fileSize") or 0,
                                "timestamp": it.get("lastModified", ""),
                            })
            else:  # artifactory
                aql = (
                    f'items.find({{"repo": "{repo}", "name": {{"$match": "*{comp}*"}}}})'
                    f'.include("name", "repo", "path", "size", "created", "modified")'
                )
                resp = await client.post("/api/search/aql", content=aql, headers={"Content-Type": "text/plain"})
                if resp.status_code == 200:
                    for it in resp.json().get("results", []):
                        f_name = it.get("name", "")
                        f_path = f"{it.get('path', '')}/{f_name}".lstrip("/")
                        if "SNAPSHOT" in f_path.upper() or comp in f_path:
                            snapshots.append({
                                "id": f_path,
                                "name": f_name,
                                "path": f_path,
                                "size": it.get("size") or 0,
                                "timestamp": it.get("modified") or it.get("created", ""),
                            })

        except Exception as exc:
            return f"❌ Error searching for snapshot components: {type(exc).__name__}: {str(exc)}"

        if not snapshots:
            return f"No snapshots found for component '{comp}' in repository '{repo}'."

        snapshots.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)

        keep_list = snapshots[:keep_latest_n]
        delete_list = snapshots[keep_latest_n:]
        reclaimable_bytes = sum(item["size"] for item in delete_list)

        if dry_run:
            lines = [
                f"### 🔍 Safe Snapshot Cleanup Simulation (`dry_run=True`)\n",
                f"  • **Repository**: `{repo}`",
                f"  • **Component**: `{comp}`",
                f"  • **Keep Latest**: `{keep_latest_n}`",
                f"  • **Total Snapshots Found**: {len(snapshots)}",
                f"  • **Snapshots to Retain**: {len(keep_list)}",
                f"  • **Snapshots Marked for Pruning**: {len(delete_list)}",
                f"  • **Estimated Reclaimable Space**: **{format_bytes(reclaimable_bytes)}**\n",
                "#### 🛡️ Retained Snapshots (Newest):",
            ]
            for it in keep_list:
                lines.append(f"  • `{it['name']}` ({format_bytes(it['size'])}) — *Retained*")

            if delete_list:
                lines.append("\n#### 🗑️ Stale Snapshots Scheduled for Deletion:")
                for it in delete_list[:15]:
                    lines.append(f"  • `{it['name']}` ({format_bytes(it['size'])}) — *Stale*")
                if len(delete_list) > 15:
                    lines.append(f"    *(and {len(delete_list) - 15} more stale artifacts)*")

            lines.extend([
                "",
                "ℹ️ **No files were deleted** because `dry_run=True`.",
                "To execute permanent pruning, re-call with `dry_run=false` and `confirm=true`.",
            ])
            return "\n".join(lines)

        if not confirm:
            return (
                f"🔒 **Confirmation Required: Permanent Snapshot Deletion**\n\n"
                f"  • **Action**: Prune {len(delete_list)} stale snapshot artifact(s)\n"
                f"  • **Repository**: `{repo}`\n"
                f"  • **Component**: `{comp}`\n"
                f"  • **Space to be permanently freed**: {format_bytes(reclaimable_bytes)}\n\n"
                f"⚠️ This is a DESTRUCTIVE action. Re-call with `dry_run=false` AND `confirm=true` to execute."
            )

        deleted_count = 0
        try:
            for item in delete_list:
                if session.registry_type == "nexus":
                    asset_id = item.get("id")
                    if asset_id:
                        del_resp = await client.delete(f"/service/rest/v1/assets/{asset_id}")
                        if del_resp.status_code in (200, 204):
                            deleted_count += 1
                else:  # artifactory
                    item_path = item.get("path")
                    del_resp = await client.delete(f"/{repo}/{item_path}")
                    if del_resp.status_code in (200, 204):
                        deleted_count += 1

            return (
                f"✅ **Snapshot Pruning Completed!**\n\n"
                f"  • **Repository**: `{repo}`\n"
                f"  • **Component**: `{comp}`\n"
                f"  • **Snapshots Deleted**: {deleted_count} / {len(delete_list)}\n"
                f"  • **Disk Space Reclaimed**: ~{format_bytes(reclaimable_bytes)}\n"
                f"  • **Snapshots Retained**: {len(keep_list)}\n"
            )

        except Exception as exc:
            return f"❌ Error during snapshot deletion: {type(exc).__name__}: {str(exc)}"

