"""
Artifact Registry MCP Server — Main Entry Point.

Author: Pawan Gunjkar (pawangunjkar@gmail.com)

A production-grade Model Context Protocol (MCP) server supporting Sonatype Nexus
Repository 3 and JFrog Artifactory. Enables AI coding and DevOps agents to list,
search, verify, upload, promote, and clean up build artifacts across CI/CD and
Kubernetes/OpenShift deployment workflows.

Usage:
    uv run server.py                # Run via stdio (for Cursor/Claude Desktop)
    uv run mcp dev server.py        # Run with MCP Inspector (for testing)
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from artifact_client import ArtifactClient
from credential_store import CredentialStore


# ============================================================
# Pydantic Models for Structured Data
# ============================================================

class MavenCoordinates(BaseModel):
    """Maven GAV coordinates for component uploads."""
    groupId: str = Field(description="Maven groupId, e.g. 'com.example'")
    artifactId: str = Field(description="Maven artifactId, e.g. 'my-service'")
    version: str = Field(description="Maven version, e.g. '1.0.0' or '1.0.0-SNAPSHOT'")
    packaging: str = Field(default="jar", description="Packaging extension, e.g. 'jar', 'war', 'pom'")
    classifier: Optional[str] = Field(default=None, description="Optional classifier, e.g. 'sources', 'javadoc'")


# ============================================================
# Initialize MCP Server
# ============================================================

mcp = FastMCP(
    "artifact-registry",
    instructions=(
        "Artifact Registry MCP Server — Full-lifecycle binary supply-chain controller "
        "for Sonatype Nexus Repository 3 and JFrog Artifactory. "
        "Call artifact_connect to establish a session first (or configure ARTIFACT_REGISTRY_TYPE, "
        "ARTIFACT_REGISTRY_URL, ARTIFACT_REGISTRY_USER, ARTIFACT_REGISTRY_TOKEN env vars). "
        "Provides 12 tools across connection, search, Docker OCI digest resolution, "
        "checksum verification, binary upload, release promotion, and snapshot pruning. "
        "Read-only tools (search, digest resolution, checksum verification) run autonomously. "
        "Mutating tools (artifact_upload_binary, artifact_promote_release, artifact_cleanup_old_snapshots) "
        "require confirm=true to execute. "
        "Integrate with github-mcp / jenkins-mcp upstream for CI build artifacts and "
        "k8s-mcp downstream for immutable container digest rollouts."
    ),
)

# Global instances
_credential_store = CredentialStore()
_client = ArtifactClient(credential_store=_credential_store)


# ============================================================
# Auto-connect from Environment
# ============================================================

async def _try_autoconnect() -> None:
    env_creds = _credential_store.get_from_env()
    if env_creds and os.environ.get("ARTIFACT_DISABLE_AUTOCONNECT") != "1":
        print(f"Auto-connecting artifact registry session from environment ({env_creds.registry_type} at {env_creds.base_url})...", file=sys.stderr)
        await _client.connect(
            registry_type=env_creds.registry_type,
            base_url=env_creds.base_url,
            token_or_password=env_creds.token_or_password,
            username=env_creds.username,
            session_name="default",
            ssl_verify=env_creds.ssl_verify,
            timeout=env_creds.timeout,
            save_credentials=False,
        )


# ============================================================
# CATEGORY 1: Connection & Authentication Tools (5 tools)
# ============================================================

@mcp.tool()
async def artifact_connect(
    registry_type: str = "",
    base_url: str = "",
    token_or_password: str = "",
    username: str = "",
    session_name: str = "default",
) -> str:
    """
    Connect to Sonatype Nexus 3 or JFrog Artifactory and create a named session.

    Probes registry system status and version to verify connectivity and credentials.
    Credentials are automatically cached to ~/.artifact-mcp-cache/credentials.json.

    **Purpose**: Establish an authenticated session before calling any registry tool.
    **When to Use**: At the start of an artifact supply chain workflow or to switch
    between staging/production registries using named sessions.
    **Behavior**: Read-Only probe (no artifacts mutated).
    **Side Effects**: Caches session credentials locally.

    Args:
        registry_type: 'nexus' (Sonatype Nexus 3) or 'artifactory' (JFrog Artifactory)
        base_url: Registry base URL (e.g. 'http://localhost:8081' or 'https://myorg.jfrog.io/artifactory')
        token_or_password: Password, API Token, or Access Token
        username: Username (e.g. 'admin' or 'ci-agent')
        session_name: Name for this session, e.g. 'prod', 'staging' (default: 'default')
    """
    return await _client.connect(
        registry_type=registry_type,
        base_url=base_url,
        token_or_password=token_or_password,
        username=username,
        session_name=session_name,
    )


@mcp.tool()
async def artifact_status(session_name: str = "default") -> str:
    """
    Check connection health, authenticated user, registry version, and storage quota.

    Probes status endpoints (Nexus /service/rest/v1/status, Artifactory /api/system/ping),
    retrieves server version, and summarizes repository storage metrics.

    **Purpose**: Verify registry availability, user privileges, and storage capacity.
    **When to Use**: Before initiating large binary uploads or checking health.
    **Behavior**: Read-Only probe.
    **Side Effects**: None.

    Args:
        session_name: Artifact registry session to inspect (default: 'default')
    """
    return await _client.status(session_name=session_name)


@mcp.tool()
async def artifact_disconnect(session_name: str = "default") -> str:
    """
    Disconnect an active artifact registry session and close HTTP connections.

    **Purpose**: Clean up open network sessions and release memory.
    **When to Use**: When switching environments or finishing a pipeline run.
    **Behavior**: Closes local HTTP client.
    **Side Effects**: Removes session from active memory.

    Args:
        session_name: Session to disconnect (default: 'default')
    """
    return await _client.disconnect(session_name=session_name)


@mcp.tool()
def artifact_list_sessions() -> str:
    """
    List all active and cached registry sessions with masked credentials.

    **Purpose**: Review available registry targets, environments, and versions.
    **When to Use**: To determine which sessions are configured before executing workflows.
    **Behavior**: Read-Only local inspection.
    **Side Effects**: None.
    """
    sessions = _client.list_sessions()
    if not sessions:
        return "No registry sessions found (neither active in memory nor cached in file)."

    lines = [
        f"### Configured Artifact Registry Sessions ({len(sessions)})\n",
        "| Session Name | Registry Type | Base URL | Username | Active | Version |",
        "|--------------|---------------|----------|----------|--------|---------|",
    ]
    for name, s in sessions.items():
        user = s.get("username") or "(token)"
        active_str = "✅ Yes" if s.get("is_active") else "⚪ Cached"
        lines.append(
            f"| `{name}` | `{s.get('registry_type')}` | {s.get('base_url')} | `{user}` | {active_str} | {s.get('version')} |"
        )
    return "\n".join(lines)


@mcp.tool()
def artifact_save_credentials(
    registry_type: str,
    base_url: str,
    token_or_password: str,
    username: str = "",
    session_name: str = "default",
) -> str:
    """
    Save registry credentials to the local persistent cache file.

    **Purpose**: Cache connection details so future sessions can reconnect automatically.
    **When to Use**: When pre-configuring staging/production environments without running queries.
    **Behavior**: Local file write to ~/.artifact-mcp-cache/credentials.json.
    **Side Effects**: Overwrites existing cached credentials for session_name.

    Args:
        registry_type: 'nexus' or 'artifactory'
        base_url: Registry base URL
        token_or_password: Password, API Token, or Access Token
        username: Username (e.g. 'admin')
        session_name: Session name to store (default: 'default')
    """
    reg_type = registry_type.strip().lower()
    if reg_type not in ("nexus", "artifactory"):
        return f"❌ registry_type must be 'nexus' or 'artifactory' (got '{registry_type}')."

    _credential_store.save_credentials(
        session_name=session_name,
        registry_type=reg_type,
        base_url=base_url.rstrip("/"),
        username=username,
        token_or_password=token_or_password,
    )
    return f"✅ Saved credentials for session '{session_name}' ({reg_type} at {base_url})."


# ============================================================
# CATEGORY 2: Core Nexus & Artifactory Lifecycle Tools (7 tools)
# ============================================================

@mcp.tool()
async def artifact_list_repositories(
    format_filter: str = "",
    type_filter: str = "",
    session_name: str = "default",
) -> str:
    """
    List repositories filtered by package format and repository type.

    Works across both Nexus 3 (/service/rest/v1/repositories) and
    Artifactory (/api/repositories).

    **Purpose**: Inspect repository topology and locate target repos for upload or promotion.
    **When to Use**: During supply chain discovery before publishing or pulling artifacts.
    **Behavior**: Read-Only query.
    **Side Effects**: None.

    Args:
        format_filter: Filter by package format: 'maven2', 'docker', 'npm', 'pypi', 'helm', 'raw' (or 'generic')
        type_filter: Filter by type: 'hosted' (or 'local'), 'proxy' (or 'remote'), 'group' (or 'virtual')
        session_name: Session to query (default: 'default')
    """
    return await _client.list_repositories(
        format_filter=format_filter,
        type_filter=type_filter,
        session_name=session_name,
    )


@mcp.tool()
async def artifact_search_binaries(
    name: str,
    group_or_repo: str = "",
    version: str = "",
    sha256: str = "",
    session_name: str = "default",
) -> str:
    """
    Search components and artifacts across Nexus or Artifactory.

    Returns download URLs, exact versions, creation/modification timestamps,
    and SHA256/SHA1/MD5 checksums.

    **Purpose**: Locate specific binaries or verify build component presence.
    **When to Use**: To locate release artifacts before deployment or check artifact metadata.
    **Behavior**: Read-Only search.
    **Side Effects**: None.

    Args:
        name: Artifact or component name (supports wildcards/substrings, e.g. 'order-service')
        group_or_repo: Repository name or Maven groupId (e.g. 'libs-release-local' or 'com.myorg')
        version: Specific version string (e.g. '1.4.2' or '2.0.0-SNAPSHOT')
        sha256: Exact 64-character SHA256 checksum to look up
        session_name: Session to query (default: 'default')
    """
    return await _client.search_binaries(
        name=name,
        group_or_repo=group_or_repo,
        version=version,
        sha256=sha256,
        session_name=session_name,
    )


@mcp.tool()
async def artifact_get_docker_image_tags_and_digests(
    repository: str,
    image_name: str,
    limit: int = 20,
    session_name: str = "default",
) -> str:
    """
    Query Docker/OCI repositories to resolve an immutable sha256:... image digest.

    Queries Docker v2 manifest endpoints and AQL in Nexus and Artifactory.
    Produces an immutable image reference (image@sha256:...) and ready-to-run
    tool arguments for k8s-mcp rollouts.

    **Purpose**: Bridge container registry images to Kubernetes deployments securely.
    **When to Use**: Right before calling k8s-mcp to deploy or update a container workload.
    **Behavior**: Read-Only query.
    **Side Effects**: None.

    Args:
        repository: Docker repository key/name in the registry (e.g. 'docker-local' or 'docker-hosted')
        image_name: Container image name (e.g. 'payment-service' or 'microservices/auth')
        limit: Maximum number of tags to return (default: 20)
        session_name: Session to query (default: 'default')
    """
    return await _client.get_docker_image_tags_and_digests(
        repository=repository,
        image_name=image_name,
        limit=limit,
        session_name=session_name,
    )


@mcp.tool()
async def artifact_verify_checksum_integrity(
    artifact_path_or_url: str,
    expected_sha256: str,
    session_name: str = "default",
) -> str:
    """
    Compare the SHA256 digest generated by CI against registry checksum before deployment.

    Verifies cryptographic attestation: compares the expected SHA256 (produced by
    github-mcp GitHub Actions or jenkins-mcp build jobs) against the checksum stored
    in Nexus or Artifactory. Blocks deployment if tampering or corruption is detected.

    **Purpose**: Supply-chain security attestation gate.
    **When to Use**: In CI/CD pipelines right before deployment to Kubernetes/OpenShift.
    **Behavior**: Read-Only verification.
    **Side Effects**: None.

    Args:
        artifact_path_or_url: Remote artifact path (e.g. 'libs-release-local/com/corp/app-1.0.jar') or full URL
        expected_sha256: 64-character SHA256 digest from CI build or SBOM
        session_name: Session to query (default: 'default')
    """
    return await _client.verify_checksum_integrity(
        artifact_path_or_url=artifact_path_or_url,
        expected_sha256=expected_sha256,
        session_name=session_name,
    )


@mcp.tool()
async def artifact_upload_binary(
    repository: str,
    local_file_path: str,
    target_path: str,
    maven_coords: dict[str, str] | None = None,
    confirm: bool = False,
    session_name: str = "default",
) -> str:
    """
    Upload a local build artifact/archive to Nexus or Artifactory with checksum verification.

    ⚠️ CONFIRMATION-GATED MUTATING TOOL: Requires confirm=true to execute.

    Computes local SHA256/SHA1/MD5 checksums, uploads the binary to the destination
    repository, and immediately verifies the remote checksum match.

    **Purpose**: Publish build archives, JARs, wheels, or tarballs to the registry.
    **When to Use**: In Workflow 1 after jenkins-mcp or github-mcp build completes.
    **Behavior**: MUTATING. Writes binary to registry storage.
    **Side Effects**: Consumes registry storage space.

    Args:
        repository: Destination repository (e.g. 'maven-releases', 'libs-snapshot-local')
        local_file_path: Absolute or relative path to the local file to upload
        target_path: Destination path in the repository (e.g. 'com/corp/auth/1.0.0/auth-1.0.0.jar')
        maven_coords: Optional dict of Maven coordinates {'groupId': '...', 'artifactId': '...', 'version': '...', 'packaging': 'jar'}
        confirm: Must be True to execute upload (default: False)
        session_name: Session to use (default: 'default')
    """
    return await _client.upload_binary(
        repository=repository,
        local_file_path=local_file_path,
        target_path=target_path,
        maven_coords=maven_coords,
        confirm=confirm,
        session_name=session_name,
    )


@mcp.tool()
async def artifact_promote_release(
    source_repo: str,
    target_repo: str,
    artifact_or_build_name: str,
    version: str,
    confirm: bool = False,
    session_name: str = "default",
) -> str:
    """
    Promote an immutable artifact from staging/snapshot to production release repository.

    ⚠️ CONFIRMATION-GATED MUTATING TOOL: Requires confirm=true to execute.

    Promotes a tested, immutable component from staging (e.g. 'dev-local', 'maven-staging')
    to production release (e.g. 'prod-release', 'maven-releases') without rebuilding,
    maintaining complete provenance and cryptographic integrity.

    **Purpose**: Supply-chain promotion between pipeline stages.
    **When to Use**: In Workflow 2 after integration/smoke tests pass.
    **Behavior**: MUTATING. Copies component to target release repository.
    **Side Effects**: Modifies target release repository contents.

    Args:
        source_repo: Source repository key (e.g. 'dev-local', 'staging-repo')
        target_repo: Target release repository key (e.g. 'prod-release', 'maven-releases')
        artifact_or_build_name: Name of the artifact or build component (e.g. 'cart-service')
        version: Version string to promote (e.g. '1.5.0')
        confirm: Must be True to execute promotion (default: False)
        session_name: Session to use (default: 'default')
    """
    return await _client.promote_release(
        source_repo=source_repo,
        target_repo=target_repo,
        artifact_or_build_name=artifact_or_build_name,
        version=version,
        confirm=confirm,
        session_name=session_name,
    )


@mcp.tool()
async def artifact_cleanup_old_snapshots(
    repository: str,
    component_name: str,
    keep_latest_n: int = 5,
    dry_run: bool = True,
    confirm: bool = False,
    session_name: str = "default",
) -> str:
    """
    Identify and prune stale snapshot artifacts to reclaim storage.

    ⚠️ CONFIRMATION-GATED MUTATING TOOL: Requires dry_run=false AND confirm=true to delete.

    Finds all snapshot versions of a component, sorts by timestamp/version descending,
    preserves the latest keep_latest_n snapshots, and simulates or deletes stale items.

    **Purpose**: Maintain storage quotas and enforce artifact retention policies.
    **When to Use**: In Workflow 4 during scheduled maintenance or when storage alerts trigger.
    **Behavior**: Dry-run simulation by default. Destructive deletion when dry_run=false and confirm=true.
    **Side Effects**: Permanently deletes pruned snapshot artifacts when executed.

    Args:
        repository: Repository containing snapshot artifacts (e.g. 'maven-snapshots', 'libs-snapshot-local')
        component_name: Name of the component to clean up (e.g. 'billing-engine')
        keep_latest_n: Number of most recent snapshots to preserve (default: 5)
        dry_run: If True, simulates cleanup without deleting files (default: True)
        confirm: Must be True when dry_run=False to execute permanent deletion (default: False)
        session_name: Session to use (default: 'default')
    """
    return await _client.cleanup_old_snapshots(
        repository=repository,
        component_name=component_name,
        keep_latest_n=keep_latest_n,
        dry_run=dry_run,
        confirm=confirm,
        session_name=session_name,
    )


# ============================================================
# Entry Point
# ============================================================

def main() -> None:
    """Entry point for artifact-registry-mcp server."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(_try_autoconnect())
        else:
            loop.run_until_complete(_try_autoconnect())
    except Exception as exc:
        print(f"Notice: Autoconnect check skipped: {exc}", file=sys.stderr)

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

