# Changelog

## [Unreleased]

### Fixed
- **Snapshot cleanup could delete release artifacts.** `artifact_cleanup_old_snapshots` now selects only
  SNAPSHOT versions (`1.0-SNAPSHOT` or timestamped `1.0-20240101.120000-1`) of the exact component, and
  `keep_latest_n` counts *versions*, not individual files. Nexus deletes whole components; Artifactory deletes
  whole version folders. Nexus results are fully paginated. `keep_latest_n` must be at least 1.
- **Checksum verification always passed.** `artifact_verify_checksum_integrity` now checks the SHA256 of the
  artifact at the given path. It uses registry metadata for that exact path, or streams and hashes the file when
  the metadata has no SHA256. A file elsewhere with the same checksum no longer counts as a match, and a missing
  artifact is reported as not found.
- **Promotion copied the wrong things.** `artifact_promote_release` copies exactly the requested version. On
  Nexus it searches by group/name/version, verifies each downloaded asset against its source checksum, checks
  every upload, and reports partial failures. On Artifactory it checks the source exists, runs a `dry=1` copy
  first, and no longer falls back to copying the whole component folder (all versions).
- **Docker digest handoff produced a wrong image reference.** Tags are sorted by modification time (newest
  first); multi-arch images resolve to their index digest; the image host can be set with `registry_host` or
  `ARTIFACT_DOCKER_REGISTRY`; the suggested k8s-mcp call now uses the real tool,
  `k8s_trigger_deployment_rollout`. New optional `tag` parameter picks the tag to hand off.
- Uploads stream from disk instead of loading the whole file into memory, and the result says clearly when
  post-upload verification did not pass. Nexus Maven uploads verify the stored Maven path.

### Changed
- The root `server.py`, `artifact_client.py`, and `credential_store.py` are now aliases for the
  `artifact_mcp` package, so there is a single implementation (the copies had drifted).

### Added
- `tests/test_registry_bugfixes.py`: 19 regression tests against an in-memory fake Nexus/Artifactory.
