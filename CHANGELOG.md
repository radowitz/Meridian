# Changelog

Each release has a `## vX.Y.Z` section; the release workflow
(`.github/workflows/release-images.yml`) uses that section as the release
notes and refuses a version without one.

## Unreleased

- One-command gateway install (`deploy/debian/install.sh`): prebuilt image by
  version, image archive or local build; management firewall for the panel
  port (IPv4/IPv6, Docker port rules); safe to re-run.
- One-command upgrade and rollback (`deploy/debian/upgrade.sh`,
  `deploy/debian/rollback.sh`) with volume backups and automatic rollback on a
  failed health check; `deploy/debian/api.sh` for API calls from the gateway.
- Multi-arch (amd64/arm64) image workflow definition, manual and build-only by
  default.
