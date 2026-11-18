# Changelog

Each release has a `## vX.Y.Z` section; the release workflow
(`.github/workflows/release-images.yml`) uses that section as the release
notes and refuses a version without one.

## v1.0.0

First public release.

- Policy rules survive `systemd-networkd` restarts (e.g. a systemd upgrade by
  unattended-upgrades): nodes and the gateway get a networkd drop-in, failover
  loops re-install missing rules, preflight warns when the drop-in is missing.
- DNS journal no longer loses records when a rotated audit file's inode is
  reused.
- SSH through a relay: a refusal sent before the version exchange is read and
  reported as rate limiting instead of an early close.
- One-command gateway install (`deploy/debian/install.sh`): prebuilt image by
  version, image archive or local build; management firewall for the panel
  port (IPv4/IPv6, Docker port rules); safe to re-run.
- One-command upgrade and rollback (`deploy/debian/upgrade.sh`,
  `deploy/debian/rollback.sh`) with volume backups and automatic rollback on a
  failed health check; `deploy/debian/api.sh` for API calls from the gateway.
- Multi-arch (amd64/arm64) image workflow definition, manual and build-only by
  default.
