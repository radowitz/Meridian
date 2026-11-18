# Air-gapped image builds

Put the upstream downloads named in `internal/artifacts/artifacts.lock`
here (the last path element of each URL, e.g.
`wstunnel_11.1.0_linux_amd64.tar.gz`, `smartdns-x86_64`) and the image build
uses them instead of downloading. They are verified against the same pinned
SHA-256 values; a copy that does not match fails the build. Nothing in this
directory except this README and `.gitignore` is tracked by git.

The files here are the binaries the panel delivers to remote nodes. The
gateway's own resolver is not one of them: it is the `smartdns` service of
`deploy/docker-compose.yml`, a container image whose SmartDNS version is
whatever that image holds. Features that depend on that version (the DNS
query journal, `settings.dns_log`) read it from the running container and
never assume it equals the version pinned in `artifacts.lock`; a version
that was not verified is checked on the gateway with
`sudo bash deploy/verify-smartdns.sh --audit-check` (throw-away containers
without a network; see docs/architecture.md「网关解析日志」).
