# Air-gapped image builds

Put the upstream downloads named in `internal/artifacts/artifacts.lock`
here (the last path element of each URL, e.g.
`wstunnel_11.1.0_linux_amd64.tar.gz`, `smartdns-x86_64`) and the image build
uses them instead of downloading. They are verified against the same pinned
SHA-256 values; a copy that does not match fails the build. Nothing in this
directory except this README and `.gitignore` is tracked by git.
