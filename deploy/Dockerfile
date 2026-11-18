# Multi-arch (linux/amd64, linux/arm64; .github/workflows/release-images.yml):
# the web, Go and artifact stages run on the build machine's platform; Go
# cross-compiles for TARGETARCH. Only the final stage is per-architecture.
FROM --platform=$BUILDPLATFORM node:22-bookworm AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/meridian ./cmd/meridian

# Panel-delivered binaries (wstunnel, SmartDNS), pinned per architecture in
# internal/artifacts/artifacts.lock. Downloaded once here from the pinned
# GitHub release URLs (or taken from deploy/artifacts/ for an air-gapped
# build) and verified: a digest or size mismatch fails the build. Target
# hosts never download them; the panel sends them over SSH.
# Arch-independent: the lock pins both architectures and all are fetched.
FROM --platform=$BUILDPLATFORM debian:13-slim AS artifacts
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY internal/artifacts/artifacts.lock /src/artifacts.lock
COPY deploy/fetch-artifacts.sh /src/fetch-artifacts.sh
COPY deploy/artifacts/ /src/local/
RUN sh /src/fetch-artifacts.sh /src/artifacts.lock /src/local /out/artifacts

FROM debian:13-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates wireguard-tools nftables iproute2 curl procps openssl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/meridian /usr/local/bin/meridian
COPY --from=web /src/web/dist /usr/share/meridian/web
COPY --from=artifacts /out/artifacts /usr/share/meridian/artifacts
RUN chmod 0555 /usr/share/meridian/artifacts
ENV MERIDIAN_WEB_DIR=/usr/share/meridian/web \
    MERIDIAN_DATA=/var/lib/meridian \
    MERIDIAN_ARTIFACTS_DIR=/usr/share/meridian/artifacts
# No built-in MERIDIAN_BIND: the panel uses the address the installer
# confirmed (deploy/.env), else the stored topology's panel_bind, else
# 127.0.0.1:8787. It never binds 0.0.0.0 / ::.
ENTRYPOINT ["/usr/local/bin/meridian"]
