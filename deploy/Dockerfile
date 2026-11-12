FROM node:22-bookworm AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/meridian ./cmd/meridian

FROM debian:13-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates wireguard-tools nftables iproute2 curl procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/meridian /usr/local/bin/meridian
COPY --from=web /src/web/dist /usr/share/meridian/web
ENV MERIDIAN_WEB_DIR=/usr/share/meridian/web \
    MERIDIAN_DATA=/var/lib/meridian \
    MERIDIAN_BIND=192.168.100.88:8787
ENTRYPOINT ["/usr/local/bin/meridian"]
