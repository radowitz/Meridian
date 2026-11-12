.PHONY: test ui run

test:
	go test ./...

ui:
	cd web && npm ci && npm run build

run:
	MERIDIAN_BIND=127.0.0.1:8787 MERIDIAN_DATA=/tmp/meridian MERIDIAN_WEB_DIR=web/dist go run ./cmd/meridian
