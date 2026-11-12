package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/radowitz/meridian/internal/api"
	"github.com/radowitz/meridian/internal/store"
)

func main() {
	bind := env("MERIDIAN_BIND", "192.168.100.88:8787")
	if err := api.CheckBind(bind); err != nil {
		log.Fatal(err)
	}
	data := env("MERIDIAN_DATA", "/var/lib/meridian")
	if err := os.MkdirAll(data, 0o750); err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(filepath.Join(data, "meridian.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	srv := &api.Server{
		Store:   st,
		DataDir: data,
		WebDir:  os.Getenv("MERIDIAN_WEB_DIR"),
	}
	log.Printf("meridian panel listening on %s (LAN only)", bind)
	if err := http.ListenAndServe(bind, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
