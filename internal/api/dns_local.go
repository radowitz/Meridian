package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/radowitz/meridian/internal/hostexec"
)

func (s *Server) dnsLocal(w http.ResponseWriter, r *http.Request) {
	rt, ok := s.Prober.(interface {
		DNSLocal(context.Context, hostexec.DNSLocalRequest) (hostexec.DNSLocalResult, int, error)
	})
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, errors.New("网关宿主代理不可用"))
		return
	}
	req := hostexec.DNSLocalRequest{Action: "status"}
	if r.Method == http.MethodPost {
		if err := decodeBody(w, r, &req); err != nil {
			writeResErr(w, err)
			return
		}
	}
	res, status, err := rt.DNSLocal(r.Context(), req)
	if status == http.StatusNotFound {
		writeErr(w, http.StatusServiceUnavailable, errors.New("请先升级网关宿主代理"))
		return
	}
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, status, res)
}
