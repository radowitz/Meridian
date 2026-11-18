package api

import (
	"testing"

	"github.com/radowitz/meridian/internal/validate"
)

// GET /api/status endpoint_access: per-class counts for the panel's one-line
// status, items never null.
func TestEndpointAccessView(t *testing.T) {
	v := newEndpointAccessView([]validate.EndpointAccess{
		{Addr: "203.0.113.10", Class: validate.EndpointDirect},
		{Addr: "198.51.100.10", Class: validate.EndpointDirect},
		{Addr: "203.0.113.41", Class: validate.EndpointTunnel},
		{Addr: "203.0.113.30", Class: validate.EndpointBlocked, Reason: "x"},
	})
	if v.Direct != 2 || v.Tunnel != 1 || v.Blocked != 1 || len(v.Items) != 4 {
		t.Fatalf("%+v", v)
	}
	if e := newEndpointAccessView(nil); e.Items == nil {
		t.Fatal("items must be [] not null")
	}
}
