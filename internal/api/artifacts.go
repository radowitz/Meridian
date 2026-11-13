package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
)

// Panel-delivered binaries (wstunnel, SmartDNS). The pins are compiled in
// (internal/artifacts/artifacts.lock); the bytes come from the image's
// read-only directory or MERIDIAN_ARTIFACTS_DIR and are verified at
// startup and again before every transfer. See docs/architecture.md
// 「面板下发的二进制」.

const codeArtifactUnavailable = "artifact_unavailable"

// artifactContext is what the preflight evaluation knows about the
// panel's binaries, for every architecture.
func (s *Server) artifactContext() []preflight.Artifact {
	var out []preflight.Artifact
	for _, st := range s.Artifacts.Statuses() {
		out = append(out, preflight.Artifact{Name: st.Name, Version: st.Version, Arch: st.Arch, SHA256: st.SHA256, Size: st.Size, Available: st.Available, Error: st.Error})
	}
	return out
}

// getArtifacts lists the pinned binaries and whether the panel holds a
// verified copy of each (no bytes, no paths of the panel's filesystem).
func (s *Server) getArtifacts(w http.ResponseWriter, r *http.Request) {
	type view struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Arch      string `json:"arch"`
		SHA256    string `json:"sha256"`
		Size      int64  `json:"size"`
		URL       string `json:"source_url"`
		HostPath  string `json:"host_path"`
		Available bool   `json:"available"`
		Error     string `json:"error,omitempty"`
	}
	var out []view
	for _, st := range s.Artifacts.Statuses() {
		out = append(out, view{Name: st.Name, Version: st.Version, Arch: st.Arch, SHA256: st.SHA256, Size: st.Size, URL: st.URL,
			HostPath: artifacts.HostPath(st.Name), Available: st.Available, Error: st.Error})
	}
	writeJSON(w, http.StatusOK, map[string]any{"artifacts": out})
}

// stageArtifacts turns the fresh preflight's binary plan into the
// provision script's artifacts and sends every binary that must be
// transferred over the flow's pooled connection (sshexec.Stage). The bytes
// are re-read and re-verified against the pin here; the plan's digest must
// equal the pin's. Nothing is installed: the script verifies the staged
// file on the host again before its transaction opens.
func (s *Server) stageArtifacts(ctx context.Context, cs *credentials.Store, ident targetIdentity, fresh *preflightRecord) ([]provision.Artifact, error) {
	var out []provision.Artifact
	for _, bp := range fresh.Binaries {
		switch bp.Action {
		case "install", "replace":
		case "keep":
			out = append(out, provision.Artifact{Name: bp.Name, Version: bp.Version, SHA256: bp.SHA256, Size: bp.Size})
			continue
		default:
			return nil, &credentials.Error{Code: codeArtifactUnavailable, Msg: fmt.Sprintf("%s 不能下发：%s", bp.Name, bp.Detail)}
		}
		data, pin, err := s.Artifacts.Read(bp.Name, bp.Arch)
		if err != nil {
			return nil, &credentials.Error{Code: codeArtifactUnavailable, Msg: err.Error()}
		}
		if pin.SHA256 != bp.SHA256 || pin.Version != bp.Version {
			return nil, &credentials.Error{Code: codeArtifactUnavailable, Msg: fmt.Sprintf("%s 的固定版本在预检之后变了：重新预检", bp.Name)}
		}
		if _, err := s.connector(cs).Stage(ctx, ident.target(), bp.Name, pin.SHA256, data); err != nil {
			return nil, err
		}
		out = append(out, provision.Artifact{Name: bp.Name, Version: pin.Version, SHA256: pin.SHA256, Size: pin.Size, Staged: true})
	}
	return out, nil
}

// previewArtifacts are the binaries a provision preview names: the plan of
// the node's last preflight when there is one, else the pins for x86_64
// (the preview never runs; it shows what the script would check).
func (s *Server) previewArtifacts(node string, files map[string]string) []provision.Artifact {
	arch := artifacts.ArchAMD64
	if rec := s.loadPreflight(node); rec != nil && artifacts.ValidArch(rec.Host.Arch) {
		arch = rec.Host.Arch
	}
	var out []provision.Artifact
	for _, b := range preflight.FootprintOf(files).Binaries {
		if p, ok := artifacts.PinFor(b, arch); ok {
			out = append(out, provision.Artifact{Name: p.Name, Version: p.Version, SHA256: p.SHA256, Size: p.Size, Staged: true})
		}
	}
	return out
}
