package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/validate"
)

// GET /api/status: the panel's cheap, read-only summary for the top bar.
// It answers four questions without side effects and without heavy
// payloads (no Mesh plan, no probe catalog, no job items):
//
//   - is the host agent reachable right now (one health call, short timeout);
//   - does the stored topology compile, and does it equal what is INSTALLED
//     on the host (compared with the installed manifest's canonical hash,
//     not with the applied snapshot: an apply without install updates the
//     snapshot but not the host);
//   - is a host transaction unfinished;
//   - the running / last state of the lists job, the unlock probe job and
//     the Mesh deployment.
//
// install.state:
//
//	in_sync        stored topology compiles to exactly the installed text
//	changed        compiles, differs from the installed text
//	not_installed  nothing of Meridian is installed on this host
//	invalid        the stored topology does not compile (draft with errors)
//	unknown        installed, but the manifest carries no canonical hash
//	               (adopted legacy install): cannot compare
//
// applied_matches says whether the stored topology equals the last applied
// snapshot; "changed" with applied_matches=true is "applied but not installed".

const statusAgentTimeout = 3 * time.Second

type statusAgent struct {
	Configured bool   `json:"configured"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

type statusInstall struct {
	State            string           `json:"state"`
	InstalledVersion *int64           `json:"installed_version"`
	InstalledAt      string           `json:"installed_at,omitempty"`
	Origin           string           `json:"origin,omitempty"`
	AppliedMatches   bool             `json:"applied_matches"`
	Applied          bool             `json:"applied"`
	Error            string           `json:"error,omitempty"`
	Issues           []validate.Issue `json:"issues,omitempty"`
}

type statusJob struct {
	// none | running | done | failed | cancelled | timeout | interrupted |
	// published | compensating | compensation_failed | withdrawn …
	State      string `json:"state"`
	Running    bool   `json:"running"`
	ID         string `json:"id,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	Error      string `json:"error,omitempty"`
}

type statusView struct {
	Agent          statusAgent        `json:"agent"`
	ListsAvailable bool               `json:"lists_available"`
	ProbeAvailable bool               `json:"probe_available"`
	Install        statusInstall      `json:"install"`
	Pending        *apply.PendingView `json:"pending"`
	Jobs           struct {
		Lists  statusJob `json:"lists"`
		Unlock statusJob `json:"unlock"`
		Mesh   statusJob `json:"mesh"`
	} `json:"jobs"`
}

func (s *Server) getStatus(w http.ResponseWriter, r *http.Request) {
	var v statusView
	v.Agent = s.agentStatus(r.Context())
	v.ListsAvailable = s.Lists != nil && v.Agent.OK
	v.ProbeAvailable = s.Prober != nil && v.Agent.OK

	ap := s.applier(true)
	pending, err := ap.Pending()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	v.Pending = pending
	inst, err := ap.Installed()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	v.Install = s.installState(ap, inst, func() (*compile.Bundle, error) { return s.compileTopo(t) })

	v.Jobs.Lists = statusJob{State: "none"}
	if j := s.currentListsJob(); j != nil {
		v.Jobs.Lists = statusJob{State: j.State, Running: j.State == "running", ID: j.ID, StartedAt: j.StartedAt.Format(time.RFC3339), Error: j.Error}
		if j.FinishedAt != nil {
			v.Jobs.Lists.FinishedAt = j.FinishedAt.Format(time.RFC3339)
		}
	}

	v.Jobs.Unlock = statusJob{State: "none"}
	s.jobMu.Lock()
	running := ""
	if s.job != nil {
		running = s.job.id
	}
	s.jobMu.Unlock()
	s.mu.Lock()
	doc := s.loadJobs()
	s.mu.Unlock()
	if n := len(doc.Jobs); n > 0 {
		j := doc.Jobs[n-1]
		v.Jobs.Unlock = statusJob{State: j.State, ID: j.ID, StartedAt: j.CreatedAt.Format(time.RFC3339), Error: j.Error}
		if j.FinishedAt != nil {
			v.Jobs.Unlock.FinishedAt = j.FinishedAt.Format(time.RFC3339)
		}
	}
	if running != "" {
		if v.Jobs.Unlock.ID != running {
			v.Jobs.Unlock = statusJob{ID: running}
		}
		v.Jobs.Unlock.State = "running"
		v.Jobs.Unlock.Running = true
	}

	v.Jobs.Mesh = statusJob{State: "none"}
	if j, err := (&mesh.Deployer{Dir: s.meshDir()}).Load(); err != nil {
		v.Jobs.Mesh = statusJob{State: "error", Error: err.Error()}
	} else if j != nil {
		v.Jobs.Mesh = statusJob{
			State: j.State, ID: j.RunID, StartedAt: j.Started, Error: j.Error,
			Running: j.State == mesh.StateRunning || j.State == mesh.StateCompensating,
		}
		if !v.Jobs.Mesh.Running {
			v.Jobs.Mesh.FinishedAt = j.Updated
		}
	}
	writeJSON(w, http.StatusOK, v)
}

// agentStatus asks the host agent for its health once, with a short timeout.
func (s *Server) agentStatus(ctx context.Context) statusAgent {
	switch {
	case s.Host != nil:
		ctx, cancel := context.WithTimeout(ctx, statusAgentTimeout)
		defer cancel()
		_, err := s.Host.Do(ctx, hostexec.Request{Action: hostexec.ActionHealth, RequestID: "status-" + randHex(4)})
		if err != nil {
			return statusAgent{Configured: true, Error: err.Error()}
		}
		return statusAgent{Configured: true, OK: true}
	case s.Activate != nil:
		return statusAgent{Configured: true, OK: true, Error: "test shim"}
	default:
		return statusAgent{Error: apply.ErrNoHostExec.Error()}
	}
}

func (s *Server) installState(ap apply.Applier, inst apply.Manifest, build func() (*compile.Bundle, error)) statusInstall {
	var out statusInstall
	if !inst.Empty() {
		v := inst.Version
		out.InstalledVersion = &v
		out.InstalledAt = inst.CreatedAt
		out.Origin = inst.Origin
	}
	b, err := build()
	if err != nil {
		out.State = "invalid"
		out.Error = err.Error()
		var ve *compile.ValidationError
		if errors.As(err, &ve) {
			for _, iss := range ve.Result.Issues {
				if iss.Severity == validate.SeverityError {
					out.Issues = append(out.Issues, iss)
				}
			}
		}
		return out
	}
	canon := b.Canonical()
	if applied, ok, err := ap.AppliedCanonical(); err == nil && ok {
		out.Applied = true
		out.AppliedMatches = applied == canon
	}
	switch {
	case inst.Empty():
		out.State = "not_installed"
	case inst.Canonical == "":
		out.State = "unknown"
	default:
		sum := sha256.Sum256([]byte(canon))
		if hex.EncodeToString(sum[:]) == inst.Canonical {
			out.State = "in_sync"
		} else {
			out.State = "changed"
		}
	}
	return out
}
