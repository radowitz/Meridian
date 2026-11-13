package hostexec

// The gateway's upstream status read (POST /v1/upstream/status).
//
// It has no parameters at all: it reads the one fixed file the gateway's
// failover loop (and, at install, its routes script) writes,
// UpstreamStateFile, bounded to MaxUpstreamFile bytes, and returns it
// parsed against a strict grammar. Nothing is executed. It tells the panel
// which path and which hub currently carry the gateway's foreign traffic
// (compile.planUpstream; docs/architecture.md「主枢纽与备用枢纽」). Like the
// remote-access status it is read-only and takes no action lock.
//
//	meridian-upstream 1
//	beat <epoch>          last pass of the loop (or the install)
//	path <name>           udp | wss | backup …
//	iface <ifname>
//	hub <node id>
//	tier <primary|backup>
//	since <epoch>         when the path was installed
//	state <static|ok|switching|down>
//	end
//
// With relay sharing (two or more relays) the gateway's controller
// (internal/pathquality, "meridian path-step") writes the second form:
// the same seven lines, then controller/alert/switched/designated, one
// "relay" line per relay and an optional "backup" line, each with a fixed
// number of fields (pathquality.FormatStatus documents them); "-" is
// "not measured". State may also be "degraded".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// UpstreamStateFile is compile.UpstreamStateFile (a test keeps them equal).
const UpstreamStateFile = "/run/meridian/upstream"

// MaxUpstreamFile bounds the read (the relay-sharing form with
// pathquality.MaxRelays relays stays well below it).
const MaxUpstreamFile = 8192

// Upstream states the gateway records.
const (
	// UpstreamStatic: written by the install; the failover loop has not
	// measured anything yet.
	UpstreamStatic = "static"
	// UpstreamOK: the path in use answered on the last pass.
	UpstreamOK = "ok"
	// UpstreamSwitching: another path is preferred on the last pass (the
	// current one stopped answering, or a better one answers again) and the
	// switch waits for its hysteresis.
	UpstreamSwitching = "switching"
	// UpstreamDown: no path answered on the last pass; table 102 stays on
	// the path shown (traffic is dropped in the tunnel, never routed out of
	// the LAN NIC).
	UpstreamDown = "down"
	// UpstreamDegraded (relay sharing): every relay is below the usable
	// floor and the backup hub is not better (or not usable): the
	// comparatively best relay carries and an alert is raised.
	UpstreamDegraded = "degraded"
)

// UpstreamState is one parsed record.
type UpstreamState struct {
	// Version is 1 (single relay) or 2 (relay sharing).
	Version int    `json:"version"`
	Beat    int64  `json:"beat"`
	Path    string `json:"path"`
	Iface   string `json:"iface"`
	Hub     string `json:"hub"`
	Tier    string `json:"tier"`
	Since   int64  `json:"since"`
	State   string `json:"state"`

	// Relay sharing (version 2) only.
	Controller string          `json:"controller,omitempty"` // go | shell (fallback)
	Alert      string          `json:"alert,omitempty"`
	Switched   int64           `json:"switched,omitempty"`
	Designated string          `json:"designated,omitempty"`
	Relays     []UpstreamRelay `json:"relays,omitempty"`
	Backup     *UpstreamBackup `json:"backup,omitempty"`
}

// UpstreamRelay is one relay line of a version 2 record. Pointer fields
// are nil when the gateway recorded "-" (not measured).
type UpstreamRelay struct {
	ID              string `json:"id"`
	Iface           string `json:"iface"`
	Status          string `json:"status"`
	Weight          int    `json:"weight"`
	Drain           bool   `json:"drain"`
	Reason          string `json:"reason,omitempty"`
	StatusSince     int64  `json:"status_since"`
	Grade           string `json:"grade"`
	RTTus           *int64 `json:"rtt_us,omitempty"`
	LossPermille    *int64 `json:"loss_permille,omitempty"`
	LastRTTus       *int64 `json:"last_rtt_us,omitempty"`
	LastLoss        *int64 `json:"last_loss_permille,omitempty"`
	MeasuredAt      int64  `json:"measured_at"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
	RxBps           int64  `json:"rx_bps"`
	TxBps           int64  `json:"tx_bps"`
	NewConns        int64  `json:"new_conns"`
	Suspicious      string `json:"suspicious,omitempty"`
	ProbeAt         int64  `json:"probe_at"`
	ProbeKbps       *int64 `json:"probe_kbps,omitempty"`
	ProbeLoss       *int64 `json:"probe_loss_permille,omitempty"`
	ProbeOK         *bool  `json:"probe_ok,omitempty"`
	ProbeBytesToday int64  `json:"probe_bytes_today"`
}

// UpstreamBackup is the backup line of a version 2 record.
type UpstreamBackup struct {
	Hub          string `json:"hub"`
	Iface        string `json:"iface"`
	Grade        string `json:"grade"`
	RTTus        *int64 `json:"rtt_us,omitempty"`
	LossPermille *int64 `json:"loss_permille,omitempty"`
	LastRTTus    *int64 `json:"last_rtt_us,omitempty"`
	LastLoss     *int64 `json:"last_loss_permille,omitempty"`
	MeasuredAt   int64  `json:"measured_at"`
	RxBytes      int64  `json:"rx_bytes"`
	TxBytes      int64  `json:"tx_bytes"`
	Drain        bool   `json:"drain"`
}

// UpstreamStatus is the agent's answer. Present is false when the file
// does not exist (not a dual-hub install, or not installed yet).
type UpstreamStatus struct {
	Present bool           `json:"present"`
	Record  *UpstreamState `json:"record,omitempty"`
	ReadAt  string         `json:"read_at"`
	Error   string         `json:"error,omitempty"`
}

var (
	reUpToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	reUpEpoch = regexp.MustCompile(`^[0-9]{1,12}$`)
)

// ParseUpstream checks the record against the grammar above.
func ParseUpstream(out string) (UpstreamState, error) {
	var st UpstreamState
	if len(out) > MaxUpstreamFile {
		return st, errors.New("上游记录过长，拒绝解析")
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) > 0 && lines[0] == "meridian-upstream 2" {
		return parseUpstream2(lines)
	}
	if len(lines) != 9 || lines[0] != "meridian-upstream 1" || lines[8] != "end" {
		return st, errors.New("上游记录格式不对")
	}
	st.Version = 1
	seen := map[string]bool{}
	for i, l := range lines[1:8] {
		f := strings.Fields(l)
		if len(f) != 2 || strings.Join(f, " ") != l || seen[f[0]] {
			return st, fmt.Errorf("上游记录第 %d 行格式不对", i+2)
		}
		seen[f[0]] = true
		v := f[1]
		epoch := func() (int64, error) {
			if !reUpEpoch.MatchString(v) {
				return 0, fmt.Errorf("上游记录第 %d 行时间不对", i+2)
			}
			return strconv.ParseInt(v, 10, 64)
		}
		var err error
		switch f[0] {
		case "beat":
			st.Beat, err = epoch()
		case "since":
			st.Since, err = epoch()
		case "path", "iface", "hub":
			if !reUpToken.MatchString(v) {
				return st, fmt.Errorf("上游记录第 %d 行的值不合格", i+2)
			}
			switch f[0] {
			case "path":
				st.Path = v
			case "iface":
				st.Iface = v
			default:
				st.Hub = v
			}
		case "tier":
			if v != "primary" && v != "backup" {
				return st, errors.New("上游记录的枢纽层级未知")
			}
			st.Tier = v
		case "state":
			switch v {
			case UpstreamStatic, UpstreamOK, UpstreamSwitching, UpstreamDown:
			default:
				return st, errors.New("上游记录的状态未知")
			}
			st.State = v
		default:
			return st, errors.New("上游记录有未知字段")
		}
		if err != nil {
			return st, err
		}
	}
	if st.Since > st.Beat {
		return st, errors.New("上游记录的切换时间晚于心跳")
	}
	return st, nil
}

// UpstreamStatus reads the gateway's upstream record.
func (a *Agent) UpstreamStatus(ctx context.Context) UpstreamStatus {
	a.init()
	st := UpstreamStatus{ReadAt: time.Now().UTC().Format(time.RFC3339)}
	path := UpstreamStateFile
	if a.PreflightRoot != "" {
		path = filepath.Join(a.PreflightRoot, UpstreamStateFile)
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return st
	}
	if err != nil {
		st.Error = "读不到上游记录：" + clip(firstLine(err.Error()))
		return st
	}
	defer f.Close()
	st.Present = true
	buf, err := io.ReadAll(io.LimitReader(f, MaxUpstreamFile+1))
	if err != nil {
		st.Error = "读不到上游记录：" + clip(firstLine(err.Error()))
		return st
	}
	rec, err := ParseUpstream(string(buf))
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Record = &rec
	return st
}

func (a *Agent) serveUpstreamStatus(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	// The only accepted body is an empty object: no caller-supplied value.
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	var empty struct{}
	if err := dec.Decode(&empty); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, UpstreamStatus{Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	writeJSON(w, http.StatusOK, a.UpstreamStatus(r.Context()))
}

// UpstreamStatus asks the agent for the gateway's upstream record.
func (c *Client) UpstreamStatus(ctx context.Context) (UpstreamStatus, error) {
	var st UpstreamStatus
	code, err := c.post(ctx, "/v1/upstream/status", struct{}{}, 10*time.Second, &st)
	if err != nil {
		return st, err
	}
	if code != http.StatusOK {
		return st, fmt.Errorf("host agent 读取上游状态失败（%d）：%s", code, st.Error)
	}
	return st, nil
}
