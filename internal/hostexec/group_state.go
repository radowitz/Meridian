package hostexec

// The gateway's own region-group state (direct-exit topologies): the
// gateway's failover script switches the groups itself and writes the same
// files a hub writes (/run/meridian/group-plan, group/<id>/report,
// exit-legs/report; see internal/compile hub_state.go). POST
// /v1/groups/state takes no parameter and answers the same framed text the
// hub read over SSH returns (sshexec.GroupStateCommand), so the panel parses
// both with hubstate.Parse.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// GroupStateDir is where the failover script keeps its group state.
const GroupStateDir = "/run/meridian"

// MaxGroupState caps the answer (the same limit as the hub read).
const MaxGroupState = 2 << 20

// GroupStateAnswer is the agent's answer.
type GroupStateAnswer struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// GroupState reads the gateway's group state files into the framed text.
// Missing files are skipped, like the hub command's `cat`.
func (a *Agent) GroupState() GroupStateAnswer {
	dir := GroupStateDir
	if a.PreflightRoot != "" {
		dir = filepath.Join(a.PreflightRoot, GroupStateDir)
	}
	var sb strings.Builder
	sb.WriteString("meridian-group-state 1\nnow " + strconv.FormatInt(time.Now().Unix(), 10) + "\n")
	add := func(p string) {
		f, err := os.Open(p)
		if err != nil {
			return
		}
		defer f.Close()
		b, _ := io.ReadAll(io.LimitReader(f, MaxGroupState+1))
		sb.Write(b)
	}
	add(filepath.Join(dir, "group-plan"))
	reports, _ := filepath.Glob(filepath.Join(dir, "group", "*", "report"))
	sort.Strings(reports)
	for _, p := range reports {
		add(p)
	}
	add(filepath.Join(dir, "exit-legs", "report"))
	sb.WriteString("meridian-group-state-end\n")
	out := sb.String()
	if len(out) > MaxGroupState+1 {
		out = out[:MaxGroupState+1]
	}
	return GroupStateAnswer{Output: out}
}

func (a *Agent) serveGroupState(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	var empty struct{}
	if err := dec.Decode(&empty); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, GroupStateAnswer{Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	writeJSON(w, http.StatusOK, a.GroupState())
}

// GatewayGroupState asks the agent for the gateway's group state text.
func (c *Client) GatewayGroupState(ctx context.Context) (string, error) {
	var ans GroupStateAnswer
	code, err := c.post(ctx, "/v1/groups/state", struct{}{}, 15*time.Second, &ans)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("host agent 读取地区组状态失败（%d）：%s", code, ans.Error)
	}
	return ans.Output, nil
}
