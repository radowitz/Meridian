package hostexec

// The list update action (POST /v1/lists) and its read-only status
// (POST /v1/lists/status).
//
// Parameters are enumerations and managed names only: a policy (domestic,
// overseas, automatic), which kinds (geosite, chnroute), the v2fly category
// names and keyword rules compile produces. Source URLs come from package
// lists (plus the agent's own environment overrides, see lists.WithEnv);
// files are derived from the names under the fixed directory
// /var/lib/meridian. Nothing in a request is a URL, a path or a command.
//
// Locking. Downloading and expanding can take minutes and changes nothing
// on the host, so it runs without the action lock (an install is not held
// up by a slow mirror). Publishing — renaming list files, the one nft
// transaction for chnroute, and restarting SmartDNS when its files changed
// — takes the action lock (waiting at most LockWait), so it never
// interleaves with activate or rollback. Only one update runs at a time;
// a second gets 503. Like an action, an update runs to its own deadline
// (ListsTimeout) even if the caller goes away; the result is kept in
// /var/lib/meridian/lists/status.json for /v1/lists/status.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/lists"
)

func agentHTTP(sock string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives: true,
		},
	}
}

// DefaultListsDir holds geosite/, keywords/ and lists/ on the gateway.
const DefaultListsDir = "/var/lib/meridian"

// ListsRequest is the whole parameter set of a list update.
type ListsRequest struct {
	RequestID string `json:"request_id"`
	// Policy: domestic, overseas or automatic.
	Policy string `json:"policy"`
	// Lists: "geosite" and/or "chnroute".
	Lists []string `json:"lists"`
	// Geosite are v2fly category names (with "geosite" only).
	Geosite []string `json:"geosite,omitempty"`
	// Keywords are rebuilt from the geosite files (with "geosite" only).
	Keywords []lists.Keyword `json:"keywords,omitempty"`
}

const (
	maxCategories = 64
	maxKeywords   = 64
)

var (
	keywordIDRe    = regexp.MustCompile(`^[a-z0-9_]{1,80}$`)
	keywordValueRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`) // validate.checkRuleShape
)

// ErrListsBusy means another list update is running.
var ErrListsBusy = errors.New("名单更新已在进行，本次没有执行")

// ValidateLists checks a list update request completely.
func ValidateLists(req ListsRequest) error {
	if !requestIDRe.MatchString(req.RequestID) {
		return errors.New("request_id 不合法")
	}
	if _, ok := lists.ParsePolicy(req.Policy); !ok {
		return errors.New("policy 只能是 domestic、overseas 或 automatic")
	}
	if len(req.Lists) == 0 || len(req.Lists) > 2 {
		return errors.New("lists 需要 geosite、chnroute 中的一到两个")
	}
	geo := false
	seen := map[string]bool{}
	for _, l := range req.Lists {
		if l != lists.KindGeosite && l != lists.KindChnroute {
			return fmt.Errorf("不支持的名单 %q", l)
		}
		if seen[l] {
			return fmt.Errorf("名单 %q 重复", l)
		}
		seen[l] = true
		geo = geo || l == lists.KindGeosite
	}
	if !geo && (len(req.Geosite) > 0 || len(req.Keywords) > 0) {
		return errors.New("geosite / keywords 只能和 geosite 名单一起出现")
	}
	if geo && (len(req.Geosite) == 0 || len(req.Geosite) > maxCategories) {
		return fmt.Errorf("geosite 需要 1 到 %d 个分类", maxCategories)
	}
	names, files := map[string]bool{}, map[string]bool{}
	for _, n := range req.Geosite {
		if !lists.CategoryRe.MatchString(n) {
			return fmt.Errorf("geosite 分类名 %q 不合法", n)
		}
		f := lists.FileName(n)
		if names[n] || files[f] {
			return fmt.Errorf("geosite 分类 %q 重复（文件 %s.txt）", n, f)
		}
		names[n], files[f] = true, true
	}
	if len(req.Keywords) > maxKeywords {
		return fmt.Errorf("keywords 最多 %d 个", maxKeywords)
	}
	ids := map[string]bool{}
	for _, k := range req.Keywords {
		if !keywordIDRe.MatchString(k.ID) || ids[k.ID] {
			return fmt.Errorf("keyword id %q 不合法或重复", k.ID)
		}
		if !keywordValueRe.MatchString(k.Value) {
			return fmt.Errorf("keyword %q 不合法", k.Value)
		}
		ids[k.ID] = true
	}
	return nil
}

func (a *Agent) listsDir() string {
	if a.ListsDir != "" {
		return a.ListsDir
	}
	return DefaultListsDir
}

// UpdateLists validates and runs one update. 200 with the report when it
// ran (lists may still have failed), 400 refused, 503 busy.
func (a *Agent) UpdateLists(ctx context.Context, req ListsRequest) (lists.Report, int) {
	a.init()
	if err := ValidateLists(req); err != nil {
		return lists.Report{Error: err.Error()}, http.StatusBadRequest
	}
	select {
	case a.listsBusy <- struct{}{}:
	default:
		return lists.Report{Error: ErrListsBusy.Error()}, http.StatusServiceUnavailable
	}
	defer func() { <-a.listsBusy }()
	policy, _ := lists.ParsePolicy(req.Policy)
	ureq := lists.Request{Policy: policy, Keywords: req.Keywords}
	for _, l := range req.Lists {
		switch l {
		case lists.KindGeosite:
			ureq.Geosite = append([]string(nil), req.Geosite...)
		case lists.KindChnroute:
			ureq.Chnroute = true
		}
	}
	// Like an action: runs to its own deadline, not the caller's.
	uctx, cancel := context.WithTimeout(context.Background(), a.ListsTimeout)
	defer cancel()
	get := a.ListsGetter
	if get == nil {
		get = &lists.Fetcher{}
	}
	sources := a.ListsSources
	if sources == nil {
		sources = func(p lists.Policy) ([]lists.Source, error) { return lists.WithEnv(lists.Order(p), os.Getenv) }
	}
	u := &lists.Updater{
		Dir:     a.listsDir(),
		Get:     get,
		Sources: sources,
		LoadNFT: func(ctx context.Context, path string) error {
			x := &run{a: a, ctx: ctx}
			if _, err := x.cmd(a.StepTimeout, "nft", "list", "table", "inet", "meridian"); err != nil {
				return errors.New("inet meridian 未加载（先安装），chnroute 集合不存在")
			}
			out, err := x.cmd(a.StepTimeout, "nft", "-f", path)
			if err != nil {
				return fmt.Errorf("%v %s", err, firstLine(out))
			}
			return nil
		},
		Lock: func(ctx context.Context) (func(), error) {
			wait, cancel := context.WithTimeout(ctx, a.LockWait)
			defer cancel()
			select {
			case a.sem <- struct{}{}:
				return func() { <-a.sem }, nil
			case <-wait.Done():
				return nil, errors.New("宿主正在执行安装/回滚，等待超时；名单未发布，旧版本保留")
			}
		},
		AfterPublish: func(ctx context.Context, rep *lists.Report) {
			if !rep.DNSChanged {
				return
			}
			x := &run{a: a, ctx: ctx}
			switch x.dnsProvider() {
			case "unit":
				if _, err := x.cmd(a.StepTimeout, "systemctl", "restart", "smartdns.service"); err != nil {
					rep.Warnings = append(rep.Warnings, "名单已发布，但重启 smartdns.service 失败："+err.Error())
					return
				}
				rep.DNSRestart = "smartdns.service"
			case "container":
				if _, err := x.cmd(a.StepTimeout, "docker", "restart", SmartDNSContainer); err != nil {
					rep.Warnings = append(rep.Warnings, "名单已发布，但重启 "+SmartDNSContainer+" 失败："+err.Error())
					return
				}
				rep.DNSRestart = SmartDNSContainer
			default:
				rep.Warnings = append(rep.Warnings, "名单已发布，但没有运行中的 SmartDNS；它下次启动时读取新文件")
			}
		},
	}
	return u.Run(uctx, ureq), http.StatusOK
}

// ListsStatus reads the host's list status (read-only, no lock).
func (a *Agent) ListsStatus() (lists.Status, error) {
	return lists.ReadStatus(a.listsDir())
}

func (a *Agent) serveLists(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var req ListsRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, lists.Report{Error: "请求格式不正确"})
		return
	}
	rep, code := a.UpdateLists(r.Context(), req)
	writeJSON(w, code, rep)
}

func (a *Agent) serveListsStatus(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	st, err := a.ListsStatus()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// UpdateLists asks the agent for one update. It is not retried: the agent
// keeps the outcome in its status, and a second request while the first
// runs is refused (ErrListsBusy).
func (c *Client) UpdateLists(ctx context.Context, req ListsRequest) (lists.Report, error) {
	if err := ValidateLists(req); err != nil {
		return lists.Report{}, err
	}
	var rep lists.Report
	code, err := c.post(ctx, "/v1/lists", req, 25*time.Minute, &rep)
	if err != nil {
		return rep, err
	}
	switch code {
	case http.StatusOK:
		return rep, nil
	case http.StatusServiceUnavailable:
		return rep, fmt.Errorf("%w（%s）", ErrListsBusy, rep.Error)
	default:
		return rep, fmt.Errorf("host agent 拒绝名单更新（%d）：%s", code, rep.Error)
	}
}

// ListsStatus reads the agent's saved list status.
func (c *Client) ListsStatus(ctx context.Context) (lists.Status, error) {
	var st lists.Status
	code, err := c.post(ctx, "/v1/lists/status", struct{}{}, 30*time.Second, &st)
	if err != nil {
		return st, err
	}
	if code != http.StatusOK {
		return st, fmt.Errorf("host agent 读取名单状态失败（%d）", code)
	}
	return st, nil
}

// post sends one JSON request over the agent socket and decodes the reply.
func (c *Client) post(ctx context.Context, path string, body any, timeout time.Duration, out any) (int, error) {
	sock := c.Socket
	if sock == "" {
		sock = DefaultSocket
	}
	tokPath := c.TokenFile
	if tokPath == "" {
		tokPath = DefaultTokenFile
	}
	if st, err := os.Stat(sock); err != nil || st.Mode()&os.ModeSocket == 0 {
		return 0, fmt.Errorf("%w：没有 %s", ErrUnavailable, sock)
	}
	raw, err := os.ReadFile(tokPath)
	if err != nil {
		return 0, fmt.Errorf("%w：读不到口令文件 %s", ErrUnavailable, tokPath)
	}
	b, _ := json.Marshal(body)
	hc := agentHTTP(sock, timeout)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://meridian-host"+path, strings.NewReader(string(b)))
	if err != nil {
		return 0, err
	}
	hreq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(raw)))
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(hreq)
	if err != nil {
		if isDialErr(err) {
			return 0, fmt.Errorf("%w：%v", ErrUnavailable, err)
		}
		return 0, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return resp.StatusCode, fmt.Errorf("host agent 应答格式不正确（%s）", resp.Status)
	}
	return resp.StatusCode, nil
}
