package hostexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
)

const dnsHostsFile = "/var/lib/meridian/keywords/meridian-panel-hosts.conf"

type DNSHost struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}
type DNSLocalRequest struct {
	Action string  `json:"action"`
	Host   DNSHost `json:"host,omitempty"`
}
type DNSLocalResult struct {
	Hosts        []DNSHost `json:"hosts"`
	HostsEnabled bool      `json:"hosts_enabled"`
	CacheEnabled bool      `json:"cache_enabled"`
	Error        string    `json:"error,omitempty"`
}

func normalizeDNSHost(h DNSHost) (DNSHost, error) {
	name, valid := ordered.NormDomain(h.Name)
	ip, err := netip.ParseAddr(strings.TrimSpace(h.IP))
	if !valid || err != nil || ip.Zone() != "" {
		return DNSHost{}, errors.New("请填写有效域名和 IPv4 或 IPv6 地址")
	}
	return DNSHost{Name: name, IP: ip.Unmap().String()}, nil
}

func parseDNSHosts(b []byte) ([]DNSHost, error) {
	rows := make([]DNSHost, 0)
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		prefix, rest, ok := strings.Cut(line, "/-.")
		name, ips, split := strings.Cut(rest, "/")
		if !ok || !split || prefix != "address " {
			return nil, errors.New("Hosts 文件格式不正确")
		}
		for _, ip := range strings.Split(ips, ",") {
			h, err := normalizeDNSHost(DNSHost{Name: name, IP: ip})
			if err != nil {
				return nil, err
			}
			rows = append(rows, h)
		}
	}
	return rows, nil
}

func renderDNSHosts(rows []DNSHost) []byte {
	slices.SortFunc(rows, func(a, b DNSHost) int {
		if n := strings.Compare(a.Name, b.Name); n != 0 {
			return n
		}
		return strings.Compare(a.IP, b.IP)
	})
	var out strings.Builder
	for i := 0; i < len(rows); {
		name := rows[i].Name
		fmt.Fprintf(&out, "address /-.%s/%s", name, rows[i].IP)
		i++
		for i < len(rows) && rows[i].Name == name {
			fmt.Fprintf(&out, ",%s", rows[i].IP)
			i++
		}
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

func (a *Agent) serveDNSLocal(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var req DNSLocalRequest
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
		writeJSON(w, http.StatusBadRequest, DNSLocalResult{Error: "请求格式不正确"})
		return
	}
	res, status := a.dnsLocal(r.Context(), req)
	writeJSON(w, status, res)
}

func (a *Agent) dnsLocal(ctx context.Context, req DNSLocalRequest) (DNSLocalResult, int) {
	res := DNSLocalResult{}
	fail := func(status int, err error) (DNSLocalResult, int) {
		res.Error = err.Error()
		return res, status
	}
	switch req.Action {
	case "status", "flush":
	case "add", "delete":
		h, err := normalizeDNSHost(req.Host)
		if err != nil {
			return fail(http.StatusBadRequest, err)
		}
		req.Host = h
	default:
		return fail(http.StatusBadRequest, errors.New("未知的 DNS 操作"))
	}
	a.init()
	wait, cancel := context.WithTimeout(ctx, a.LockWait)
	defer cancel()
	select {
	case a.sem <- struct{}{}:
	case <-wait.Done():
		return fail(http.StatusServiceUnavailable, errDNSReloadLocked)
	}
	defer func() { <-a.sem }()

	cfg, err := os.ReadFile(a.hostPath("/etc/smartdns/smartdns.conf"))
	res.CacheEnabled = err == nil && bytes.HasPrefix(cfg, []byte("# Meridian SmartDNS.")) &&
		bytes.Contains(cfg, []byte("\ncache-persist no\n"))
	res.HostsEnabled = res.CacheEnabled && bytes.Contains(cfg, []byte("\n"+model.DNSHostsInclude+"\n"))
	if req.Action == "flush" && !res.CacheEnabled {
		return fail(http.StatusConflict, errors.New("网关未安装关闭持久缓存的 Meridian SmartDNS 配置"))
	}
	path := a.hostPath(dnsHostsFile)
	var before []byte
	var existed bool
	if req.Action != "flush" {
		before, err = os.ReadFile(path)
		existed = err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail(http.StatusServiceUnavailable, err)
		}
		res.Hosts, err = parseDNSHosts(before)
		if err != nil {
			return fail(http.StatusServiceUnavailable, err)
		}
	}
	if req.Action == "status" {
		return res, http.StatusOK
	}
	change := req.Action != "flush"
	if change && !res.HostsEnabled {
		return fail(http.StatusConflict, errors.New("请先在部署页安装支持 Hosts 的网关解析配置"))
	}
	oldRows := slices.Clone(res.Hosts)
	if change {
		i := slices.Index(res.Hosts, req.Host)
		if req.Action == "add" {
			if i >= 0 {
				return res, http.StatusOK
			}
			if len(res.Hosts) >= 500 {
				return fail(http.StatusBadRequest, errors.New("最多保存 500 条 Hosts 记录"))
			}
			res.Hosts = append(res.Hosts, req.Host)
		} else {
			if i < 0 {
				return res, http.StatusOK
			}
			res.Hosts = slices.Delete(res.Hosts, i, i+1)
		}
		if err := writeFileAtomic(path, renderDNSHosts(res.Hosts), 0o644); err != nil {
			return fail(http.StatusServiceUnavailable, err)
		}
	}
	restart := func() error {
		runCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), a.ActionTimeout)
		defer stop()
		result, _ := a.doDNSReloadLocked(runCtx, dnsReq{force: true}, lists.DNSReloadResult{At: time.Now().UTC()})
		if result.SmartDNSOK {
			return nil
		}
		if result.Error != "" {
			return errors.New(result.Error)
		}
		return errors.New("没有运行中的网关 SmartDNS")
	}
	if err := restart(); err != nil {
		if change {
			var restored error
			if existed {
				restored = writeFileAtomic(path, before, 0o644)
			} else {
				restored = os.Remove(path)
			}
			if restored != nil {
				return fail(http.StatusServiceUnavailable, fmt.Errorf("%v；恢复 Hosts 文件失败：%w", err, restored))
			}
			res.Hosts = oldRows
			if restored = restart(); restored != nil {
				return fail(http.StatusServiceUnavailable, fmt.Errorf("%v；已恢复旧 Hosts 文件，但解析服务未确认恢复：%w", err, restored))
			}
		}
		return fail(http.StatusServiceUnavailable, err)
	}
	return res, http.StatusOK
}

func (c *Client) DNSLocal(ctx context.Context, req DNSLocalRequest) (DNSLocalResult, int, error) {
	var res DNSLocalResult
	status, err := c.post(ctx, "/v1/dns/local", req, 3*time.Minute, &res)
	return res, status, err
}
