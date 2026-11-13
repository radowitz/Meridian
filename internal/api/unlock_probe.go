package api

// Panel-run unlock probes.
//
// The panel's "立即测试" and the 6-hour scheduler share one execution chain:
//
//	startProbeJob(kind, selection)       plan: service × exit × family, validated
//	  → runProbeJob                      at most probeExitConcurrency exits at once
//	    → runProbeGroup (one exit)       one host-agent probe per family, sequential
//	      → Prober.Probe                 hostexec.Client → meridian-host /v1/probe
//	        → probe.Prober.Run           egress check, catalog adapters, egress re-check
//	      → unlock.Ingest                one Observation per service with every family
//	                                     of this run, under s.mu (load → Ingest → save)
//
// Kind is scheduled for the scheduler and manual for the panel button, so
// only scheduled verdicts count toward the two-failure demotion. The only
// category → state mapping is probe.IngestVerdict: unlocked = success,
// not_unlocked = failure, everything else (network_ok = reachability only,
// unknown, failed) = no verdict. A service whose families all ended without
// a platform verdict is ingested as unlock.KindInconclusive: it never
// demotes and never restores, but it does end the preferred member's
// recovery streak. Only the primary check of a multi-platform adapter is
// ingested; informational parts are shown only. Results of a cancelled job
// are recorded in the job but not ingested.
//
// REST (all under the panel token):
//
//	GET  /api/unlock/catalog          adapters, capabilities, sources, validation status
//	POST /api/unlock/run              {services?, exits?, groups?, families?} → 202 {job}
//	GET  /api/unlock/jobs             {jobs (newest first), running, catalog, available}
//	                                  (available = a probe channel is configured; it does
//	                                  not check that meridian-host answers — GET
//	                                  /api/status probe_available / probe_reason does)
//	GET  /api/unlock/jobs/{id}        {job, running}
//	POST /api/unlock/jobs/{id}/cancel
//	GET  /api/unlock/results          newest item per service/exit/family, with the
//	                                  exit's groups and the live active member;
//	                                  filters ?service= &exit= &group= &family=
//	GET  /api/unlock                  state machine, decisions and history
//
// The job record (kv "unlock_jobs", last maxProbeJobs jobs) keeps per
// service / exit / family the start and finish time, category, region,
// evidence, egress evidence, error and what Ingest did with it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/hubstate"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

// ProbeRuntime is the host agent's probe endpoint (hostexec.Client).
type ProbeRuntime interface {
	Probe(ctx context.Context, req hostexec.ProbeRequest) (probe.Report, error)
}

const (
	probeJobsKey = "unlock_jobs"
	maxProbeJobs = 10
	// probeExitConcurrency matches the agent's MaxProbes default.
	probeExitConcurrency = 2
	// probeRequestTimeout bounds one agent call (the agent caps itself at 3m).
	probeRequestTimeout = 200 * time.Second
	defaultJobTimeout   = 15 * time.Minute
	maxProbeItems       = 256
	maxSelectExits      = 32
)

// Job and item states.
const (
	jobRunning     = "running"
	jobDone        = "done"
	jobCancelled   = "cancelled"
	jobTimedOut    = "timeout"
	jobInterrupted = "interrupted"

	itemQueued  = "queued"
	itemRunning = "running"
	itemDone    = "done"
	itemSkipped = "skipped"
)

var (
	errJobRunning = errors.New("已有一轮解锁探测在运行，等它结束或先取消")
	errNoProber   = errors.New("面板没有宿主探测能力（meridian-host 未运行或未挂载），无法从面板发起解锁探测；路由保持不变")
)

type probeJobItem struct {
	Service     string         `json:"service"`
	ServiceName string         `json:"service_name"`
	ExitID      string         `json:"exit_id"`
	ExitRegion  string         `json:"exit_region,omitempty"`
	Family      unlock.Family  `json:"family"`
	State       string         `json:"state"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	FinishedAt  *time.Time     `json:"finished_at,omitempty"`
	Category    probe.Category `json:"category,omitempty"`
	// Grade is probe.GradeOf(Category), recomputed by the panel; Signal the
	// marker code; Capability the adapter's declaration; Validation is
	// always probe.Validation ("synthetic_only") in this build.
	Grade      probe.Grade      `json:"grade,omitempty"`
	Signal     string           `json:"signal,omitempty"`
	Capability probe.Capability `json:"capability,omitempty"`
	Validation string           `json:"validation,omitempty"`
	Region     string           `json:"region,omitempty"`
	Status     int              `json:"status,omitempty"`
	Evidence   string           `json:"evidence,omitempty"`
	// Parts are the per-platform checks of a multi-platform service; only
	// the primary one is ingested.
	Parts       []probe.Part `json:"parts,omitempty"`
	Egress      string       `json:"egress,omitempty"`
	EgressIP    string       `json:"egress_ip,omitempty"`
	EgressBasis string       `json:"egress_basis,omitempty"`
	EgressIface string       `json:"egress_iface,omitempty"`
	Error       string       `json:"error,omitempty"`
	// Group context at plan time: the rule's region group, its mode, whether
	// the exit is a member; ActiveExit is the member carrying the service
	// after this item was ingested.
	Group      string `json:"group,omitempty"`
	GroupMode  string `json:"group_mode,omitempty"`
	InGroup    bool   `json:"in_group"`
	ActiveExit string `json:"active_exit,omitempty"`
	// Ingest is what unlock.Ingest did: accepted, accepted:inconclusive,
	// rejected:<reason>, note:<text>, or not_ingested:<why>.
	Ingest string `json:"ingest,omitempty"`
	// Transport is "tcp_only" for an external SOCKS exit: the probe went
	// through its proxy over TCP (HTTPS); Untested names what such an exit
	// cannot carry and so was not tested (anything that needs UDP). A pass
	// says nothing about those.
	Transport string   `json:"transport,omitempty"`
	Untested  []string `json:"untested,omitempty"`
}

// tcpOnlyUntested is what an external (TCP-only SOCKS) exit cannot carry.
var tcpOnlyUntested = []string{"UDP（QUIC / HTTP/3、DNS over UDP 直连、语音视频通话、部分游戏）：外部 SOCKS 出口只承载 TCP，UDP 在承载节点上被拒绝，无法测试也无法使用"}

type probeJob struct {
	ID         string         `json:"id"`
	Kind       unlock.Kind    `json:"kind"`
	State      string         `json:"state"`
	CreatedAt  time.Time      `json:"created_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Error      string         `json:"error,omitempty"`
	Items      []probeJobItem `json:"items"`
}

type probeJobsDoc struct {
	Jobs []probeJob `json:"jobs"`
}

type jobHandle struct {
	id     string
	cancel context.CancelFunc
	done   chan struct{}
}

type probeSelection struct {
	Services []string `json:"services,omitempty"`
	Exits    []string `json:"exits,omitempty"`
	// Groups adds every member of these region groups to Exits.
	Groups   []string `json:"groups,omitempty"`
	Families []string `json:"families,omitempty"`
}

// probeGroup is one exit's share of a job. sent lists, per family, the
// services actually sent (an IPv4-only adapter is not sent on IPv6).
type probeGroup struct {
	exit     compile.ProbeExit
	families []unlock.Family
	services []string
	sent     map[unlock.Family][]string
}

// newItem fills the static part of a job item.
func newItem(svc unlock.Service, ex compile.ProbeExit, fam unlock.Family, state string) probeJobItem {
	it := probeJobItem{
		Service: svc.RuleID, ServiceName: svc.Name, ExitID: ex.ID, ExitRegion: ex.Region, Family: fam, State: state,
		Validation: probe.Validation, Group: svc.Pool, InGroup: containsStr(svc.Members, ex.ID),
	}
	if a, ok := probe.Lookup(svc.RuleID); ok {
		it.Capability = a.Capability
	}
	it.GroupMode = string(model.GroupAuto)
	if svc.Pin {
		it.GroupMode = string(model.GroupManual)
	}
	if ex.TCPOnly {
		it.Transport, it.Untested = "tcp_only", tcpOnlyUntested
	}
	return it
}

func (s *Server) loadJobs() probeJobsDoc {
	raw, ok, err := s.Store.Get(probeJobsKey)
	if err != nil || !ok || raw == "" {
		return probeJobsDoc{}
	}
	var doc probeJobsDoc
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return probeJobsDoc{}
	}
	return doc
}

func (s *Server) saveJobs(doc probeJobsDoc) error {
	if len(doc.Jobs) > maxProbeJobs {
		doc.Jobs = doc.Jobs[len(doc.Jobs)-maxProbeJobs:]
	}
	buf, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return s.Store.Put(probeJobsKey, string(buf))
}

// updateJob applies f to the stored job. Caller holds s.mu.
func (s *Server) updateJob(id string, f func(*probeJob)) {
	doc := s.loadJobs()
	for i := range doc.Jobs {
		if doc.Jobs[i].ID == id {
			f(&doc.Jobs[i])
			if err := s.saveJobs(doc); err != nil {
				log.Printf("unlock probe job %s: save failed: %v", id, err)
			}
			return
		}
	}
}

// markInterrupted closes jobs left "running" by a previous process. Caller
// holds s.mu.
func (s *Server) markInterrupted(except string) {
	doc := s.loadJobs()
	changed := false
	for i := range doc.Jobs {
		j := &doc.Jobs[i]
		if j.State != jobRunning || j.ID == except {
			continue
		}
		now := time.Now().UTC()
		j.State, j.FinishedAt, changed = jobInterrupted, &now, true
		j.Error = "面板进程在探测途中退出，这一轮没有完成；未完成的项没有入库"
		for k := range j.Items {
			if j.Items[k].State == itemQueued || j.Items[k].State == itemRunning {
				j.Items[k].State = itemSkipped
				j.Items[k].Ingest = "not_ingested:interrupted"
			}
		}
	}
	if changed {
		_ = s.saveJobs(doc)
	}
}

func adapterServices(t model.Topology, includePinned bool) []unlock.Service {
	var out []unlock.Service
	for _, svc := range servicesOf(t) {
		if !probe.Probeable(svc.RuleID) {
			continue
		}
		if svc.Pin && !includePinned {
			continue
		}
		out = append(out, svc)
	}
	return out
}

// planProbe turns a selection into per-exit groups plus items that will not
// be sent (unsupported family, no resolver, nothing to confirm egress with).
func planProbe(t model.Topology, sel probeSelection) ([]probeGroup, []probeJobItem, error) {
	exits, err := compile.ProbeExits(t)
	if err != nil {
		return nil, nil, fmt.Errorf("拓扑无法编译出出口参数：%v", err)
	}
	all := map[string]unlock.Service{}
	for _, svc := range adapterServices(t, true) {
		all[svc.RuleID] = svc
	}
	var services []unlock.Service
	if len(sel.Services) == 0 {
		services = adapterServices(t, false)
	} else {
		if len(sel.Services) > len(probe.Catalog) {
			return nil, nil, errors.New("services 过多")
		}
		seen := map[string]bool{}
		for _, id := range sel.Services {
			svc, ok := all[id]
			if !ok {
				if !probe.Probeable(id) {
					return nil, nil, fmt.Errorf("服务 %q 没有可执行的面板探测适配器（只能用出口上的 regioncheck 报告）", id)
				}
				return nil, nil, fmt.Errorf("服务 %q 不是已启用的池规则", id)
			}
			if seen[id] {
				return nil, nil, fmt.Errorf("服务 %q 重复", id)
			}
			seen[id] = true
			services = append(services, svc)
		}
	}
	if len(services) == 0 {
		return nil, nil, errors.New("没有可以从面板探测的自动规则")
	}
	if len(sel.Exits) > maxSelectExits || len(sel.Groups) > maxSelectExits {
		return nil, nil, errors.New("exits / groups 过多")
	}
	for _, id := range sel.Exits {
		if _, ok := exits[id]; !ok {
			return nil, nil, fmt.Errorf("出口 %q 不存在", id)
		}
	}
	targetsSel := append([]string(nil), sel.Exits...)
	for _, gid := range sel.Groups {
		g, ok := t.GroupByID(gid)
		if !ok {
			return nil, nil, fmt.Errorf("地区组 %q 不存在", gid)
		}
		for _, id := range g.Members {
			if _, ok := exits[id]; ok && !containsStr(targetsSel, id) {
				targetsSel = append(targetsSel, id)
			}
		}
	}
	if len(sel.Groups) > 0 && len(targetsSel) == 0 {
		return nil, nil, errors.New("所选地区组没有可探测的出口")
	}
	var fams []unlock.Family
	for _, f := range sel.Families {
		fam, ok := unlock.ParseFamily(f)
		if !ok || fam == unlock.FamilyAny {
			return nil, nil, errors.New("families 只能是 ipv4 / ipv6")
		}
		if !containsFam(fams, fam) {
			fams = append(fams, fam)
		}
	}

	byExit := map[string][]string{}
	for _, svc := range services {
		targets := targetsSel
		if len(targets) == 0 {
			targets = svc.Members
		}
		for _, id := range targets {
			if _, ok := exits[id]; ok && !containsStr(byExit[id], svc.RuleID) {
				byExit[id] = append(byExit[id], svc.RuleID)
			}
		}
	}
	ids := make([]string, 0, len(byExit))
	for id := range byExit {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	byID := map[string]unlock.Service{}
	for _, svc := range services {
		byID[svc.RuleID] = svc
	}

	var groups []probeGroup
	var skipped []probeJobItem
	count := 0
	for _, id := range ids {
		ex := exits[id]
		want := fams
		if len(want) == 0 {
			if ex.EgressV4 {
				want = append(want, unlock.FamilyIPv4)
			}
			if ex.EgressV6 {
				want = append(want, unlock.FamilyIPv6)
			}
		}
		g := probeGroup{exit: ex, services: byExit[id], sent: map[unlock.Family][]string{}}
		for _, fam := range want {
			reason := ""
			switch {
			case fam == unlock.FamilyIPv4 && !ex.EgressV4:
				reason = "出口没有 IPv4 出口能力（egress_v4=false），未探测"
			case fam == unlock.FamilyIPv6 && ex.TCPOnly:
				reason = "外部 SOCKS 出口只承载 IPv4 的 TCP：IPv6 无法测试（不是通过）"
			case fam == unlock.FamilyIPv6 && !ex.EgressV6:
				reason = "出口没有 IPv6 出口能力（egress_v6=false），未探测"
			case ex.Resolver == "":
				reason = "出口没有隧道解析器地址，不能经出口解析，未探测"
			case ex.Region == "" && expectAddr(ex, fam) == "":
				reason = "出口既没有地区也没有该地址族的公网端点，无法确认实际出口，未探测"
			}
			for _, svc := range g.services {
				count++
				switch {
				case reason != "":
					it := newItem(byID[svc], ex, fam, itemSkipped)
					it.Category, it.Grade, it.Error, it.Ingest = probe.CatFailed, probe.GradeError, reason, "not_ingested:not_sent"
					skipped = append(skipped, it)
				case !probe.SupportsFamily(svc, fam):
					it := newItem(byID[svc], ex, fam, itemSkipped)
					it.Category, it.Grade, it.Signal = probe.CatNotApplicable, probe.GradeNotApplicable, probe.SigFamily
					it.Error, it.Ingest = "该服务的公开检测方法只支持 IPv4，未探测 IPv6", "not_ingested:family_not_supported"
					skipped = append(skipped, it)
				default:
					g.sent[fam] = append(g.sent[fam], svc)
				}
			}
			if reason == "" && len(g.sent[fam]) > 0 {
				g.families = append(g.families, fam)
			}
		}
		if len(g.families) > 0 {
			groups = append(groups, g)
		}
	}
	if count > maxProbeItems {
		return nil, nil, fmt.Errorf("这一轮有 %d 项，超过上限 %d；请缩小服务或出口范围", count, maxProbeItems)
	}
	if count == 0 {
		return nil, nil, errors.New("所选服务和出口没有可探测的组合")
	}
	return groups, skipped, nil
}

func containsFam(fs []unlock.Family, f unlock.Family) bool {
	for _, v := range fs {
		if v == f {
			return true
		}
	}
	return false
}

func expectAddr(ex compile.ProbeExit, fam unlock.Family) string {
	if fam == unlock.FamilyIPv6 {
		return ex.EndpointV6
	}
	return ex.EndpointV4
}

// startProbeJob validates the selection, records the job and starts it.
// Only one job runs at a time.
func (s *Server) startProbeJob(kind unlock.Kind, sel probeSelection) (probeJob, error) {
	if s.Prober == nil {
		return probeJob{}, errNoProber
	}
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if s.job != nil {
		return probeJob{}, errJobRunning
	}
	s.mu.Lock()
	t, err := s.topology()
	if err != nil {
		s.mu.Unlock()
		return probeJob{}, err
	}
	groups, skipped, err := planProbe(t, sel)
	if err != nil {
		s.mu.Unlock()
		return probeJob{}, err
	}
	svcs := map[string]unlock.Service{}
	for _, svc := range servicesOf(t) {
		svcs[svc.RuleID] = svc
	}
	job := probeJob{ID: "job-" + time.Now().UTC().Format("20060102T150405") + "-" + randHex(3), Kind: kind, State: jobRunning, CreatedAt: time.Now().UTC()}
	for _, g := range groups {
		for _, fam := range g.families {
			for _, svc := range g.sent[fam] {
				job.Items = append(job.Items, newItem(svcs[svc], g.exit, fam, itemQueued))
			}
		}
	}
	job.Items = append(job.Items, skipped...)
	s.markInterrupted("")
	doc := s.loadJobs()
	doc.Jobs = append(doc.Jobs, job)
	err = s.saveJobs(doc)
	if err == nil && kind == unlock.KindScheduled {
		snap := s.loadUnlock()
		snap.NextRun = time.Now().UTC().Add(unlock.Interval(t.Settings.UnlockIntervalSec))
		err = s.saveUnlock(snap)
	}
	s.mu.Unlock()
	if err != nil {
		return probeJob{}, err
	}
	timeout := s.ProbeJobTimeout
	if timeout <= 0 {
		timeout = defaultJobTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	h := &jobHandle{id: job.ID, cancel: cancel, done: make(chan struct{})}
	s.job = h
	go s.runProbeJob(ctx, h, kind, groups)
	return job, nil
}

func (s *Server) runProbeJob(ctx context.Context, h *jobHandle, kind unlock.Kind, groups []probeGroup) {
	defer close(h.done)
	defer h.cancel()
	sem := make(chan struct{}, probeExitConcurrency)
	var wg sync.WaitGroup
	for _, g := range groups {
		wg.Add(1)
		go func(g probeGroup) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				s.closeGroup(h.id, g, ctx)
				return
			}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				s.closeGroup(h.id, g, ctx)
				return
			}
			s.runProbeGroup(ctx, h.id, kind, g)
		}(g)
	}
	wg.Wait()
	state := jobDone
	errText := ""
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		state, errText = jobTimedOut, "整轮探测超时，未完成的项没有入库"
	case ctx.Err() != nil:
		state, errText = jobCancelled, "已在面板取消，未完成的项没有入库"
	}
	s.mu.Lock()
	s.updateJob(h.id, func(j *probeJob) {
		now := time.Now().UTC()
		j.State, j.FinishedAt = state, &now
		if j.Error == "" {
			j.Error = errText
		}
	})
	s.mu.Unlock()
	s.jobMu.Lock()
	if s.job == h {
		s.job = nil
	}
	s.jobMu.Unlock()
}

// closeGroup marks a group that never started.
func (s *Server) closeGroup(id string, g probeGroup, ctx context.Context) {
	why := cancelWhy(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateJob(id, func(j *probeJob) {
		for k := range j.Items {
			it := &j.Items[k]
			if it.ExitID == g.exit.ID && it.State == itemQueued {
				it.State, it.Category, it.Grade, it.Error, it.Ingest = itemSkipped, probe.CatFailed, probe.GradeError, why, "not_ingested:cancelled"
			}
		}
	})
}

func cancelWhy(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "整轮超时，未开始"
	}
	return "已取消，未开始"
}

func (s *Server) runProbeGroup(ctx context.Context, jobID string, kind unlock.Kind, g probeGroup) {
	// One run of this exit: every family shares one observation time (panel
	// clock), and all families reach Ingest together.
	observed := time.Now().UTC()
	s.mu.Lock()
	s.updateJob(jobID, func(j *probeJob) {
		for k := range j.Items {
			it := &j.Items[k]
			if it.ExitID == g.exit.ID && it.State == itemQueued {
				it.State, it.StartedAt = itemRunning, &observed
			}
		}
	})
	s.mu.Unlock()

	reports := map[unlock.Family]probe.Report{}
	for _, fam := range g.families {
		req := hostexec.ProbeRequest{
			RequestID: jobID + "/" + g.exit.ID + "/" + string(fam),
			ExitID:    g.exit.ID, Family: string(fam), Mark: g.exit.Mark,
			TransitV4: g.exit.TransitV4, TransitV6: g.exit.TransitV6, Resolver: g.exit.Resolver,
			Region: unlock.NormRegion(g.exit.Region), ExpectAddr: expectAddr(g.exit, fam), Services: g.sent[fam],
		}
		spec := probe.Spec{ExitID: g.exit.ID, Family: fam, Services: g.sent[fam]}
		var rep probe.Report
		if ctx.Err() != nil {
			rep = probe.FailedReport(spec, cancelWhy(ctx), time.Now())
		} else {
			rctx, cancel := context.WithTimeout(ctx, probeRequestTimeout)
			var err error
			rep, err = s.Prober.Probe(rctx, req)
			cancel()
			if err != nil {
				msg := err.Error()
				if ctx.Err() != nil {
					msg = cancelText(ctx)
				}
				rep = probe.FailedReport(spec, msg, time.Now())
			}
		}
		reports[fam] = sanitizeReport(rep, spec)
	}
	cancelled := ctx.Err() != nil

	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.topology()
	if err != nil {
		return
	}
	svcByID := map[string]unlock.Service{}
	for _, svc := range servicesOf(t) {
		svcByID[svc.RuleID] = svc
	}
	snap := s.loadUnlock()
	ingest := map[string]string{} // service|family → outcome
	for _, id := range g.services {
		svc, ok := svcByID[id]
		if !ok {
			for _, fam := range g.families {
				ingest[id+"|"+string(fam)] = "not_ingested:规则已不存在"
			}
			continue
		}
		// probe.IngestVerdict is the only category → state mapping:
		// unlocked = success, not_unlocked = failure, anything else
		// (reachability only, unknown, failed) = no verdict.
		sentFams := []unlock.Family{}
		verdicts := map[unlock.Family]bool{}
		for _, fam := range g.families {
			if !containsStr(g.sent[fam], id) {
				continue
			}
			sentFams = append(sentFams, fam)
			r, _ := findResult(reports[fam], id)
			if ok, has := probe.IngestVerdict(r.Category); has {
				verdicts[fam] = ok
			}
		}
		obKind, results := kind, verdicts
		if len(verdicts) == 0 {
			if cancelled {
				for _, fam := range sentFams {
					ingest[id+"|"+string(fam)] = "not_ingested:cancelled"
				}
				continue
			}
			obKind, results = unlock.KindInconclusive, map[unlock.Family]bool{}
			for _, fam := range sentFams {
				results[fam] = false
			}
		}
		note := ingestNote(svc, g.exit.ID)
		seedState(&snap, svc)
		ob := unlock.Observation{Service: id, ExitID: g.exit.ID, Kind: obKind, ObservedAt: observed, Results: results}
		for _, o := range unlock.Ingest(&snap, ob, svc.Members, note, time.Now()) {
			k := id + "|" + string(o.Family)
			switch {
			case o.Note != "":
				ingest[k] = "note:" + o.Note
			case o.Rejected != "":
				ingest[k] = "rejected:" + o.Rejected
			case obKind == unlock.KindInconclusive:
				ingest[k] = "accepted:inconclusive"
			default:
				ingest[k] = "accepted"
			}
		}
		for _, fam := range sentFams {
			if _, done := ingest[id+"|"+string(fam)]; !done {
				ingest[id+"|"+string(fam)] = "not_ingested:no_verdict"
			}
		}
	}
	if err := s.saveUnlock(snap); err != nil {
		log.Printf("unlock probe job %s: saving results failed: %v", jobID, err)
		for k := range ingest {
			ingest[k] = "not_ingested:save_failed"
		}
	}
	var finished []probeJobItem
	s.updateJob(jobID, func(j *probeJob) {
		for k := range j.Items {
			it := &j.Items[k]
			if it.ExitID != g.exit.ID || it.State != itemRunning {
				continue
			}
			rep := reports[it.Family]
			r, _ := findResult(rep, it.Service)
			st, fin := r.StartedAt, r.FinishedAt
			if st.IsZero() {
				st = observed
			}
			if fin.IsZero() {
				fin = time.Now().UTC()
			}
			it.State, it.StartedAt, it.FinishedAt = itemDone, &st, &fin
			it.Category, it.Region, it.Evidence, it.Error = r.Category, r.Region, r.Evidence, r.Error
			it.Grade, it.Signal, it.Status, it.Parts = probe.GradeOf(r.Category), r.Signal, r.Status, r.Parts
			if rep.Egress.Confirmed {
				it.Egress = rep.Egress.Evidence
				it.EgressIP, it.EgressBasis, it.EgressIface = rep.Egress.IP, rep.Egress.Basis, rep.Egress.Interface
			} else if rep.Egress.Error != "" {
				it.Egress = "未确认：" + rep.Egress.Error
			}
			it.Ingest = ingest[it.Service+"|"+string(it.Family)]
			it.ActiveExit = activeFor(snap, svcByID[it.Service])
			finished = append(finished, *it)
		}
	})
	s.recordResults(finished)
}

// activeFor is the exit currently carrying svc: the unlock decision inside
// an automatic group, else the group's preferred/chosen member.
func activeFor(snap unlock.Snapshot, svc unlock.Service) string {
	if svc.RuleID == "" {
		return ""
	}
	if d, ok := unlock.Decisions(snap, []unlock.Service{svc})[svc.RuleID]; ok {
		return d
	}
	return svc.Preferred
}

func cancelText(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "整轮超时"
	}
	return "已取消"
}

func findResult(rep probe.Report, service string) (probe.Result, bool) {
	for _, r := range rep.Results {
		if r.Service == service {
			return r, true
		}
	}
	return probe.Result{Service: service, Category: probe.CatFailed, Error: "agent 没有返回这个服务的结果"}, false
}

// sanitizeReport keeps only results the job asked for, of the exit and
// family it asked for, with a category the adapter declared, and bounds the
// text. A malformed or confused agent answer cannot invent a verdict for
// another exit, service or family; the grade is recomputed here.
func sanitizeReport(rep probe.Report, spec probe.Spec) probe.Report {
	out := rep
	out.Results = nil
	wrongExit := rep.ExitID != spec.ExitID || (rep.Family != "" && rep.Family != spec.Family)
	for _, r := range rep.Results {
		if !containsStr(spec.Services, r.Service) || r.Family != spec.Family {
			continue
		}
		a, _ := probe.Lookup(r.Service)
		notApplicable := r.Category == probe.CatNotApplicable && !probe.SupportsFamily(r.Service, spec.Family)
		r.Category, r.Signal = sanitizeCategory(a, r.Category, r.Signal)
		switch {
		case notApplicable && !wrongExit:
			// Nothing was sent for a family the check does not support: not a
			// platform result, whatever the egress check said.
			r.Category, r.Region, r.Signal, r.Parts = probe.CatNotApplicable, "", probe.SigFamily, nil
		case wrongExit:
			r.Category, r.Region, r.Signal, r.Error = probe.CatFailed, "", probe.SigEgressChanged, "agent 报告的出口或地址族与请求不符，不作为平台结果"
		case !rep.Egress.Confirmed && r.Category != probe.CatFailed:
			r.Category, r.Region, r.Error = probe.CatFailed, "", "出口未确认，不作为平台结果"
		}
		r.Grade, r.Capability = probe.GradeOf(r.Category), a.Capability
		r.Evidence, r.Error, r.Region, r.Signal = clipText(r.Evidence, 400), clipText(r.Error, 400), clipText(r.Region, 12), clipText(r.Signal, 40)
		if len(r.Parts) > 4 {
			r.Parts = r.Parts[:4]
		}
		parts := make([]probe.Part, 0, len(r.Parts))
		for _, pt := range r.Parts {
			pt.Category, pt.Signal = sanitizeCategory(a, pt.Category, pt.Signal)
			if wrongExit || (!rep.Egress.Confirmed && pt.Category != probe.CatFailed) {
				pt.Category, pt.Region = probe.CatFailed, ""
			}
			pt.Grade = probe.GradeOf(pt.Category)
			pt.Platform, pt.Evidence, pt.Error = clipText(pt.Platform, 40), clipText(pt.Evidence, 300), clipText(pt.Error, 300)
			pt.Region, pt.Signal = clipText(pt.Region, 12), clipText(pt.Signal, 40)
			parts = append(parts, pt)
		}
		if len(parts) == 0 {
			parts = nil
		}
		r.Parts = parts
		out.Results = append(out.Results, r)
	}
	if wrongExit {
		out.Egress.Confirmed = false
		out.Egress.Error = "agent 报告的出口与请求不符"
	}
	out.Egress.Evidence = clipText(out.Egress.Evidence, 400)
	out.Egress.Error = clipText(out.Egress.Error, 400)
	return out
}

// sanitizeCategory: unknown categories become unknown, and a category the
// adapter did not declare (an "unlocked" from a reachability adapter, say)
// is downgraded: platform verdicts to unknown, reachability to unknown.
// not_applicable is accepted only by sanitizeReport, for a family the
// service's check does not support; here it is an unknown category.
func sanitizeCategory(a probe.Adapter, c probe.Category, sig string) (probe.Category, string) {
	switch c {
	case probe.CatNetworkOK, probe.CatUnlocked, probe.CatNotUnlocked, probe.CatFailed, probe.CatUnknown:
	default:
		return probe.CatUnknown, probe.SigUnexpected
	}
	if !a.Allows(c) {
		return probe.CatUnknown, probe.SigUnexpected
	}
	return c, sig
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ingestNote: a pinned rule or an exit outside the pool is recorded only.
func ingestNote(svc unlock.Service, exitID string) string {
	switch {
	case svc.Pin:
		return "钉死规则不受解锁结果影响，只记录。"
	case !containsStr(svc.Members, exitID):
		return "出口不在该服务的池里，不改变路由，也不换国家。"
	}
	return ""
}

func seedState(snap *unlock.Snapshot, svc unlock.Service) {
	if snap.Services == nil {
		snap.Services = map[string]unlock.State{}
	}
	// A fresh state starts on the group's preferred member; an existing
	// one is re-aligned when the group's order changed (unlock.Reconcile).
	snap.Services[svc.RuleID] = unlock.Reconcile(snap.Services[svc.RuleID], svc)
}

// ---- HTTP ------------------------------------------------------------------

func (s *Server) postUnlockRun(w http.ResponseWriter, r *http.Request) {
	body, err := readLimited(r, 16<<10)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var sel probeSelection
	if len(strings.TrimSpace(string(body))) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&sel); err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("请求只接受 services / exits / families"))
			return
		}
	}
	job, err := s.startProbeJob(unlock.KindManual, sel)
	switch {
	case errors.Is(err, errNoProber):
		writeErr(w, http.StatusServiceUnavailable, err)
	case errors.Is(err, errJobRunning):
		writeErr(w, http.StatusConflict, err)
	case err != nil:
		writeErr(w, http.StatusBadRequest, err)
	default:
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
	}
}

// catalogEntry is one adapter's capability declaration as the panel shows
// it. Validation is "synthetic_only" for every adapter of this build: the
// rules come from public methods and synthetic fixtures and have not been
// validated against the real platform by this project.
type catalogEntry struct {
	Service        string           `json:"service"`
	Name           string           `json:"name"`
	Capability     probe.Capability `json:"capability"`
	Reachability   bool             `json:"reachability"`
	Returns        []probe.Category `json:"returns"`
	IPv4Only       bool             `json:"ipv4_only"`
	Probeable      bool             `json:"probeable"`
	Platforms      []probe.Platform `json:"platforms"`
	Requests       []string         `json:"requests"`
	Hosts          []string         `json:"hosts"`
	Combine        string           `json:"combine,omitempty"`
	Basis          string           `json:"basis"`
	Limits         string           `json:"limits"`
	Sources        []probe.Source   `json:"sources"`
	Validation     string           `json:"validation"`
	ValidationText string           `json:"validation_text"`
	// Rule context: whether an enabled rule uses this service, its group.
	Enabled   bool   `json:"enabled"`
	Group     string `json:"group,omitempty"`
	GroupMode string `json:"group_mode,omitempty"`
}

func catalogView(t model.Topology) []catalogEntry {
	svcs := map[string]unlock.Service{}
	for _, svc := range servicesOf(t) {
		svcs[svc.RuleID] = svc
	}
	out := make([]catalogEntry, 0, len(probe.Catalog))
	for _, a := range probe.Catalog {
		e := catalogEntry{
			Service: a.Service, Name: a.Name, Capability: a.Capability, Reachability: a.Reachability(),
			Returns: append([]probe.Category{probe.CatFailed}, a.Returns...), IPv4Only: a.IPv4Only,
			Probeable: probe.Probeable(a.Service), Platforms: a.Platforms, Requests: a.Requests(), Hosts: a.Hosts(),
			Combine: a.Combine, Basis: a.Basis, Limits: a.Limits, Sources: a.Sources,
			Validation: probe.Validation, ValidationText: probe.ValidationText,
		}
		if svc, ok := svcs[a.Service]; ok {
			e.Enabled, e.Group, e.GroupMode = true, svc.Pool, string(model.GroupAuto)
			if svc.Pin {
				e.GroupMode = string(model.GroupManual)
			}
		}
		out = append(out, e)
	}
	return out
}

func (s *Server) getUnlockJobs(w http.ResponseWriter, r *http.Request) {
	s.jobMu.Lock()
	running := ""
	if s.job != nil {
		running = s.job.id
	}
	s.jobMu.Unlock()
	s.mu.Lock()
	doc := s.loadJobs()
	t, err := s.topology()
	s.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	jobs := make([]probeJob, 0, len(doc.Jobs))
	for i := len(doc.Jobs) - 1; i >= 0; i-- {
		jobs = append(jobs, doc.Jobs[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"jobs": jobs, "running": running, "catalog": catalogView(t), "available": s.Prober != nil,
		"validation": probe.Validation, "validation_text": probe.ValidationText,
	})
}

func (s *Server) getUnlockCatalog(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	t, err := s.topology()
	s.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"catalog": catalogView(t), "available": s.Prober != nil,
		"validation": probe.Validation, "validation_text": probe.ValidationText,
		"grades":      []probe.Grade{probe.GradePlatform, probe.GradeReachability, probe.GradeUnknown, probe.GradeError, probe.GradeNotApplicable},
		"ingest_rule": "unlocked = 成功，not_unlocked = 失败；network_ok / unknown / failed 不是解锁结论，按 inconclusive 入库，既不降级也不恢复；not_applicable（检测方法不支持这个地址族，没有发出请求）不入库",
	})
}

func (s *Server) getUnlockJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.jobMu.Lock()
	running := s.job != nil && s.job.id == id
	s.jobMu.Unlock()
	s.mu.Lock()
	doc := s.loadJobs()
	s.mu.Unlock()
	for _, j := range doc.Jobs {
		if j.ID == id {
			writeJSON(w, http.StatusOK, map[string]any{"job": j, "running": running})
			return
		}
	}
	writeErr(w, http.StatusNotFound, errors.New("没有这一轮探测（只保留最近几轮）"))
}

// ---- latest results ---------------------------------------------------------

// probeResultsKey holds the newest finished item per service|exit|family,
// independent of the job ring, so the panel's matrix survives later jobs.
const probeResultsKey = "unlock_results"

type probeResultsDoc struct {
	Items map[string]probeJobItem `json:"items"`
}

func resultKey(it probeJobItem) string {
	return it.Service + "|" + it.ExitID + "|" + string(it.Family)
}

// recordResults stores finished items. Caller holds s.mu.
func (s *Server) recordResults(items []probeJobItem) {
	if len(items) == 0 {
		return
	}
	doc := s.loadResults()
	for _, it := range items {
		doc.Items[resultKey(it)] = it
	}
	if buf, err := json.Marshal(doc); err == nil {
		if err := s.Store.Put(probeResultsKey, string(buf)); err != nil {
			log.Printf("unlock results: save failed: %v", err)
		}
	}
}

func (s *Server) loadResults() probeResultsDoc {
	doc := probeResultsDoc{Items: map[string]probeJobItem{}}
	raw, ok, err := s.Store.Get(probeResultsKey)
	if err != nil || !ok || raw == "" {
		return doc
	}
	if json.Unmarshal([]byte(raw), &doc) != nil || doc.Items == nil {
		return probeResultsDoc{Items: map[string]probeJobItem{}}
	}
	return doc
}

type exitGroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Mode string `json:"mode"`
	// ActualActive is the member the hub reported in use (actual state ok
	// only); ModelActive is the panel's computation (面板推算), never an
	// observation.
	ActualActive string `json:"actual_active,omitempty"`
	ModelActive  string `json:"model_active,omitempty"`
}

type resultRow struct {
	probeJobItem
	ExitName string `json:"exit_name,omitempty"`
	// ExitGroups are all region groups the exit belongs to.
	ExitGroups []exitGroupRef `json:"exit_groups"`
	// ServiceActive is the member currently carrying the service (live).
	ServiceActive string `json:"service_active,omitempty"`
	IsActive      bool   `json:"is_active"`
	Ingestible    bool   `json:"ingestible"`
	// ExitRemoved: the exit is no longer in the topology. Such rows are
	// history, never current results; they are left out unless asked for
	// (include_removed=1) and can be deleted (POST /api/unlock/results/prune).
	ExitRemoved bool `json:"exit_removed"`
}

// removedExitCount is how many stored results belong to one removed exit.
type removedExitCount struct {
	ExitID  string `json:"exit_id"`
	Results int    `json:"results"`
}

// exitExists: the id names an exit node of the topology.
func exitExists(t model.Topology) func(string) bool {
	return func(id string) bool {
		n, ok := t.NodeByID(id)
		return ok && n.Role == model.RoleExit
	}
}

func (s *Server) getUnlockResults(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	t, err := s.topology()
	if err != nil {
		s.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	doc := s.loadResults()
	snap := s.loadUnlock()
	runtime := s.loadPools().Pools
	s.mu.Unlock()

	plans := plansOf(t)
	hs := s.hubSet(r.Context(), t)
	groupsOf := map[string][]exitGroupRef{}
	for _, g := range sortedGroups(t) {
		v := viewGroup(t, g, plans, runtime, hs)
		ref := exitGroupRef{ID: g.ID, Name: g.Name, Mode: string(g.Mode), ModelActive: v.Model.Active}
		if v.Actual.State == hubstate.StateOK {
			ref.ActualActive = v.Actual.Active
		}
		for _, m := range g.Members {
			groupsOf[m] = append(groupsOf[m], ref)
		}
	}
	svcs := map[string]unlock.Service{}
	for _, svc := range servicesOf(t) {
		svcs[svc.RuleID] = svc
	}
	fService, fExit, fGroup, fFam := q.Get("service"), q.Get("exit"), q.Get("group"), q.Get("family")
	includeRemoved := q.Get("include_removed") == "1"
	exists := exitExists(t)
	removed := map[string]int{}
	rows := []resultRow{}
	for _, it := range doc.Items {
		gone := !exists(it.ExitID)
		if gone {
			removed[it.ExitID]++
			if !includeRemoved {
				continue
			}
		}
		if (fService != "" && it.Service != fService) || (fExit != "" && it.ExitID != fExit) || (fFam != "" && string(it.Family) != fFam) {
			continue
		}
		row := resultRow{probeJobItem: it, ExitName: nodeName(t, it.ExitID), ExitGroups: groupsOf[it.ExitID], ExitRemoved: gone}
		if row.ExitGroups == nil {
			row.ExitGroups = []exitGroupRef{}
		}
		if fGroup != "" {
			in := it.Group == fGroup
			for _, g := range row.ExitGroups {
				in = in || g.ID == fGroup
			}
			if !in {
				continue
			}
		}
		if svc, ok := svcs[it.Service]; ok && !gone {
			row.ServiceActive = activeFor(snap, svc)
			row.IsActive = row.ServiceActive == it.ExitID
		}
		_, row.Ingestible = probe.IngestVerdict(it.Category)
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.ExitID != b.ExitID {
			return a.ExitID < b.ExitID
		}
		return a.Family < b.Family
	})
	gone := []removedExitCount{}
	for id, n := range removed {
		gone = append(gone, removedExitCount{ExitID: id, Results: n})
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].ExitID < gone[j].ExitID })
	writeJSON(w, http.StatusOK, map[string]any{
		"results": rows, "validation": probe.Validation, "validation_text": probe.ValidationText,
		"removed_exits": gone,
	})
}

// postUnlockResultsPrune deletes the stored probe results of exits that are
// no longer in the topology. It touches only the panel's result matrix:
// the unlock state's admission records (unlock.Snapshot Latest/Applied) and
// its history are kept, so admission is unchanged and the history still
// shows what happened (marked as a removed exit by GET /api/unlock).
func (s *Server) postUnlockResultsPrune(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	exists := exitExists(t)
	doc := s.loadResults()
	exits := map[string]bool{}
	n := 0
	for k, it := range doc.Items {
		if !exists(it.ExitID) {
			delete(doc.Items, k)
			exits[it.ExitID] = true
			n++
		}
	}
	if n > 0 {
		buf, err := json.Marshal(doc)
		if err == nil {
			err = s.Store.Put(probeResultsKey, string(buf))
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	ids := make([]string, 0, len(exits))
	for id := range exits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	writeJSON(w, http.StatusOK, map[string]any{"removed": n, "exits": ids})
}

func (s *Server) postUnlockJobCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.jobMu.Lock()
	h := s.job
	s.jobMu.Unlock()
	if h == nil || h.id != id {
		writeErr(w, http.StatusConflict, errors.New("这一轮探测没有在运行"))
		return
	}
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
	}
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": id})
}

// waitProbeJob blocks until the running job (if any) finishes. Tests only.
func (s *Server) waitProbeJob(d time.Duration) bool {
	s.jobMu.Lock()
	h := s.job
	s.jobMu.Unlock()
	if h == nil {
		return true
	}
	select {
	case <-h.done:
		return true
	case <-time.After(d):
		return false
	}
}

// ---- scheduler -------------------------------------------------------------

// StartUnlockScheduler runs the 6-hour probe through the same job chain as
// the panel button. Without a host agent it records that the run was due and
// leaves routing unchanged; it never invents results.
func (s *Server) StartUnlockScheduler() {
	if os.Getenv("MERIDIAN_UNLOCK_EXEC") != "" {
		log.Printf("MERIDIAN_UNLOCK_EXEC is set but no longer used: unlock probes run through meridian-host (/v1/probe)")
	}
	s.mu.Lock()
	s.markInterrupted("")
	s.mu.Unlock()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.tickUnlock()
		}
	}()
}

func (s *Server) tickUnlock() {
	s.mu.Lock()
	t, err := s.topology()
	if err != nil {
		s.mu.Unlock()
		return
	}
	snap := s.loadUnlock()
	now := time.Now().UTC()
	interval := unlock.Interval(t.Settings.UnlockIntervalSec)
	if snap.NextRun.IsZero() {
		snap.NextRun = now.Add(interval)
		_ = s.saveUnlock(snap)
		s.mu.Unlock()
		return
	}
	if now.Before(snap.NextRun) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	_, err = s.startProbeJob(unlock.KindScheduled, probeSelection{})
	switch {
	case err == nil:
		return
	case errors.Is(err, errJobRunning):
		// A manual run is in progress; try again on the next tick.
		return
	}
	note := "到达定时，但没有发起探测：" + err.Error() + "。路由保持不变。"
	s.mu.Lock()
	defer s.mu.Unlock()
	snap = s.loadUnlock()
	snap.History = append(snap.History, unlock.HistoryEntry{At: now, Kind: unlock.KindScheduled, Note: note})
	snap.NextRun = now.Add(interval)
	_ = s.saveUnlock(snap)
}
