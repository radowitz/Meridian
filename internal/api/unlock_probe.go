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
// only scheduled verdicts count toward the two-failure demotion. A service
// whose families all ended without a platform verdict (failed / unknown) is
// ingested as unlock.KindInconclusive: it never demotes, but it does end the
// preferred member's recovery streak. Results of a cancelled job are recorded
// in the job but not ingested.
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
	// probeRequestTimeout bounds one agent call (the agent caps itself at 2m).
	probeRequestTimeout = 150 * time.Second
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
	Region      string         `json:"region,omitempty"`
	Evidence    string         `json:"evidence,omitempty"`
	Egress      string         `json:"egress,omitempty"`
	Error       string         `json:"error,omitempty"`
	// Ingest is what unlock.Ingest did: accepted, rejected:<reason>,
	// note:<text>, or not_ingested:<why>.
	Ingest string `json:"ingest,omitempty"`
}

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
	Families []string `json:"families,omitempty"`
}

// probeGroup is one exit's share of a job.
type probeGroup struct {
	exit     compile.ProbeExit
	families []unlock.Family
	services []string
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
		if _, ok := probe.Lookup(svc.RuleID); !ok {
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
				if _, has := probe.Lookup(id); !has {
					return nil, nil, fmt.Errorf("服务 %q 没有面板探测适配器（只能用出口上的 regioncheck 报告）", id)
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
	if len(sel.Exits) > maxSelectExits {
		return nil, nil, errors.New("exits 过多")
	}
	for _, id := range sel.Exits {
		if _, ok := exits[id]; !ok {
			return nil, nil, fmt.Errorf("出口 %q 不存在", id)
		}
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
		targets := sel.Exits
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
	names := map[string]string{}
	for _, svc := range services {
		names[svc.RuleID] = svc.Name
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
		g := probeGroup{exit: ex, services: byExit[id]}
		for _, fam := range want {
			reason := ""
			switch {
			case fam == unlock.FamilyIPv4 && !ex.EgressV4:
				reason = "出口没有 IPv4 出口能力（egress_v4=false），未探测"
			case fam == unlock.FamilyIPv6 && !ex.EgressV6:
				reason = "出口没有 IPv6 出口能力（egress_v6=false），未探测"
			case ex.Resolver == "":
				reason = "出口没有隧道解析器地址，不能经出口解析，未探测"
			case ex.Region == "" && expectAddr(ex, fam) == "":
				reason = "出口既没有地区也没有该地址族的公网端点，无法确认实际出口，未探测"
			}
			for _, svc := range g.services {
				count++
				if reason != "" {
					skipped = append(skipped, probeJobItem{
						Service: svc, ServiceName: names[svc], ExitID: id, ExitRegion: ex.Region, Family: fam,
						State: itemSkipped, Category: probe.CatFailed, Error: reason, Ingest: "not_ingested:not_sent",
					})
				}
			}
			if reason == "" {
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
	names := map[string]string{}
	for _, svc := range servicesOf(t) {
		names[svc.RuleID] = svc.Name
	}
	job := probeJob{ID: "job-" + time.Now().UTC().Format("20060102T150405") + "-" + randHex(3), Kind: kind, State: jobRunning, CreatedAt: time.Now().UTC()}
	for _, g := range groups {
		for _, fam := range g.families {
			for _, svc := range g.services {
				job.Items = append(job.Items, probeJobItem{
					Service: svc, ServiceName: names[svc], ExitID: g.exit.ID, ExitRegion: g.exit.Region,
					Family: fam, State: itemQueued,
				})
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
				it.State, it.Category, it.Error, it.Ingest = itemSkipped, probe.CatFailed, why, "not_ingested:cancelled"
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
			Region: unlock.NormRegion(g.exit.Region), ExpectAddr: expectAddr(g.exit, fam), Services: g.services,
		}
		spec := probe.Spec{ExitID: g.exit.ID, Family: fam, Services: g.services}
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
		verdicts := map[unlock.Family]bool{}
		for _, fam := range g.families {
			r, _ := findResult(reports[fam], id)
			switch r.Category {
			case probe.CatUnlocked, probe.CatNetworkOK:
				verdicts[fam] = true
			case probe.CatNotUnlocked:
				verdicts[fam] = false
			}
		}
		obKind, results := kind, verdicts
		if len(verdicts) == 0 {
			if cancelled {
				for _, fam := range g.families {
					ingest[id+"|"+string(fam)] = "not_ingested:cancelled"
				}
				continue
			}
			obKind, results = unlock.KindInconclusive, map[unlock.Family]bool{}
			for _, fam := range g.families {
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
		for _, fam := range g.families {
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
			if rep.Egress.Confirmed {
				it.Egress = rep.Egress.Evidence
			} else if rep.Egress.Error != "" {
				it.Egress = "未确认：" + rep.Egress.Error
			}
			it.Ingest = ingest[it.Service+"|"+string(it.Family)]
		}
	})
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

// sanitizeReport keeps only results the job asked for, with a known
// category and the right family, and bounds the text. A malformed agent
// answer cannot invent a verdict for another service or family.
func sanitizeReport(rep probe.Report, spec probe.Spec) probe.Report {
	out := rep
	out.Results = nil
	for _, r := range rep.Results {
		if !containsStr(spec.Services, r.Service) || r.Family != spec.Family {
			continue
		}
		switch r.Category {
		case probe.CatNetworkOK, probe.CatUnlocked, probe.CatNotUnlocked, probe.CatFailed, probe.CatUnknown:
		default:
			r.Category, r.Error = probe.CatUnknown, "agent 返回了未知类别"
		}
		if a, ok := probe.Lookup(r.Service); ok && a.Reachability && r.Category == probe.CatUnlocked {
			// Reachability adapters never claim an unlock.
			r.Category = probe.CatNetworkOK
		}
		if !rep.Egress.Confirmed && r.Category != probe.CatFailed {
			r.Category, r.Region, r.Error = probe.CatFailed, "", "出口未确认，不作为平台结果"
		}
		r.Evidence, r.Error, r.Region = clipText(r.Evidence, 400), clipText(r.Error, 400), clipText(r.Region, 12)
		out.Results = append(out.Results, r)
	}
	out.Egress.Evidence = clipText(out.Egress.Evidence, 400)
	out.Egress.Error = clipText(out.Egress.Error, 400)
	return out
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
	prev := snap.Services[svc.RuleID]
	if prev.Pool == "" {
		prev.Pool = svc.Pool
		prev.Preferred = svc.Preferred
		prev.Active = svc.Preferred
	}
	snap.Services[svc.RuleID] = prev
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

type catalogEntry struct {
	Service      string `json:"service"`
	Name         string `json:"name"`
	Reachability bool   `json:"reachability"`
	Basis        string `json:"basis"`
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
	s.mu.Unlock()
	jobs := make([]probeJob, 0, len(doc.Jobs))
	for i := len(doc.Jobs) - 1; i >= 0; i-- {
		jobs = append(jobs, doc.Jobs[i])
	}
	cat := make([]catalogEntry, 0, len(probe.Catalog))
	for _, a := range probe.Catalog {
		cat = append(cat, catalogEntry{Service: a.Service, Name: a.Name, Reachability: a.Reachability, Basis: a.Basis})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"jobs": jobs, "running": running, "catalog": cat, "available": s.Prober != nil,
	})
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
