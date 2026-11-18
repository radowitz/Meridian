package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

// rsBulkConcurrency bounds the downloads of one "update all".
const rsBulkConcurrency = 4

// rsBulkJob is one "update all rule-sets" (in memory; poll
// GET /api/rule-sets/update-all until State is not "running").
type rsBulkJob struct {
	ID         string    `json:"id"`
	State      string    `json:"state"` // running, done
	Total      int       `json:"total"`
	Done       int       `json:"done"`
	Failed     []string  `json:"failed"`
	Skipped    []string  `json:"skipped"` // already downloading
	StartedAt  time.Time `json:"started_at"`
	FinishedAt string    `json:"finished_at,omitempty"`
}

func (s *Server) bulkSnapshot() *rsBulkJob {
	st := s.rs()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.bulk == nil {
		return nil
	}
	j := *st.bulk
	j.Failed = append([]string{}, j.Failed...)
	j.Skipped = append([]string{}, j.Skipped...)
	return &j
}

func (s *Server) getUpdateAllRuleSets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"job": s.bulkSnapshot()})
}

func (s *Server) updateAllRuleSets(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	st := s.rs()
	st.mu.Lock()
	if st.bulk != nil && st.bulk.State == "running" {
		st.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{"error": "规则集正在全部更新", "code": codeUpdateRunning, "job": s.bulkSnapshot()})
		return
	}
	job := &rsBulkJob{ID: "rs-" + randHex(8), State: "running", Total: len(t.RuleSets), Failed: []string{}, Skipped: []string{}, StartedAt: time.Now().UTC()}
	st.bulk = job
	st.mu.Unlock()
	go s.runBulk(t, job)
	writeJSON(w, http.StatusAccepted, map[string]any{"job": s.bulkSnapshot()})
}

// runBulk fetches every rule-set with at most rsBulkConcurrency at a time.
func (s *Server) runBulk(t model.Topology, job *rsBulkJob) {
	st := s.rs()
	sem := make(chan struct{}, rsBulkConcurrency)
	var wg sync.WaitGroup
	for _, rs := range t.RuleSets {
		wg.Add(1)
		sem <- struct{}{}
		go func(rs model.RuleSet) {
			defer wg.Done()
			defer func() { <-sem }()
			ran := s.startFetch(t, rs, true)
			failed := false
			if ran {
				if x := s.loadRSStatus()[rs.ID]; x != nil && x.LastError != "" {
					failed = true
				}
			}
			st.mu.Lock()
			job.Done++
			switch {
			case !ran:
				job.Skipped = append(job.Skipped, rs.ID)
			case failed:
				job.Failed = append(job.Failed, rs.ID)
			}
			st.mu.Unlock()
		}(rs)
	}
	wg.Wait()
	st.mu.Lock()
	job.State, job.FinishedAt = "done", time.Now().UTC().Format(time.RFC3339)
	st.mu.Unlock()
}
