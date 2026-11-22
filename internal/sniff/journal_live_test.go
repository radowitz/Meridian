package sniff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJournalChangesWakesAfterActivityAndCommit(t *testing.T) {
	j, err := OpenJournal(JournalConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	s := &Server{Journal: j, active: make(map[uint64]*activeConn)}
	handler := s.StatusHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	read := func(after string) string {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/journal/changes?after="+after, nil).WithContext(ctx))
		var body struct{ Revision string }
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return body.Revision
	}
	checkChange := func(change func()) {
		t.Helper()
		current := read("")
		result := make(chan string, 1)
		go func() { result <- read(current) }()
		select {
		case <-result:
			t.Fatal("idle request returned before a change")
		case <-time.After(20 * time.Millisecond):
		}
		change()
		select {
		case next := <-result:
			if next == "" || next == current {
				t.Fatalf("expected a new revision, got %q", next)
			}
		case <-ctx.Done():
			t.Fatal("change did not wake the request")
		}
	}
	record := ConnRecord{Conn: 1, Start: time.Now(), Source: "192.0.2.10"}
	checkChange(func() { s.addActive(record, nil, nil) })
	checkChange(func() { j.Add(record) })
	page, err := j.Query(JournalQuery{})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("notified before record was queryable: %v, %d records", err, len(page.Records))
	}
	checkChange(func() { j.Clear() })
}
