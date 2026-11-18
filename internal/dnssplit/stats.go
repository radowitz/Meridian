package dnssplit

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Outcomes of one query.
const (
	outcomeDomestic = iota // a qualifying domestic answer
	outcomeExit            // the exit's answer
	outcomeServfail        // nothing usable
	outcomeOther           // not A/AAAA: the exit only
	nOutcomes
)

var outcomeNames = [nOutcomes]string{"domestic", "exit", "servfail", "other"}

// stats counts outcomes and decision times for the periodic summary. It
// holds no names: what was asked is not logged.
type stats struct {
	mu   sync.Mutex
	lat  [nOutcomes][]time.Duration
	seen [nOutcomes]int
	// silent: a domestic resolver that never answered (DomesticTimeout);
	// secondReply: a qualifying reply after a non-qualifying one within
	// Settle (injection then genuine answer).
	silent, secondReply atomic.Int64
}

// maxSamples bounds the memory of one period; counts stay exact.
const maxSamples = 4096

func (st *stats) record(o int, d time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.seen[o]++
	if len(st.lat[o]) < maxSamples {
		st.lat[o] = append(st.lat[o], d)
	}
}

func pct(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	return ds[int(float64(len(ds)-1)*p)]
}

// summary returns one line for the last period and starts a new one ("" if
// nothing was asked).
func (st *stats) summary(period time.Duration) string {
	st.mu.Lock()
	lat, seen := st.lat, st.seen
	st.lat, st.seen = [nOutcomes][]time.Duration{}, [nOutcomes]int{}
	st.mu.Unlock()
	silent, second := st.silent.Swap(0), st.secondReply.Swap(0)
	total := 0
	for _, n := range seen {
		total += n
	}
	if total == 0 {
		return ""
	}
	line := fmt.Sprintf("meridian-dns-split-stats: last %v: %d queries;", period, total)
	for o := 0; o < nOutcomes; o++ {
		if seen[o] == 0 {
			continue
		}
		ds := lat[o]
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		ms := func(d time.Duration) int64 { return d.Milliseconds() }
		line += fmt.Sprintf(" %s %d (decision ms p50 %d p90 %d p99 %d);", outcomeNames[o], seen[o], ms(pct(ds, 0.5)), ms(pct(ds, 0.9)), ms(pct(ds, 0.99)))
	}
	return line + fmt.Sprintf(" silent domestic resolvers %d; accepted after a non-qualifying reply %d", silent, second)
}
