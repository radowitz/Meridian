//go:build !unix

package apply

import "sync"

var txnMu sync.Mutex

// lockFile falls back to a process-wide mutex where flock is unavailable.
func lockFile(string) (func(), error) {
	txnMu.Lock()
	return txnMu.Unlock, nil
}

// lockBusy reports whether the process-wide transaction mutex is held.
func lockBusy(string) (bool, error) {
	if txnMu.TryLock() {
		txnMu.Unlock()
		return false, nil
	}
	return true, nil
}
