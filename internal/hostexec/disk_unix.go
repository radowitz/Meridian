//go:build linux || darwin

package hostexec

import "syscall"

// diskAvailKB is the space available to unprivileged users on the
// filesystem of path, in KiB (-1 when unknown).
func diskAvailKB(path string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize) / 1024
}
