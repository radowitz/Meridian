//go:build !linux && !darwin

package hostexec

func diskAvailKB(string) int64 { return -1 }
