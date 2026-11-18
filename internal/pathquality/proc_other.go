//go:build !unix

package pathquality

func processAlive(int) bool { return false }
