//go:build !unix

package query

func processAlive(int) bool { return false }
