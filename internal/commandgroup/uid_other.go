//go:build !linux && !darwin

package commandgroup

func RealUID(int) string { return "" }
