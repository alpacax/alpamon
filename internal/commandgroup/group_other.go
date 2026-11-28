//go:build !linux

package commandgroup

import (
	"context"
	"os/exec"
)

func Path(int) string                                               { return "" }
func Prepare(ctx context.Context) (context.Context, string, func()) { return ctx, "", func() {} }
func Configure(context.Context, *exec.Cmd)                          {}

func Owned(string) bool                 { return false }
func RealUID(int) string                { return "" }
func Unsupported(*exec.Cmd, error) bool { return false }

func CleanupEmpty() {}
