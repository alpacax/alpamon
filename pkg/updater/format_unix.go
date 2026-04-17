//go:build !windows

package updater

import (
	"fmt"
	"os"
	"runtime"
)

func validateBinaryFormat(binaryPath string) error {
	f, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	magic := make([]byte, 4)
	if _, err := readFull(f, magic); err != nil {
		return fmt.Errorf("failed to read binary header: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		if !isMachO(magic) {
			return fmt.Errorf("not a valid Mach-O binary (magic: %x)", magic)
		}
	case "linux":
		if magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F' {
			return fmt.Errorf("not a valid ELF binary (magic: %x)", magic)
		}
	default:
		return fmt.Errorf("binary format validation not supported on platform %q", runtime.GOOS)
	}
	return nil
}
