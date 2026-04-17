package updater

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// buildPEFixture writes a minimal PE layout that passes validateBinaryFormat.
// It's not a loadable executable — just enough header bytes to satisfy the
// magic-byte checks the updater performs before executing a new binary.
func buildPEFixture(t *testing.T, machine uint16) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "alpamon.exe")
	const peOffset = 0x80
	buf := make([]byte, peOffset+6)

	// DOS header: MZ magic + e_lfanew at 0x3C.
	binary.LittleEndian.PutUint16(buf[0:], peDOSMagic)
	binary.LittleEndian.PutUint32(buf[peHeaderOffset:], uint32(peOffset))

	// PE header: "PE\0\0" + machine (start of IMAGE_FILE_HEADER).
	binary.LittleEndian.PutUint32(buf[peOffset:], peSignature)
	binary.LittleEndian.PutUint16(buf[peOffset+4:], machine)

	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func currentArchMachine(t *testing.T) uint16 {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		return peMachineAMD64
	case "arm64":
		return peMachineARM64
	case "386":
		return peMachineI386
	default:
		t.Skipf("no PE fixture machine for GOARCH=%s", runtime.GOARCH)
		return 0
	}
}

func TestValidatePE_Valid(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE validation is Windows-only; the helper lives under _windows.go build tag")
	}
	path := buildPEFixture(t, currentArchMachine(t))
	if err := validateBinaryFormat(path); err != nil {
		t.Fatalf("expected valid PE to pass, got %v", err)
	}
}

func TestValidatePE_BadMZ(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE validation is Windows-only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.exe")
	// Two zero bytes at position 0 — not MZ.
	if err := os.WriteFile(path, []byte{0, 0, 0, 0, 0, 0}, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := validateBinaryFormat(path); err == nil {
		t.Fatal("expected error for non-MZ file")
	}
}

func TestValidatePE_WrongMachine(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE validation is Windows-only")
	}
	// Pick a different machine than the runtime arch to force a mismatch.
	wrong := uint16(peMachineI386)
	if runtime.GOARCH == "386" {
		wrong = peMachineAMD64
	}
	path := buildPEFixture(t, wrong)
	if err := validateBinaryFormat(path); err == nil {
		t.Fatal("expected machine-mismatch error")
	}
}

func TestValidatePE_BadOffset(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE validation is Windows-only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.exe")
	// Valid MZ but e_lfanew points way out of file.
	buf := make([]byte, peHeaderOffset+4)
	binary.LittleEndian.PutUint16(buf[0:], peDOSMagic)
	binary.LittleEndian.PutUint32(buf[peHeaderOffset:], uint32(peMaxHeaderSeek+1))
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := validateBinaryFormat(path); err == nil {
		t.Fatal("expected error for out-of-range PE header offset")
	}
}
