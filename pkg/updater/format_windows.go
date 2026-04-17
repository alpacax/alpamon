package updater

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
)

// Windows PE/COFF constants (see PE Format reference).
const (
	peDOSMagic      = 0x5A4D     // "MZ" little-endian
	peSignature     = 0x00004550 // "PE\0\0"
	peHeaderOffset  = 0x3C       // offset of e_lfanew in DOS header
	peMachineAMD64  = 0x8664
	peMachineARM64  = 0xAA64
	peMachineI386   = 0x014C
	peMaxHeaderSeek = 1024 * 1024 // guard against absurd e_lfanew values
)

// validateBinaryFormat checks that binaryPath is a valid PE/COFF
// executable whose IMAGE_FILE_HEADER.Machine matches runtime.GOARCH.
// The file is inspected by magic bytes only; it is never executed.
func validateBinaryFormat(binaryPath string) error {
	f, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// 1. DOS header: MZ magic at offset 0.
	var dosMagic uint16
	if err := binary.Read(f, binary.LittleEndian, &dosMagic); err != nil {
		return fmt.Errorf("failed to read DOS magic: %w", err)
	}
	if dosMagic != peDOSMagic {
		return fmt.Errorf("not a valid PE binary (DOS magic: 0x%04x)", dosMagic)
	}

	// 2. e_lfanew: 32-bit offset of the PE signature, at 0x3C.
	var peOffset uint32
	if _, err := f.Seek(peHeaderOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to PE header offset: %w", err)
	}
	if err := binary.Read(f, binary.LittleEndian, &peOffset); err != nil {
		return fmt.Errorf("failed to read PE header offset: %w", err)
	}
	if peOffset == 0 || peOffset > peMaxHeaderSeek {
		return fmt.Errorf("invalid PE header offset: %d", peOffset)
	}

	// 3. PE signature: "PE\0\0" at peOffset.
	if _, err := f.Seek(int64(peOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to PE signature: %w", err)
	}
	var sig uint32
	if err := binary.Read(f, binary.LittleEndian, &sig); err != nil {
		return fmt.Errorf("failed to read PE signature: %w", err)
	}
	if sig != peSignature {
		return fmt.Errorf("not a valid PE binary (signature: 0x%08x)", sig)
	}

	// 4. IMAGE_FILE_HEADER.Machine is the next field after the PE
	// signature. Confirm it matches this process's architecture so we
	// don't replace a 64-bit alpamon with a 32-bit binary or vice versa.
	var machine uint16
	if err := binary.Read(f, binary.LittleEndian, &machine); err != nil {
		return fmt.Errorf("failed to read IMAGE_FILE_HEADER.Machine: %w", err)
	}
	if err := checkPEMachine(machine); err != nil {
		return err
	}
	return nil
}

// checkPEMachine matches the runtime architecture against the
// IMAGE_FILE_HEADER.Machine field.
//
// Note: .goreleaser.yaml currently only builds windows/amd64; the
// arm64 and 386 cases here are forward-compatible but today there is
// no corresponding release artifact. Update the release matrix before
// relying on anything other than amd64.
func checkPEMachine(machine uint16) error {
	var want uint16
	switch runtime.GOARCH {
	case "amd64":
		want = peMachineAMD64
	case "arm64":
		want = peMachineARM64
	case "386":
		want = peMachineI386
	default:
		return fmt.Errorf("unsupported GOARCH for Windows update: %q", runtime.GOARCH)
	}
	if machine != want {
		return fmt.Errorf("PE machine 0x%04x does not match runtime.GOARCH=%s (want 0x%04x)", machine, runtime.GOARCH, want)
	}
	return nil
}
