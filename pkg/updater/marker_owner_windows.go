package updater

import (
	"errors"
	"io"
	"os"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"golang.org/x/sys/windows"
)

// readMarker opens the marker without following a reparse point and checks
// the opened handle itself: a plain file owned by SYSTEM or Administrators.
// It then reads from the same handle.
func readMarker(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer func() { _ = f.Close() }()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, errors.New("upgrade marker is not a regular file")
	}
	ok, err := utils.HandleOwnedByAdministrators(h)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("upgrade marker is not owned by SYSTEM or Administrators")
	}
	return io.ReadAll(io.LimitReader(f, maxMarkerSize))
}
