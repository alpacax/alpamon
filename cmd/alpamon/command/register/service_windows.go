package register

import (
	"fmt"
	"os"

	"github.com/alpacax/alpamon/pkg/utils"
)

const alpamonBinPath = `C:\Program Files\alpamon\alpamon.exe`

func ensureDirectories() error {
	return utils.EnsureDirectories()
}

func startService() error {
	binPath := alpamonBinPath
	if exe, err := os.Executable(); err == nil {
		binPath = exe
	}
	fmt.Println("Windows Service management is not yet supported.")
	fmt.Println("Please install alpamon as a Windows Service manually:")
	fmt.Printf("  sc.exe create alpamon binPath= \"%s\"\n", binPath)
	fmt.Println("  sc.exe start alpamon")
	return nil
}

func printManualStartHint() {
	fmt.Println("Please start alpamon manually:")
	fmt.Println("  sc.exe start alpamon")
}
