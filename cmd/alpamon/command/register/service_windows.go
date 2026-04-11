package register

import (
	"fmt"

	"github.com/alpacax/alpamon/pkg/utils"
)

const alpamonBinPath = `C:\Program Files\alpamon\alpamon.exe`

func ensureDirectories() error {
	return utils.EnsureDirectories()
}

func startService() error {
	fmt.Println("Windows Service management is not yet supported.")
	fmt.Println("Please install alpamon as a Windows Service manually:")
	fmt.Printf("  sc.exe create alpamon binPath= \"%s\"\n", alpamonBinPath)
	fmt.Println("  sc.exe start alpamon")
	return nil
}

func printManualStartHint() {
	fmt.Println("Please start alpamon manually:")
	fmt.Printf("  sc.exe start alpamon\n")
}
