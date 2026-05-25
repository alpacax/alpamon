package pidfile

import (
	"fmt"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

func FilePath(name string) string {
	return fmt.Sprintf("%s/%s.pid", utils.RunDir(), name)
}
