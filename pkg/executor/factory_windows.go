package executor

import (
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/executor/handlers/system"
	"github.com/alpacax/alpamon/pkg/utils"
)

func platformHandlers(deps platformHandlerDeps) []common.Handler {
	return []common.Handler{
		system.NewSystemHandler(deps.cmdExec, deps.wsClient, deps.ctxManager, deps.pool, utils.NewDefaultVersionResolver()),
	}
}
