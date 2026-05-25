package executor

import (
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/system"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/tunnel"
	"github.com/alpacax/alpamon/v2/pkg/utils"
)

func platformHandlers(deps platformHandlerDeps) []common.Handler {
	return []common.Handler{
		system.NewSystemHandler(deps.cmdExec, deps.wsClient, deps.ctxManager, deps.pool, utils.NewDefaultVersionResolver(), deps.apiSession),
		tunnel.NewTunnelHandler(deps.cmdExec),
	}
}
