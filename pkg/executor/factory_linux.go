package executor

import (
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/executor/handlers/firewall"
	"github.com/alpacax/alpamon/pkg/executor/handlers/group"
	"github.com/alpacax/alpamon/pkg/executor/handlers/system"
	"github.com/alpacax/alpamon/pkg/executor/handlers/tunnel"
	"github.com/alpacax/alpamon/pkg/executor/handlers/user"
	"github.com/alpacax/alpamon/pkg/utils"
)

func platformHandlers(deps platformHandlerDeps) []common.Handler {
	return []common.Handler{
		system.NewSystemHandler(deps.cmdExec, deps.wsClient, deps.ctxManager, deps.pool, utils.NewDefaultVersionResolver()),
		group.NewGroupHandler(deps.cmdExec, deps.infoAdapter),
		user.NewUserHandler(deps.cmdExec, deps.groupService, deps.infoAdapter),
		firewall.NewFirewallHandler(deps.cmdExec),
		tunnel.NewTunnelHandler(deps.cmdExec),
	}
}
