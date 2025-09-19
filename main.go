package main

import (
	"context"

	"os/signal"
	"syscall"

	"github.com/luoying/gin-hander/conf"
	"github.com/luoying/gin-hander/pkg/api"
	"github.com/luoying/gin-hander/pkg/log"
	"github.com/luoying/gin-hander/pkg/utils"
)

var (
	AppName = "luoyy"
)

func main() {
	cfg, err := conf.LoadAppConfig()
	if err != nil {
		log.Warn("load config failed", err)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	worker := utils.NewBaseWorker(AppName, func() (utils.Worker, error) {
		return utils.NewApiWorker(cfg.Listen,
			func() (utils.APIWorker, error) {
				return api.NewCustomerWorker(cfg)
			},
		), nil
	},
	)
	if err = worker.Serve(ctx); err != nil {
		log.Warnf("worker %s exit with error %s", worker.Tag(), err)
	}
}
