package router

import (
	"github.com/gin-gonic/gin"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/internal/core/routing/proxy"
)

// Router 定义路由引擎的接口
type Router interface {
	Setup(r gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config)
}
