package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/penwyp/mini-gateway/config"
)

func Auth() gin.HandlerFunc {
	authenticator := NewAuthenticator(config.GetConfig())
	return func(c *gin.Context) {
		authenticator.Authenticate(c)
	}
}
