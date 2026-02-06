package auth

import (
	"net/http"
	"strings"

	"github.com/penwyp/mini-gateway/internal/core/observability"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/gin-gonic/gin"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/internal/core/security"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.uber.org/zap"
)

var jwtTracer = otel.Tracer("auth:jwt") // 定义认证模块的 Tracer

type JWTAuthenticator struct {
	cfg *config.Config
}

func (j *JWTAuthenticator) Authenticate(c *gin.Context) {
	_, span := jwtTracer.Start(c.Request.Context(), "Auth.JWT",
		trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
	defer span.End()

	authHeader := c.GetHeader("Authorization") // 获取 HTTP 头
	if authHeader == "" {
		// --- 失败处理四部曲 ---
		// 1. 追踪系统：标记该 Span 状态为 Error
		span.SetStatus(codes.Error, "Authorization header required")
		// 2. 日志系统：打印警告
		logger.Warn("No Authorization header provided")
		// 3. 监控指标：给 "失败计数器" +1
		observability.JwtAuthFailures.WithLabelValues(c.Request.URL.Path).Inc()
		// 4. HTTP 响应：返回 401 JSON
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
		// [关键] 必须调用 Abort，否则 Gin 会继续执行后面的 Handler
		c.Abort()
		return
	}

	parts := strings.Split(authHeader, " ") // 按空格切割
	// 标准格式必须是: "Bearer <token>"，所以长度必须是 2，且第一个词是 Bearer
	if len(parts) != 2 || parts[0] != "Bearer" {
		span.SetStatus(codes.Error, "Invalid Authorization header")
		logger.Warn("Invalid Authorization header format")
		observability.JwtAuthFailures.WithLabelValues(c.Request.URL.Path).Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
		c.Abort()
		return
	}

	token := parts[1] // 拿到真正的 token 字符串
	// 调用 security 包里的 ValidateToken 去解密、验签、查过期时间
	claims, err := security.ValidateToken(token)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Invalid JWT token")
		logger.Warn("Invalid JWT token", zap.Error(err))
		observability.JwtAuthFailures.WithLabelValues(c.Request.URL.Path).Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		c.Abort()
		return
	}
	span.SetAttributes(attribute.String("username", claims.Username))
	span.SetStatus(codes.Ok, "Authentication succeeded")
	// 2. [关键] 将用户信息存入 Gin 上下文 (Context)
	// 这样后续的 Handler (比如处理业务逻辑的 Controller) 就能通过 c.Get("username") 知道是谁在操作
	c.Set("username", claims.Username)
	// 3. 放行！把控制权移交给下一个中间件或最终的处理函数
	c.Next()
}
