package router

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/internal/core/routing/proxy"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var trieRegexpTracer = otel.Tracer("router:trie-regexp")

type TrieRegexpRouter struct {
	Trie *TrieRegexp
}

type TrieRegexp struct {
	Root *TrieRegexpNode
}

type TrieRegexpNode struct {
	Children   map[rune]*TrieRegexpNode
	Rules      config.RoutingRules
	IsEnd      bool
	RegexRules []RegexRule // 存储多个正则规则
}

type RegexRule struct {
	Regex   *regexp.Regexp
	Pattern string
	Rules   config.RoutingRules
}

func NewTrieRegexpRouter() *TrieRegexpRouter {
	return &TrieRegexpRouter{
		Trie: &TrieRegexp{
			Root: &TrieRegexpNode{Children: make(map[rune]*TrieRegexpNode)},
		},
	}
}

func (t *TrieRegexp) Insert(path string, rules config.RoutingRules) {
	node := t.Root //以此为起点
	originalPath := path

	// --- 分支 A: 这是一个正则路径吗？ ---
	// 检查是否包含正则特殊字符 (*, +, ?, etc.)
	if strings.ContainsAny(path, ".*+?()|[]^$\\") {
		// 编译正则，加上 ^$ 锚点
		re, err := regexp.Compile("^" + path + "$")
		if err != nil {
			logger.Error("Failed to compile regular expression pattern",
				zap.String("path", originalPath),
				zap.Error(err))
			return
		}
		// 【重点关注】
		// 这里直接把正则规则 append 到了 node.RegexRules。
		// 因为 node 初始化为 t.Root，且在正则分支里没有下移（没有 node = node.Children[...]）。
		// 结论：所有的正则规则，实际上都存储在【根节点】的一个列表里。
		node.RegexRules = append(node.RegexRules, RegexRule{
			Regex:   re,
			Pattern: path,
			Rules:   rules,
		})
		logger.Info("Successfully inserted regex route into Trie",
			zap.String("pattern", originalPath),
			zap.Any("rules", rules))
		return
	}

	// --- 分支 B: 这是一个静态路径 ---
	// 标准的 Trie 插入逻辑
	cleanPath := strings.TrimPrefix(path, "/")
	for _, ch := range cleanPath {
		// ... 遍历字符创建节点 ...
		if node.Children[ch] == nil {
			node.Children[ch] = &TrieRegexpNode{Children: make(map[rune]*TrieRegexpNode)}
		}
		node = node.Children[ch]
	}
	node.Rules = rules
	node.IsEnd = true
	logger.Info("Successfully inserted static route into TrieRegexp",
		zap.String("path", originalPath),
		zap.Any("rules", rules))
}

func (t *TrieRegexp) Search(ctx context.Context, path string) (config.RoutingRules, bool) {
	ctx, span := trieRegexpTracer.Start(ctx, "TrieRegexp.Search",
		trace.WithAttributes(attribute.String("path", path)))
	defer span.End()

	// ... 开启追踪 ...

	// --- 步骤 1: 尝试 Trie 静态匹配 ---
	node := t.Root
	cleanPath := strings.TrimPrefix(path, "/")

	for _, ch := range cleanPath {
		if node.Children[ch] == nil {
			break // 树里没这条路，跳出循环
		}
		node = node.Children[ch]
	}
	// 如果走完了静态路径，且这里是一个已注册的终点
	if node != nil && node.IsEnd {
		return node.Rules, true
	} // 【命中静态路由，直接返回】

	// 检查所有正则规则
	// --- 步骤 2: 静态没命中，兜底查正则 ---
	// 检查所有正则规则 (t.Root.RegexRules)
	// 注意：这里的 t.Root.RegexRules 对应了 Insert 时全部存在 Root 的逻辑
	for _, regexRule := range t.Root.RegexRules {
		if regexRule.Regex.MatchString(path) {
			return regexRule.Rules, true
		} // 【命中正则路由】
	}

	return nil, false // 彻底没找到
}

func (tr *TrieRegexpRouter) Setup(r gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config) {
	rules := cfg.Routing.GetHTTPRules()
	if len(rules) == 0 {
		logger.Warn("No HTTP routing rules found in configuration")
		return
	}

	for path, targetRules := range rules {
		tr.Trie.Insert(path, targetRules)
	}

	r.Use(func(c *gin.Context) {
		ctx, span := trieRegexpTracer.Start(c.Request.Context(), "Routing.Match",
			trace.WithAttributes(attribute.String("type", "TrieRegexp")),
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()

		path := c.Request.URL.Path
		targetRules, found := tr.Trie.Search(ctx, path)
		if !found {
			logger.Warn("No matching route found",
				zap.String("path", path),
				zap.String("method", c.Request.Method))
			c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
			c.Abort()
			span.SetStatus(codes.Error, "Route not found")
			return
		}

		span.SetAttributes(attribute.String("matched_target", targetRules[0].Target))
		span.SetStatus(codes.Ok, "Route matched successfully")
		logger.Info("Successfully matched route in TrieRegexp",
			zap.String("path", path),
			zap.Any("rules", targetRules))

		c.Request = c.Request.WithContext(ctx)
		httpProxy.CreateHTTPHandler(targetRules)(c)
	})
}
