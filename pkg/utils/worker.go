package utils

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/luoying/gin-hander/pkg/log"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// RunWorkers 并发运行多个Worker实例
func RunWorkers[T Worker](ctx context.Context, workers []T) error {
	eg, ctx := errgroup.WithContext(ctx)
	for _, worker := range workers {
		w := worker
		eg.Go(func() error {
			return w.Serve(ctx)
		})
	}
	return eg.Wait()
}

// simpleWorker 简单的Worker实现

type simpleWorker struct {
	tag string                          // worker的标识符
	fn  func(ctx context.Context) error // 要执行的函数
}

// SimpleWorker 创建一个简单的Worker实例
func SimpleWorker(tag string, fn func(ctx context.Context) error) Worker {
	return &simpleWorker{tag: tag, fn: fn}
}

// Serve 实现Worker接口的Serve方法
func (worker *simpleWorker) Serve(ctx context.Context) error {
	if worker.fn != nil {
		return worker.fn(ctx)
	}
	return nil
}

// Tag 实现Worker接口的Tag方法
func (worker *simpleWorker) Tag() string {
	return worker.tag
}

// baseWorker 基础Worker实现
type baseWorker struct {
	name     string            // worker的名称标识
	creators []Creator[Worker] // Worker创建器列表，用于延迟创建Worker实例
}

// Serve 实现Worker接口的Serve方法
func (b *baseWorker) Serve(ctx context.Context) error {
	workers, err := Map(b.creators, func(creator Creator[Worker]) (Worker, error) {
		return creator()
	})
	if err != nil {
		return err
	}
	return RunWorkers(ctx, workers)
}

// Tag 实现Worker接口的Tag方法
func (b *baseWorker) Tag() string {
	return b.name
}

// NewBaseWorker 创建一个新的baseWorker实例
func NewBaseWorker(name string, creators ...Creator[Worker]) Worker {
	return &baseWorker{name: name, creators: creators}
}

// apiWorker API服务Worker实现
type apiWorker struct {
	name     string               // API服务的名称标识
	listen   string               // HTTP服务器监听地址，格式如":8080"
	creators []Creator[APIWorker] // APIWorker创建器列表，用于延迟创建APIWorker实例
}

// Serve 实现Worker接口的Serve方法
func (api *apiWorker) Serve(ctx context.Context) error {
	workers, err := Map(api.creators, func(t Creator[APIWorker]) (APIWorker, error) {
		return t()
	})
	if err != nil {
		return err
	}
	raw, _ := Map(workers, func(t APIWorker) (Worker, error) {
		return t, nil
	})
	raw = append(raw, &simpleWorker{tag: api.name, fn: api.runApi(workers...)})
	return RunWorkers(ctx, raw)
}

// Tag 实现Worker接口的Tag方法
func (api *apiWorker) Tag() string {
	return api.name
}

// runApi 创建并运行HTTP API服务器的内部方法
func (api *apiWorker) runApi(workers ...APIWorker) func(context.Context) error {
	return func(ctx context.Context) error {
		// 创建新的Gin路由器实例
		r := gin.New()
		// 注册中间件：恢复中间件和日志中间件
		r.Use(
			gin.Recovery(),
			GinLogrusMiddleware,
		)
		// 为每个APIWorker挂载路由
		for _, worker := range workers {
			if worker.Tag() != "" {
				// 如果worker有标签，创建对应的路由组
				worker.Mount(r.Group(fmt.Sprintf("%s", worker.Tag())))
			} else {
				// 如果worker没有标签，直接挂载到根路由
				worker.Mount(r)
			}
		}
		// 创建HTTP服务器
		srv := http.Server{Handler: r, Addr: api.listen}
		// 启动goroutine监听上下文取消信号，优雅关闭服务器
		go func() {
			<-ctx.Done()
			if err := srv.Shutdown(context.Background()); err != nil {
				log.Warn("http server shutdown error", err)
			}
		}()
		// 启动HTTP服务器（阻塞调用）
		return srv.ListenAndServe()
	}
}

// NewApiWorker 创建一个新的apiWorker实例
func NewApiWorker(listen string, creators ...Creator[APIWorker]) Worker {
	return &apiWorker{listen: listen, creators: creators}
}

// GinLogrusMiddleware Gin框架的Logrus日志中间件
func GinLogrusMiddleware(c *gin.Context) {
	// 记录请求开始时间，用于计算处理耗时
	start := time.Now()

	// 继续处理请求链中的下一个处理器
	c.Next()

	// 获取响应状态码和客户端IP
	statusCode := c.Writer.Status()
	clientIP := c.ClientIP()

	// 创建包含请求详细信息的日志条目
	entry := logrus.WithFields(logrus.Fields{
		"clientIP":   clientIP,                   // 客户端IP地址
		"method":     c.Request.Method,           // HTTP请求方法
		"path":       c.Request.URL.Path,         // 请求路径
		"referer":    c.Request.Referer(),        // 请求来源页面
		"userAgent":  c.Request.UserAgent(),      // 用户代理字符串
		"statusCode": statusCode,                 // HTTP响应状态码
		"latency":    time.Since(start).String(), // 请求处理耗时
	})

	// 根据是否有错误和状态码选择日志级别
	if len(c.Errors) > 0 {
		// 如果有错误，记录Error级别日志
		entry.Error(c.Errors.ByType(gin.ErrorTypePrivate).String())
	} else {
		// 构造日志消息
		msg := fmt.Sprintf("%s %s %s referer %s", clientIP, c.Request.Method, c.Request.URL.String(), c.Request.Referer())
		if statusCode == http.StatusOK {
			// 成功请求记录Info级别
			entry.Info(msg)
		} else if statusCode >= http.StatusInternalServerError {
			// 服务器错误记录Error级别
			entry.Error(msg)
		} else {
			// 其他状态码记录Warn级别
			entry.Warn(msg)
		}
	}
}
