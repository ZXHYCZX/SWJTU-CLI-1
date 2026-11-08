package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// HTTPTimeout 返回单次请求超时，SWJTU_CLI_TIMEOUT 秒（默认 30）。
// 校园网不通时避免命令长时间挂起。
func HTTPTimeout() time.Duration {
	if s := os.Getenv("SWJTU_CLI_TIMEOUT"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 30 * time.Second
}

// NewBaseClient 返回一个不自动跟随重定向的 HTTP client。
// 铁律：重定向必须手动逐跳处理，3xx 不能被 client 内部吞掉，
// 否则 CAS 登录无法从 Location 中截获 ticket。
func NewBaseClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: HTTPTimeout(),
	}
}

// Do 发送请求并读全部 body；返回状态码与响应头（重定向需手动逐跳跟随）。
func Do(ctx context.Context, client *http.Client, req *http.Request) (int, http.Header, []byte, error) {
	if client == nil {
		client = NewBaseClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, &ServiceError{Msg: fmt.Sprintf("请求失败: %v", err)}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return resp.StatusCode, resp.Header, nil, &ServiceError{Msg: fmt.Sprintf("读取响应失败: %v", err)}
	}
	return resp.StatusCode, resp.Header, b, nil
}

// HTTPGet 是便捷的 GET 封装。
func HTTPGet(ctx context.Context, client *http.Client, rawurl string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", "swjtu-cli")
	return Do(ctx, client, req)
}

// debugRequest 在 SWJTU_CLI_DEBUG=1 时向 stderr 打印请求详情（诊断用）。
func debugRequest(method, url, token string) {
	if os.Getenv("SWJTU_CLI_DEBUG") != "1" {
		return
	}
	masked := token
	if len(masked) > 12 {
		masked = masked[:12] + "..."
	}
	fmt.Fprintf(os.Stderr, "[debug] %s %s\n[debug] ytoken: %s\n", method, url, masked)
}
