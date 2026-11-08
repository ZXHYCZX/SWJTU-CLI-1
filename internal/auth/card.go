package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"swjtu-cli/internal/config"
)

// 本文件实现校园一卡通（card.swjtu.edu.cn）的静默登录与查询。
//
// 登录链（实测，全部不注销 SSO）：
//   1. GET /cassyno/index → 302 内网 IAS（192.168.240.198，需校园网）
//   2. IAS prelogin → 302 CAS login?service=<IAS>
//   3. CAS（TGC）→ 302 IAS?...&ticket=ST
//   4. IAS 验票 → 200 回发表单（ssoticketid）
//   5. POST 回发字段到 /cassyno/index → 302 /user/user → 卡会话
//
// 注意：第 1-2 步依赖校园网访问内网 IAS；校外需先连 WebVPN。

const cardBaseURL = "https://card.swjtu.edu.cn"

var (
	reSsoTicketID  = regexp.MustCompile(`name="ssoticketid"\s*id="ssoticketid" value="([^"]+)"`)
	reContinueURL  = regexp.MustCompile(`name="continueurl"\s*id="continueurl" value="([^"]+)"`)
	reErrorCode    = regexp.MustCompile(`name="errorcode"\s*id="errorcode"\s*value="([^"]+)"`)
	reCardInnerURL = regexp.MustCompile(`http://192\.168\.[0-9.]+:\d+[^"']*`)
)

// CardClient 是一卡通服务大厅客户端。
type CardClient struct {
	HTTP *http.Client
}

// NewCardClient 载入已保存的卡会话；没有则返回未登录。
func NewCardClient() (*CardClient, error) {
	if !HasCASSession() {
		return nil, &UnauthenticatedError{Msg: "尚未登录，请先执行 swjtu auth login 或 swjtu app login"}
	}
	c := &CardClient{}
	if sess, err := config.LoadCardSession(); err == nil && sess != nil && len(sess.Cookies) > 0 {
		client := NewBaseClient()
		jar, _ := cookiejar.New(nil)
		restoreUserHallCookies(jar, sess.Cookies) // 同样按 Domain/Path 精确恢复
		client.Jar = jar
		c.HTTP = client
	}
	return c, nil
}

// EnsureSession 保证卡会话可用；失效时静默重登（需校园网）。
func (c *CardClient) EnsureSession(ctx context.Context) error {
	if c.HTTP != nil && c.alive(ctx) {
		return nil
	}
	return c.Login(ctx)
}

func (c *CardClient) alive(ctx context.Context) bool {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cardBaseURL+"/user/user", nil)
	req.Header.Set("User-Agent", "swjtu-cli")
	status, header, _, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return false
	}
	// 200 = 已登录；302 回首页/CAS = 失效
	return status == http.StatusOK && !strings.Contains(header.Get("Location"), "cassyno")
}

// Login 走完整 SSO 链建立卡会话。
func (c *CardClient) Login(ctx context.Context) error {
	bridge, err := LoadCASBridge()
	if err != nil {
		return err
	}
	client := NewBaseClient()
	jar, _ := cookiejar.New(nil)
	client.Jar = jar

	// 1-2: cassyno → IAS prelogin → CAS
	status, header, _, err := HTTPGet(ctx, client, cardBaseURL+"/cassyno/index")
	if err != nil {
		return err
	}
	casURL := ""
	for i := 0; i < 6; i++ {
		if status < 300 || status >= 400 {
			break
		}
		loc := header.Get("Location")
		if loc == "" {
			break
		}
		if strings.Contains(loc, "authserver/login") {
			casURL = loc
			break
		}
		status, header, _, err = HTTPGet(ctx, client, loc)
		if err != nil {
			return err
		}
	}
	if casURL == "" {
		return &LoginError{Msg: "一卡通 SSO 链未找到 CAS 入口（需校园网访问内网 IAS）"}
	}
	// 3: CAS 发票（bridge 的 cookie 需要并进来：直接用 bridge 的 client 铸票）
	ticket, err := bridge.ServiceTicket(ctx, casURL[strings.Index(casURL, "service=")+len("service="):])
	if err != nil {
		// casURL 里的 service 是 URL 编码的，ServiceTicket 需要 service 本身
		if u, perr := url.Parse(casURL); perr == nil {
			ticket, err = bridge.ServiceTicket(ctx, u.Query().Get("service"))
		}
		if err != nil {
			return err
		}
	}
	// 4: 带 ticket 走到 IAS 回发表单
	sep := "&"
	if !strings.Contains(casURL[strings.Index(casURL, "service="):], "%26") {
		// casURL 的 service 参数内含编码的 continueurl；直接拼 ticket 到 CAS 返回的 Location 链
	}
	_ = sep
	iasURL := ""
	if u, perr := url.Parse(casURL); perr == nil {
		iasURL = u.Query().Get("service")
	}
	status, header, _, err = HTTPGet(ctx, client, iasURL+"&ticket="+url.QueryEscape(ticket))
	if err != nil {
		return err
	}
	var body []byte
	for i := 0; i < 6; i++ {
		if status < 300 || status >= 400 {
			break
		}
		loc := header.Get("Location")
		if loc == "" {
			break
		}
		status, header, body, err = HTTPGet(ctx, client, loc)
		if err != nil {
			return err
		}
	}
	_ = body
	// 重新取回发表单页（可能中间 302 到带 jsessionid 的 URL）
	status, _, formBody, err := HTTPGet(ctx, client, iasURL)
	if err != nil {
		return err
	}
	_ = status
	// 5: 解析并回发
	tid := ""
	if m := reSsoTicketID.FindSubmatch(formBody); m != nil {
		tid = string(m[1])
	}
	if tid == "" {
		return &LoginError{Msg: "IAS 回发页未找到 ssoticketid: " + snippet(formBody)}
	}
	cont := "https://card.swjtu.edu.cn/cassyno/index"
	if m := reContinueURL.FindSubmatch(formBody); m != nil {
		cont = string(m[1])
	}
	ecode := "1"
	if m := reErrorCode.FindSubmatch(formBody); m != nil {
		ecode = string(m[1])
	}
	form := url.Values{}
	form.Set("errorcode", ecode)
	form.Set("continueurl", cont)
	form.Set("ssoticketid", tid)
	preq, err := http.NewRequestWithContext(ctx, http.MethodPost, cardBaseURL+"/cassyno/index", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.Header.Set("User-Agent", "swjtu-cli")
	status, header, _, err = Do(ctx, client, preq)
	if err != nil {
		return err
	}
	// 登录成功的标志：302 /user/user
	if status == 302 || status == 303 {
		loc := header.Get("Location")
		if strings.Contains(loc, "user") || strings.Contains(loc, "cassyno") {
			// 跟一跳落位
			if loc != "" {
				if !strings.HasPrefix(loc, "http") {
					loc = cardBaseURL + loc
				}
				_, _, _, _ = HTTPGet(ctx, client, loc)
			}
		}
	}
	c.HTTP = client
	return c.persist()
}

// persist 保存卡会话 cookies。
func (c *CardClient) persist() error {
	jar, ok := c.HTTP.Jar.(*cookiejar.Jar)
	if !ok {
		return nil
	}
	cookies := collectCardCookies(jar, []string{
		cardBaseURL + "/",
		cardBaseURL + "/user/",
		cardBaseURL + "/cassyno/",
	})
	return config.SaveCardSession(&config.CardSession{Cookies: cookies, LoginTime: time.Now().Unix()})
}

// CardInfo 是一卡通账户信息（金额已从分转换为元）。
type CardInfo struct {
	Account     string  `json:"account"`
	Name        string  `json:"name"`
	CardName    string  `json:"card_name"`
	ExpDate     string  `json:"expire_date"`
	ElecBalance float64 `json:"elec_balance"` // 电子账户余额（元）
	DBBalance   float64 `json:"db_balance"`   // 数据库余额（元）
	Unsettle    float64 `json:"unsettle_amount"`
	Lost        bool    `json:"lost"`
	Frozen      bool    `json:"frozen"`
	Status      string  `json:"status"` // 0 正常
}

// GetBalance 查询卡余额与状态。
func (c *CardClient) GetBalance(ctx context.Context) (*CardInfo, error) {
	if c.HTTP == nil {
		return nil, &UnauthenticatedError{Msg: "一卡通会话未建立"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cardBaseURL+"/User/GetCardInfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "swjtu-cli")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Referer", cardBaseURL+"/User/Account")
	req.ContentLength = 0 // 服务端要求显式 Content-Length
	status, _, body, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized || strings.Contains(string(body), "Object moved") {
		return nil, &UnauthenticatedError{}
	}
	// 响应壳：{"IsSucceed":false,"Msg":"<json string>",...} —— 真数据在 Msg 字符串里
	var shell struct {
		Msg string `json:"Msg"`
	}
	if err := json.Unmarshal(body, &shell); err != nil {
		return nil, &ServiceError{StatusCode: status, Msg: "响应解析失败: " + snippet(body)}
	}
	var inner struct {
		QueryCard struct {
			RetCode string `json:"retcode"`
			ErrMsg  string `json:"errmsg"`
			Cards   []struct {
				Account     string `json:"account"`
				Name        string `json:"name"`
				CardName    string `json:"cardname"`
				ExpDate     string `json:"expdate"`
				ElecAccAmt  string `json:"elec_accamt"`
				DBBalance   string `json:"db_balance"`
				UnsettleAmt string `json:"unsettle_amount"`
				LostFlag    string `json:"lostflag"`
				FreezeFlag  string `json:"freezeflag"`
				AccStatus   string `json:"acc_status"`
				SNO         string `json:"sno"`
			} `json:"card"`
		} `json:"query_card"`
	}
	if err := json.Unmarshal([]byte(shell.Msg), &inner); err != nil {
		return nil, &ServiceError{StatusCode: status, Msg: "卡信息解析失败: " + snippet([]byte(shell.Msg))}
	}
	if inner.QueryCard.RetCode != "0" {
		return nil, &ServiceError{Msg: firstNonEmpty(inner.QueryCard.ErrMsg, "卡信息查询失败")}
	}
	if len(inner.QueryCard.Cards) == 0 {
		return nil, &ServiceError{Msg: "没有卡账户"}
	}
	cd := inner.QueryCard.Cards[0]
	return &CardInfo{
		Account:     cd.Account,
		Name:        cd.Name,
		CardName:    cd.CardName,
		ExpDate:     cd.ExpDate,
		ElecBalance: fenToYuan(cd.ElecAccAmt),
		DBBalance:   fenToYuan(cd.DBBalance),
		Unsettle:    fenToYuan(cd.UnsettleAmt),
		Lost:        cd.LostFlag == "1",
		Frozen:      cd.FreezeFlag == "1",
		Status:      cd.AccStatus,
	}, nil
}

// fenToYuan 分转元（空/坏值返回 0）。
func fenToYuan(fen string) float64 {
	var n int64
	if _, err := SscanInt(fen, &n); err != nil {
		return 0
	}
	return float64(n) / 100
}

// CardRaw 调用卡系统任意 GET 接口（调试用）。
func (c *CardClient) CardRaw(ctx context.Context, path string) (json.RawMessage, error) {
	if !strings.HasPrefix(path, "http") {
		path = cardBaseURL + "/" + strings.TrimPrefix(path, "/")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "swjtu-cli")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	status, _, body, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return nil, err
	}
	if status >= 300 && status < 400 {
		return nil, &UnauthenticatedError{}
	}
	return json.RawMessage(body), nil
}

// collectCardCookies 从 jar 收集指定 URL 列表下的全部 cookie。
func collectCardCookies(jar *cookiejar.Jar, urls []string) []config.HTTPCookie {
	seen := map[string]bool{}
	var out []config.HTTPCookie
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for _, ck := range jar.Cookies(u) {
			domain := ck.Domain
			if domain == "" {
				domain = u.Hostname()
			}
			key := ck.Name + "|" + domain + "|" + ck.Path
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, config.HTTPCookie{
				Name: ck.Name, Value: ck.Value, Path: ck.Path, Domain: domain,
				Expires: ck.Expires, Secure: ck.Secure, HttpOnly: ck.HttpOnly,
			})
		}
	}
	return out
}

// SscanInt 解析整数（分转元用）。
func SscanInt(s string, n *int64) (int, error) { return fmt.Sscanf(s, "%d", n) }
