package auth

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"swjtu-cli/internal/config"
)

// 本文件实现办事大厅（userhall，xgsys.swjtu.edu.cn）的静默登录与 API 客户端。
//
// 登录链（全程不注销 SSO，与 oneloginout.aspx 的单次登录链相反）：
//   1. CAS 桥为 service=https://xgsys.swjtu.edu.cn/cas/onelogin.aspx 签发 ticket；
//   2. GET onelogin.aspx?ticket → 验票下发 .ASPXAUTH，302 回落点页；
//   3. 落点页 HTML 里解析 Captcha-Token（后续 API 请求头需要）；
//   4. GET /userhall/login/thirdpartycas → 下发 ASPXAUTH_USERHALL_AUTH（大厅会话）。
// 之后即可访问 /userhall/api/*。

const (
	userhallBase     = "https://xgsys.swjtu.edu.cn"
	userhallOnelogin = userhallBase + "/cas/onelogin.aspx"
)

var reUserHallToken = regexp.MustCompile(`id="Captcha-Token" value="([^"]+)"`)

// UserHallClient 是办事大厅客户端。
type UserHallClient struct {
	HTTP  *http.Client
	Token string // Captcha-Token（登录时从落点页解析）
}

// NewUserHallClient 载入已保存的大厅会话；无效时由调用方走 Login。
// 本地没有 CAS 会话时返回错误。
func NewUserHallClient() (*UserHallClient, error) {
	if !HasCASSession() {
		return nil, &UnauthenticatedError{Msg: "尚未登录，请先执行 swjtu auth login 或 swjtu app login"}
	}
	c := &UserHallClient{}
	if sess, err := config.LoadUserHallSession(); err == nil && sess != nil && len(sess.Cookies) > 0 {
		client := NewBaseClient()
		jar, _ := cookiejar.New(nil)
		restoreUserHallCookies(jar, sess.Cookies)
		client.Jar = jar
		c.HTTP = client
		c.Token = sess.Token
	}
	return c, nil
}

// restoreUserHallCookies 按 cookie 自身的 Domain/Path 精确恢复
// （restoreAppCookies 是为 i.swjtu/CAS 写的，会把 xgsys 的 cookie 路由错）。
func restoreUserHallCookies(jar *cookiejar.Jar, cookies []config.HTTPCookie) {
	if jar == nil {
		return
	}
	for _, ck := range cookies {
		host := strings.TrimPrefix(strings.ToLower(ck.Domain), ".")
		if host == "" {
			host = "xgsys.swjtu.edu.cn"
		}
		path := ck.Path
		if path == "" {
			path = "/"
		}
		u := &url.URL{Scheme: "https", Host: host, Path: path}
		jar.SetCookies(u, []*http.Cookie{{
			Name: ck.Name, Value: ck.Value, Path: ck.Path, Domain: ck.Domain,
			Expires: ck.Expires, Secure: ck.Secure, HttpOnly: ck.HttpOnly,
		}})
	}
}

// EnsureSession 保证大厅会话可用；失效时用 CAS 桥静默重登。
func (c *UserHallClient) EnsureSession(ctx context.Context) error {
	if c.HTTP != nil && c.alive(ctx) {
		return nil
	}
	return c.Login(ctx)
}

func (c *UserHallClient) alive(ctx context.Context) bool {
	status, _, _, err := c.do(ctx, http.MethodGet, "/userhall/api/home/todo/top?top=1", nil, nil)
	return err == nil && status == http.StatusOK
}

// Login 走完整静默链建立大厅会话。
func (c *UserHallClient) Login(ctx context.Context) error {
	bridge, err := LoadCASBridge()
	if err != nil {
		return err
	}
	ticket, err := bridge.ServiceTicket(ctx, userhallOnelogin)
	if err != nil {
		return err
	}
	jar, _ := cookiejar.New(nil)
	client := NewBaseClient()
	client.Jar = jar

	// 1. 验票（跟随 302 到落点页；落点页只有 JS 跳转器，没有 token）
	pageURL := userhallOnelogin + "?ticket=" + url.QueryEscape(ticket)
	if _, err := followForBody(ctx, client, pageURL, 8); err != nil {
		return err
	}
	// 2. thirdpartycas：下发大厅会话，页面携带 Captcha-Token
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, userhallBase+"/userhall/login/thirdpartycas", nil)
	req.Header.Set("User-Agent", "swjtu-cli")
	_, _, tpBody, err := Do(ctx, client, req)
	if err != nil {
		return err
	}
	m := reUserHallToken.FindSubmatch(tpBody)
	if m == nil {
		return &LoginError{Msg: "userhall 登录页未找到 Captcha-Token（登录页可能已改版）: " + snippet(tpBody)}
	}
	c.Token = string(m[1])
	c.HTTP = client
	if err := c.persist(); err != nil {
		return err
	}
	return nil
}

// followForBody 手动跟随 302 链，返回最终 200 页面的 body。
func followForBody(ctx context.Context, client *http.Client, start string, maxHops int) ([]byte, error) {
	u := start
	var body []byte
	for i := 0; i < maxHops; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "swjtu-cli")
		status, header, b, err := Do(ctx, client, req)
		if err != nil {
			return nil, err
		}
		body = b
		if status >= 300 && status < 400 {
			loc := header.Get("Location")
			if loc == "" {
				break
			}
			if !strings.HasPrefix(loc, "http") {
				if base, perr := url.Parse(u); perr == nil {
					if ref, rerr := url.Parse(loc); rerr == nil {
						loc = base.ResolveReference(ref).String()
					}
				}
			}
			u = loc
			continue
		}
		return body, nil
	}
	return body, nil
}

// userHallCookieURLs 覆盖大厅与应用（apps/apploadframe）的常见 path。
var userHallCookieURLs = []string{
	userhallBase + "/",
	userhallBase + "/userhall/",
	userhallBase + "/userhall/Sec/",
	userhallBase + "/userhall/api/",
	userhallBase + "/apploadframe/",
	userhallBase + "/apps/",
	userhallBase + "/apps/studentinfo/",
}

// persist 保存大厅会话 cookies + token。
func (c *UserHallClient) persist() error {
	jar, ok := c.HTTP.Jar.(*cookiejar.Jar)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var cookies []config.HTTPCookie
	for _, raw := range userHallCookieURLs {
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
			cookies = append(cookies, config.HTTPCookie{
				Name: ck.Name, Value: ck.Value, Path: ck.Path, Domain: domain,
				Expires: ck.Expires, Secure: ck.Secure, HttpOnly: ck.HttpOnly,
			})
		}
	}
	sess := &config.UserHallSession{
		Cookies:   cookies,
		Token:     c.Token,
		LoginTime: time.Now().Unix(),
	}
	return config.SaveUserHallSession(sess)
}

// do 发起大厅 API 请求（自动带 Captcha-Token 头），返回状态码与 body。
func (c *UserHallClient) do(ctx context.Context, method, path string, body io.Reader, headers map[string]string) (int, http.Header, []byte, error) {
	if c.HTTP == nil {
		return 0, nil, nil, &UnauthenticatedError{Msg: "办事大厅会话未建立"}
	}
	full := path
	if !strings.HasPrefix(full, "http") {
		full = userhallBase + path
	}
	req, err := http.NewRequestWithContext(ctx, method, full, body)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", "swjtu-cli")
	if c.Token != "" {
		req.Header.Set("Captcha-Token", c.Token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return Do(ctx, c.HTTP, req)
}

// GetJSON 调 GET 接口并返回 body；302 跳 CAS 视为会话失效（触发重登）。
func (c *UserHallClient) GetJSON(ctx context.Context, path string) (json.RawMessage, error) {
	return c.jsonCall(ctx, http.MethodGet, path, nil, nil)
}

// PostJSON 调 POST 接口（JSON body + PartialId 可选）。
func (c *UserHallClient) PostJSON(ctx context.Context, path string, payload any, partialID string) (json.RawMessage, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"Content-Type": "application/json"}
	if partialID != "" {
		headers["PartialId"] = partialID
	}
	return c.jsonCall(ctx, http.MethodPost, path, strings.NewReader(string(b)), headers)
}

func (c *UserHallClient) jsonCall(ctx context.Context, method, path string, body io.Reader, headers map[string]string) (json.RawMessage, error) {
	data, err := c.jsonTry(ctx, method, path, body, headers)
	if err == nil {
		return data, nil
	}
	// 会话失效（302 跳 CAS / 401）→ 静默重登重放一次
	if !IsUnauthenticated(err) {
		return nil, err
	}
	if lerr := c.Login(ctx); lerr != nil {
		return nil, err
	}
	return c.jsonTry(ctx, method, path, body, headers)
}

func (c *UserHallClient) jsonTry(ctx context.Context, method, path string, body io.Reader, headers map[string]string) (json.RawMessage, error) {
	// body 是一次性 reader，重放时需要重建；调用方传入构造函数即可，这里简单复制
	var bodyCopy io.Reader
	if body != nil {
		if b, err := io.ReadAll(body); err == nil {
			bodyCopy = strings.NewReader(string(b))
		}
	} else {
		bodyCopy = nil
	}
	status, header, resp, err := c.do(ctx, method, path, bodyCopy, headers)
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusUnauthorized:
		return nil, &UnauthenticatedError{}
	case status >= 300 && status < 400:
		if strings.Contains(header.Get("Location"), "cas.swjtu.edu.cn") {
			return nil, &UnauthenticatedError{}
		}
		return nil, &ServiceError{StatusCode: status, Msg: "意外重定向: " + header.Get("Location")}
	case status != http.StatusOK:
		return nil, &ServiceError{StatusCode: status, Msg: snippet(resp)}
	}
	// 部分接口用 200 + {"LoginUrl":...,"Msg":"登录信息已失效..."} 表示未登录
	if len(resp) > 0 && strings.Contains(string(resp), `"LoginUrl"`) &&
		(strings.Contains(string(resp), "登录信息已失效") || strings.Contains(string(resp), "重新登录")) {
		return nil, &UnauthenticatedError{}
	}
	return json.RawMessage(resp), nil
}

// PartialIDs 从大厅首页解析各分区（Todo/MyServices/Announcement）的 GUID。
// service/get/all 等 POST 接口需要 PartialId 请求头。
func (c *UserHallClient) PartialIDs(ctx context.Context) (map[string]string, error) {
	body, err := followForBody(ctx, c.HTTP, userhallBase+"/userhall/Sec/page/index", 5)
	if err != nil {
		return nil, err
	}
	s := string(body)
	out := map[string]string{}
	re := regexp.MustCompile(`partial="([A-Za-z]+)"[^>]*id="([0-9a-fA-F-]{36})"|id="([0-9a-fA-F-]{36})"[^>]*partial="([A-Za-z]+)"`)
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		if m[1] != "" {
			out[m[1]] = m[2]
		} else if m[4] != "" {
			out[m[4]] = m[3]
		}
	}
	return out, nil
}

// Ensure 便捷入口：NewUserHallClient + EnsureSession。
func EnsureUserHallClient(ctx context.Context) (*UserHallClient, error) {
	c, err := NewUserHallClient()
	if err != nil {
		return nil, err
	}
	if err := c.EnsureSession(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// reFormAction / reFormInput 解析 ASP.NET WebForms 自动回发页。
var (
	reFormAction = regexp.MustCompile(`(?is)<form[^>]*action="([^"]*)"`)
	reFormInput  = regexp.MustCompile(`(?is)<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"`)
	reQuotedJSON = regexp.MustCompile(`^\s*"(.*)"\s*$`)
)

// ServiceLanding 是一次服务跳转的落点。
type ServiceLanding struct {
	ServiceID string `json:"service_id"`
	JumpURL   string `json:"jump_url"`
	FinalURL  string `json:"final_url"`
	Title     string `json:"title,omitempty"`
	Text      string `json:"text,omitempty"`
}

// OpenService 打开一个办事服务：jump API（form 编码）→ WebForms 自动回发
// → 应用落点。serviceID 是服务 GUID（hall services 里取）。
func (c *UserHallClient) OpenService(ctx context.Context, serviceID string) (*ServiceLanding, error) {
	// 1. 取跳转 URL（注意：该接口只接受 form 编码，JSON 会 500）
	form := url.Values{"serviceid": {serviceID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		userhallBase+"/userhall/api/omni/get/jump/url",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.Token != "" {
		req.Header.Set("Captcha-Token", c.Token)
	}
	status, _, body, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &ServiceError{StatusCode: status, Msg: snippet(body)}
	}
	jump := strings.TrimSpace(string(body))
	if m := reQuotedJSON.FindStringSubmatch(jump); m != nil {
		jump = m[1]
	}
	if !strings.HasPrefix(jump, "http") {
		return nil, &ServiceError{Msg: "jump API 未返回 URL: " + snippet(body)}
	}
	landing := &ServiceLanding{ServiceID: serviceID, JumpURL: jump}

	// 2. 打开跳转页（WebForms 自动回发壳）
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, jump, nil)
	if err != nil {
		return nil, err
	}
	req2.Header.Set("User-Agent", "swjtu-cli")
	_, _, shell, err := Do(ctx, c.HTTP, req2)
	if err != nil {
		return nil, err
	}
	action := reFormAction.FindStringSubmatch(string(shell))
	if action == nil {
		// 不是回发壳：直接当落点处理
		landing.FinalURL = jump
		landing.Title = extractTitle(shell)
		return landing, nil
	}
	// 3. 解析隐藏域并回发
	postURL := action[1]
	if !strings.HasPrefix(postURL, "http") {
		if base, perr := url.Parse(jump); perr == nil {
			if ref, rerr := url.Parse(postURL); rerr == nil {
				postURL = base.ResolveReference(ref).String()
			}
		}
	}
	form2 := url.Values{}
	for _, m := range reFormInput.FindAllStringSubmatch(string(shell), -1) {
		name := htmlUnescape(m[1])
		val := htmlUnescape(m[2])
		if name == "" || name == "__EVENTTARGET" || name == "__EVENTARGUMENT" {
			continue
		}
		form2.Set(name, val)
	}
	req3, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, strings.NewReader(form2.Encode()))
	if err != nil {
		return nil, err
	}
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.Header.Set("User-Agent", "swjtu-cli")
	req3.Header.Set("Referer", jump)
	// 回发会产生会话 cookie 并 302 到应用首页；手动跟随到落点
	finalURL, finalBody, ferr := followForBodyURL(ctx, c.HTTP, req3, 8)
	if ferr != nil {
		return nil, ferr
	}
	landing.FinalURL = finalURL
	landing.Title = extractTitle(finalBody)
	landing.Text = extractText(finalBody)
	if err := c.persist(); err != nil {
		return landing, err
	}
	return landing, nil
}

// followForURL 跟随重定向链，返回最终 URL 与 body。
func followForBodyURL(ctx context.Context, client *http.Client, req *http.Request, maxHops int) (string, []byte, error) {
	u := req.URL.String()
	var body []byte
	for i := 0; i < maxHops; i++ {
		status, header, b, err := Do(ctx, client, req)
		if err != nil {
			return u, body, err
		}
		body = b
		if status >= 300 && status < 400 {
			loc := header.Get("Location")
			if loc == "" {
				return u, body, nil
			}
			if !strings.HasPrefix(loc, "http") {
				if pu, perr := url.Parse(u); perr == nil {
					loc = pu.Scheme + "://" + pu.Host + loc
				}
			}
			u = loc
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return u, body, err
			}
			req.Header.Set("User-Agent", "swjtu-cli")
			continue
		}
		return u, body, nil
	}
	return u, body, nil
}

var reHTMLTitle = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

func extractTitle(body []byte) string {
	if m := reHTMLTitle.FindSubmatch(body); m != nil {
		return strings.TrimSpace(htmlUnescape(string(m[1])))
	}
	return ""
}

// extractText 粗提取可见文本（去 script/style/标签）。
func extractText(body []byte) string {
	s := reScriptBody.ReplaceAllString(string(body), "")
	s = reStyleBody.ReplaceAllString(s, "")
	s = reAnyTag.ReplaceAllString(s, " ")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

var (
	reScriptBody = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	reStyleBody  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reAnyTag     = regexp.MustCompile(`<[^>]*>`)
	reHTMLEntity = regexp.MustCompile(`&(amp|lt|gt|quot|#39|#x27);`)
)

func htmlUnescape(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", `"`)
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&#x27;", "'")
	return s
}

var _ = reHTMLEntity

// UserHallBaseURL 暴露大厅基址（CLI 提示用）。
func UserHallBaseURL() string { return userhallBase }

var _ = fmt.Sprintf

// ---- 学生基本信息应用（apps/StudentInfo）----

// InfoCategory 是学生基本信息的一个类别页。
type InfoCategory struct {
	Alias string // CLI 别名
	Title string // 页面标题
	Path  string // 相对 apps/StudentInfo/Features 的路径
}

// infoCategories 是 9 类信息的页面映射（frame 标签页顺序）。
var infoCategories = []InfoCategory{
	{"duty", "任职信息", "studentother/MyStuDutyThing.aspx"},
	{"practice", "实践及活动信息", "studentother/MyStuActionPalm.aspx"},
	{"project", "科研项目信息", "StudentOther/MyStuScienThing.aspx"},
	{"paper", "论文及出版物信息", "StudentOther/MyStuDiscourse.aspx"},
	{"patent", "专利信息", "StudentOther/MyStuPatent.aspx"},
	{"skill", "专业技能信息", "StudentOther/MyStuSkillLetter.aspx"},
	{"active", "其他活动信息", "StudentOther/MyOtherActive.aspx"},
}

// InfoCategories 返回支持的类别清单。
func InfoCategories() []InfoCategory { return infoCategories }

var (
	reInfoTotal   = regexp.MustCompile(`共检索到\s*(?:&nbsp;)*\s*(\d+)\s*(?:&nbsp;)*\s*条`)
	reInfoTR      = regexp.MustCompile(`(?is)<tr[^>]*>(.*?)</tr>`)
	reInfoCell    = regexp.MustCompile(`(?is)<t[dh][^>]*>(.*?)</t[dh]>`)
	reInfoRowID   = regexp.MustCompile(`Id=([0-9a-fA-F-]{36})`)
	reInfoAnyTag2 = regexp.MustCompile(`<[^>]*>`)
)

// InfoTable 是一个类别页解析出的记录表。
type InfoTable struct {
	Category string           `json:"category"`
	Title    string           `json:"title"`
	Total    int              `json:"total"`
	Rows     []map[string]any `json:"rows"`
}

// GetInfo 拉取并解析一个类别页。
// WebForms 列表页结构：共检索到 N 条记录 + 数据表（首行表头），
// 行内 Edit/Delete 链接带记录 Id。
func (c *UserHallClient) GetInfo(ctx context.Context, cat InfoCategory) (*InfoTable, error) {
	u := userhallBase + "/apps/StudentInfo/Features/" + cat.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "swjtu-cli")
	_, _, body, err := Do(ctx, c.HTTP, req)
	if err != nil {
		return nil, err
	}
	s := string(body)
	t := &InfoTable{Category: cat.Alias, Title: cat.Title}
	if m := reInfoTotal.FindStringSubmatch(s); m != nil {
		fmt.Sscanf(m[1], "%d", &t.Total)
	}
	// 行序：[汇总行(1格)] -> 表头行(>=2格) -> 数据行...
	rows := reInfoTR.FindAllStringSubmatch(s, -1)
	var headers []string
	for _, row := range rows {
		cells := reInfoCell.FindAllStringSubmatch(row[1], -1)
		if len(cells) < 2 { // 汇总/分页等单格行
			continue
		}
		texts := make([]string, 0, len(cells))
		for _, cell := range cells {
			texts = append(texts, strings.TrimSpace(extractText([]byte(cell[1]))))
		}
		if len(headers) == 0 {
			headers = texts
			continue
		}
		rec := map[string]any{}
		for i, h := range headers {
			h = strings.TrimSpace(strings.ReplaceAll(h, " ", ""))
			if i < len(texts) && texts[i] != "" && h != "" && h != "删除" {
				rec[h] = texts[i]
			}
		}
		if idm := reInfoRowID.FindStringSubmatch(row[1]); idm != nil {
			rec["_id"] = idm[1]
		}
		if len(rec) > 0 {
			t.Rows = append(t.Rows, rec)
		}
	}
	if t.Total == 0 && len(t.Rows) > 0 {
		t.Total = len(t.Rows)
	}
	return t, nil
}

// UploadToken 从大厅首页解析上传服务 token（每会话刷新）。
func (c *UserHallClient) UploadToken(ctx context.Context) (string, error) {
	body, err := followForBody(ctx, c.HTTP, userhallBase+"/userhall/Sec/page/index", 5)
	if err != nil {
		return "", err
	}
	m := reUploadToken.FindSubmatch(body)
	if m == nil {
		return "", &LoginError{Msg: "大厅页面未找到上传 token"}
	}
	return string(m[1]), nil
}

var reUploadToken = regexp.MustCompile(`token=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)

// UploadResult 是一次暂存上传的结果。
type UploadResult struct {
	File     string `json:"file"`
	Path     string `json:"path,omitempty"`
	ShowURL  string `json:"show_url,omitempty"`
	MergeMsg string `json:"msg,omitempty"`
}

// UploadStaging 上传文件到上传服务的暂存区（chunked Upis + Merge）。
// conid 是目标表单的图片列表控件 ID（如 StuDutyThing1_ImageList）。
// 注意：只进暂存区，不会自动写入任何记录。
func (c *UserHallClient) UploadStaging(ctx context.Context, filePath, conid string) (*UploadResult, error) {
	data, err := osReadFile(filePath)
	if err != nil {
		return nil, err
	}
	token, err := c.UploadToken(ctx)
	if err != nil {
		return nil, err
	}
	name := filePath
	if idx := strings.LastIndexAny(name, `/\`); idx >= 0 {
		name = name[idx+1:]
	}
	const chunkSize = 512 * 1024
	chunks := (len(data) + chunkSize - 1) / chunkSize
	if chunks == 0 {
		chunks = 1
	}
	md5sum := md5Hex(data)
	q := url.Values{}
	q.Set("t", "s")
	q.Set("cf", "children")
	q.Set("tot", "50")
	q.Set("c", conid)
	q.Set("btn", "1")
	q.Set("orig", "1")
	q.Set("cut", "1")
	q.Set("uploadedNum", "0")
	q.Set("token", token)
	upURL := "https://xgservice.swjtu.edu.cn/service/uploadserver/FileUpload/Upis?" + q.Encode()
	for i := 0; i < chunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		part := data[start:end]
		body := &bytes.Buffer{}
		writer := multipartWriter(body)
		_ = writer.WriteField("name", name)
		_ = writer.WriteField("type", "application/octet-stream")
		_ = writer.WriteField("size", itoa64(int64(len(data))))
		_ = writer.WriteField("chunks", itoa64(int64(chunks)))
		_ = writer.WriteField("chunk", itoa64(int64(i)))
		_ = writer.WriteField("fileMd5", md5sum)
		partHeader := make(map[string][]string)
		partHeader["Content-Disposition"] = []string{`form-data; name="file"; filename="` + name + `"`}
		partHeader["Content-Type"] = []string{"application/octet-stream"}
		_, _ = writer.CreatePart(partHeader)
		_, _ = body.Write(part)
		_ = writer.Close()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, upURL, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("User-Agent", "swjtu-cli")
		status, _, resp, err := Do(ctx, c.HTTP, req)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK || strings.Contains(string(resp), "错误") && !strings.Contains(string(resp), "已接收") {
			return nil, &ServiceError{StatusCode: status, Msg: "分块上传失败: " + snippet(resp)}
		}
	}
	// Merge
	mergeURL := "https://xgservice.swjtu.edu.cn/service/uploadserver/FileUpload/Merge?" + q.Encode()
	mreq, err := http.NewRequestWithContext(ctx, http.MethodPost, mergeURL,
		strings.NewReader("fileMd5="+md5sum+"&fileName="+url.QueryEscape(name)))
	if err != nil {
		return nil, err
	}
	mreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mreq.Header.Set("User-Agent", "swjtu-cli")
	mstatus, _, mresp, err := Do(ctx, c.HTTP, mreq)
	if err != nil {
		return nil, err
	}
	if mstatus != http.StatusOK {
		return nil, &ServiceError{StatusCode: mstatus, Msg: "合并失败: " + snippet(mresp)}
	}
	out := &UploadResult{File: name, MergeMsg: snippet(mresp)}
	// Merge 响应: [{"data":"<showurl>|<path>|<conid>","et":"2","msg":"上传成功【x】"}]
	var arr []struct {
		Data string `json:"data"`
		Et   string `json:"et"`
		Msg  string `json:"msg"`
	}
	if json.Unmarshal(mresp, &arr) == nil && len(arr) > 0 {
		out.MergeMsg = arr[0].Msg
		parts := strings.Split(arr[0].Data, "|")
		if len(parts) >= 2 {
			out.ShowURL = parts[0]
			out.Path = parts[1]
		}
	}
	return out, nil
}

// osReadFile 读文件（测试隔离用包装）。
func osReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// md5Hex 计算字节流的 MD5 十六进制值（上传服务用它做分块合并键）。
func md5Hex(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// multipartWriter 创建 multipart 写入器。
func multipartWriter(buf *bytes.Buffer) *multipart.Writer { return multipart.NewWriter(buf) }

// itoa64 整数转字符串。
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
