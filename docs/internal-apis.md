# 校内业务系统接口逆向笔记

> 实测时间：2026-11。全部结论来自真实账号抓包与逐跳验证，无任何凭据落盘。
> 参考实现（可运行的 Go CLI）：https://github.com/ZXHYCZX/swjtu-cli
>
> 本文整理统一身份认证（CAS）的信任模型，以及五个业务系统的静默登录链与
> 关键接口，供 SWJTU-CLI 后续按需选用。所有流程均已用学生账号端到端验证。

## 统一身份认证（cas.swjtu.edu.cn）的三级信任

同一账号的 CAS 会话存在三种信任级别，**决定敏感系统是否要求二次认证**：

| 级别 | 产生方式 | 敏感 service 表现 |
|---|---|---|
| 高 | 密码登录 + 短信/OTP 二次认证完成 | 一切 service 静默发票 |
| 低 | 浏览器手动登录（未做二次认证） | 敏感 service 302 → `reAuthLoginView`（可完成一次 reAuth 升级） |
| 无 | TGC 过期 | 登录表单 |

**检测陷阱**：`reAuthLoginView.do` 的页面里同样包含 `pwdEncryptSalt`。
如果用"响应里是否出现登录表单"判断会话失效，会把"需要二次认证"误判为
"会话已失效"。应先匹配 `reAuthLoginView` / `isMultifactor` 标记。

## 各系统静默登录链（均不注销 SSO）

### 扬华小智 App（i.swjtu.edu.cn）

1. `GET /authserver/mobile/auth?appId=1442090678600208384`（SSO 有效时 302 链末端带 `mobile_code`）
2. `POST i.swjtu.edu.cn/swjtu/frontend/app-login/exchangeRsa`：form `content=RSA(JSON)`，
   请求头 `authorization-str=RSA({"timestamp":ms,"ticket":""})`
3. **必须带 App UA**（`ZhilinEai ZhilinSwjtuApp/x.y.z …`），否则服务端按非 App 请求处理
4. 响应 `{e,m,d}`：`e=0` 成功；`e=10013/4600400` 会话失效；`d` 为 RSA 私钥解密后的 JSON
5. 请求加密公钥与响应解密私钥**不是同一对**密钥

### 扬华学堂（yhxt.swjtu.edu.cn）

1. CAS service = `https://yhxt.swjtu.edu.cn/cas-login.html`，302 链取得 `ticket`
2. `GET /yethan/public/casCallback?ticket=` → `{code:"00000", data:{token,...}}`（JWT，约 7 天）
3. 业务请求：GET，参数经 SM2(C1C3C2) 加密后以 `_j=<hex>` 查询参数携带；请求头 `ytoken`
4. 工具箱查询接口：`/yethan/common/mh/*`（部分免登录：teaching-term/teaching-college）
5. 全校历史开课：`GET /yethan/common/course-schedule/listPage/history`，
   参数 `{term:"allTerm", pageNum, pageSize, courseCode?, courseName?, teachId?, termId?, collegeCode?}`

### 交大体测（tycs.swjtu.edu.cn）

1. `GET /prod-api/casService/cas/sso-url` → 返回 service（`/prod-api/casService/cas/callback`）
2. CAS 签发 ticket 后 `POST /prod-api/casService/cas/login`，body `{"ticket":"ST-…"}` → JWT
3. 后续 `Authorization: Bearer <jwt>`；统一包层 `{"code":"0000","msg":…,"data":…}`
4. 成绩：`GET /prod-api/peeService/exam/list/visible/current`（examId 列表）→
   `GET /prod-api/peeService/exam-user/record/current?examId=`（总分/等级/各单项 recordList）

### 办事大厅（xgsys.swjtu.edu.cn/userhall）

**正确入口**（静默、不注销 SSO）：

1. CAS service = `https://xgsys.swjtu.edu.cn/cas/onelogin.aspx`（注意：不带 out）
2. `GET onelogin.aspx?ticket=` → 下发 `.ASPXAUTH`，302 到 JS 落点页
3. `GET /userhall/login/thirdpartycas` → 下发 `ASPXAUTH_USERHALL_AUTH`，
   页面内嵌 `Captcha-Token`（后续 API 请求头需要）
4. API 前缀 `/userhall/api/*`；部分 POST 接口需要 `PartialId` 请求头（大厅首页
   `partial="Todo|MyServices|Announcement"` 元素的 DOM id）
5. 服务跳转：`POST /userhall/api/omni/get/jump/url` **只收 form 编码**（JSON 会 500），
   body `serviceid=<guid>`；返回 JSON 字符串形式的 Omniselector 签票 URL；
   该 URL 是 WebForms 自动回发壳（解析 `__VIEWSTATE/__EVENTVALIDATION` 后 POST）
   才落到真实应用

**陷阱**：App 应用市场里的入口 URL 是 `/userhall/Login` → service
`oneloginout.aspx`（"单次登录"设计）：验票后**主动调用 CAS logout 注销整个
SSO 会话**，且其下发的 `.ASPXAUTH` 不被 `/userhall/Sec/*` 认可。自动化请走
上面的 onelogin.aspx 链。

**上传服务**（xgservice.swjtu.edu.cn，跨域，靠 token 鉴权）：

- token 从大厅首页 HTML 的 `file-upload-url` 里解析（每会话刷新）
- 分块上传 `POST /service/uploadserver/FileUpload/Upis?t=s&cf=<容器>&c=<conid>&token=<t>`，
  multipart：`file/name/type/size/chunks/chunk/fileMd5`
- 合并 `POST …/FileUpload/Merge`，form `fileMd5=&fileName=` → 返回存储 path 与预览 URL

### 一卡通服务大厅（card.swjtu.edu.cn）

1. `GET /cassyno/index` → 302 **内网 IAS** `http://192.168.240.198:8088/ias/prelogin?sysid=FWDT…`
   —— 需校园网环境（校外经 WebVPN）
2. IAS → 302 CAS（service=IAS prelogin）→ 302 回 IAS 带 ticket
3. IAS 验票页内嵌 `ssoticketid`，把表单（errorcode/continueurl/ssoticketid）
   POST 回 `https://card.swjtu.edu.cn/cassyno/index` → 302 `/user/user` → 卡会话
4. 余额：`POST /User/GetCardInfo`（**需显式 `Content-Length: 0`**，否则 411），
   响应壳 `{"IsSucceed":…,"Msg":"<内层 JSON 字符串>"}`，金额单位为分
5. 消费流水页是配置驱动的内部路由，未定位到公开 API

## 已知不可行 / 放弃项

- **智慧学工手机端**（xgsys `/XGPhone/`）：SPA 的 token 通道
  `Account/WeixinLogin?code=` 绑定微信 openId，外部无法复现
- **userhall 旧入口**：见上述单次登录设计
- 图书馆个人借阅（lib.swjtu.edu.cn，维普智图）：检索为匿名 token 体系
  （`/jwt/api/Auth/AccessToken`，orgCode=swjtu），个人借阅入口为 SPA，登录链待逆向

## 状态选择建议

若 SWJTU-CLI 引入需要登录的功能，建议维持现有"浏览器持会话"哲学，或
参考 ZXHYCZX/swjtu-cli 的分层实现：统一 CAS 会话文件（0600）作为万能钥匙 →
各系统静默链换票 → 派生会话文件 + 失效自动重登。三个信任级别的处理与
reAuth 升级流程（changeReAuthType → getDynamicCodeByReauth → reAuthSubmit）
在该仓库 `internal/auth/` 下有完整可运行实现。
