# Go Desensitize - 零依赖数据脱敏库

> `go-desensitize` 把敏感数据的隐藏做成三条互不干扰的路：**结构体 tag 逐字段声明**、**字段名启发式判定**、**整段报文重写**，另提供持密钥可还原的加密脱敏
> 零第三方依赖、100% 语句覆盖；按类型缓存处理计划、注册表写时拷贝，热路径无锁且多数形态零分配

[![stable](https://img.shields.io/badge/stable-stable-green.svg)](https://github.com/kamalyes/go-desensitize)
[![license](https://img.shields.io/github/license/kamalyes/go-desensitize)]()
[![release](https://img.shields.io/github/v/release/kamalyes/go-desensitize)]()
[![commit](https://img.shields.io/github/last-commit/kamalyes/go-desensitize)]()
[![issues](https://img.shields.io/github/issues/kamalyes/go-desensitize)]()
[![pull](https://img.shields.io/github/issues-pr/kamalyes/go-desensitize)]()
[![fork](https://img.shields.io/github/forks/kamalyes/go-desensitize)]()
[![star](https://img.shields.io/github/stars/kamalyes/go-desensitize)]()
[![go](https://img.shields.io/github/go-mod/go-version/kamalyes/go-desensitize)]()
[![size](https://img.shields.io/github/repo-size/kamalyes/go-desensitize)]()
[![contributors](https://img.shields.io/github/contributors/kamalyes/go-desensitize)]()
[![deps](https://img.shields.io/badge/deps-0-brightgreen)]()
[![coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)]()
[![codecov](https://codecov.io/gh/kamalyes/go-desensitize/branch/master/graph/badge.svg)](https://codecov.io/gh/kamalyes/go-desensitize)
[![Go Report Card](https://goreportcard.com/badge/github.com/kamalyes/go-desensitize)](https://goreportcard.com/report/github.com/kamalyes/go-desensitize)
[![Go Reference](https://pkg.go.dev/badge/github.com/kamalyes/go-desensitize?status.svg)](https://pkg.go.dev/github.com/kamalyes/go-desensitize?tab=doc)
[![Sourcegraph](https://sourcegraph.com/github.com/kamalyes/go-desensitize/-/badge.svg)](https://sourcegraph.com/github.com/kamalyes/go-desensitize?badge)

[English](README.md) · **中文**

## ✨ 特性亮点

- 🪶 **零第三方依赖** - 使用者编译本库时第三方包数为 0，`testify` 仅测试用，不进入任何使用者的构建图
- 🧪 **100% 语句覆盖** - 包含理论上不可达的防御分支，均以可注入缝隙闸住其行为
- 🏷️ **结构体 tag 驱动** - `desensitize:"mobilePhone"` 逐字段声明，你掌握 schema 时最准的方式
- 🔎 **字段名启发式** - 拿不到 schema 时按名字猜，200 余条规则分严格与宽松两档
- 📦 **报文整体脱敏** - 请求/响应体按字段名重写，JSON 与文本双路径
- 🔐 **可还原加密脱敏** - AES-GCM 带认证加密，密文带版本标识，持密钥可还原
- ⚡ **按类型缓存计划** - tag 解析与脱敏器绑定每类型只算一次，并发无锁
- 🎯 **21 种内置脱敏类型** - 手机号、身份证、银行卡、邮箱、IP、PEM 密钥、各类 ID
- 🧩 **可扩展** - 自定义脱敏器与参数化工厂，`jump(3,-4,1)` 这类带参数标签开箱可用
- 🛡️ **失败关闭** - 加密不可用时整体擦除，绝不留下明文

## ⚠️ 重要默认值

这几条默认行为会直接影响线上结果，接入前先过一遍：

| 默认值 | 行为 | 需要注意什么 |
| --- | --- | --- |
| **`cipher` tag 未装配密钥 = 整体擦除** | 字段变成 `[REDACTED]` | 忘记调 `SetDefaultCipher` 的后果是**看不到数据**，而不是明文漏出去；这是故意的失败关闭 |
| **本库不提供默认密钥** | `SetDefaultCipher` 必须由调用方给 key | 写死默认密钥等于没加密，随机生成则重启即丢数据，两者都比没有更坏 |
| 加密每次输出不同 | 随机 nonce，同一明文密文不同 | 密文**不能**用于比较与去重；需要这类能力请另存一份哈希 |
| **`MaskerConfig.SensitiveKeys` 只追加** | 内置规则表始终生效 | 无法通过配置把 `password` 配成不敏感——不允许意外收窄安全基线 |
| 报文上限 = 10KB | 超限先截断再脱敏 | 截断后多半已非合法 JSON，会落到文本路径；需要完整处理用 `WithMaxBodySize(n)` |
| 字段名判定 = 两档 | 日志用严格档、报文用宽松档 | 选错会既误擦又漏擦，分工见下表 |
| **会话与令牌默认整体擦除** | `session_id`、`token`、`cookie`、`authorization` 看不到 | 它们是可重放的凭据；需要跨行关联或事故定位时用 `OverrideKeyAction` 调成指纹或加密，而不是改成明文 |
| **Model 不走字段名启发式** | 只认 `desensitize` tag | 规则表是按日志调的，`name`、`status_code` 这些取舍对 Model 是错的 |
| 掩码不可逆 | `Desensitize` 系列丢弃被掩字符 | 需要还原的字段用 `cipher` tag，不要指望从掩码恢复 |
| **`BankCard` 不幂等** | 每遍插入分组空格并重新补位，越跑越长 | 12 个类型里只有它不幂等；中间件与仓储层各脱一次会产出越来越长的垃圾，要自己保证只脱一次 |
| Go 版本 = 1.20 | 不用任何 1.21+ 符号 | 零依赖库刻意压低语言版本，便于被老工具链的项目引用 |

## 🚀 快速开始

### 安装

```bash
go get github.com/kamalyes/go-desensitize
```

语言版本压到 `go 1.20`：本库零依赖，没有任何 1.21+ 的内建或标准库符号，可吃下尽量旧的工具链

### 结构体 tag 驱动（推荐）

贴近真实的订单模型：多层嵌套、结构体指针、指针切片、映射、七种 tag 混用

```go
import "github.com/kamalyes/go-desensitize"

type Contact struct {
    RealName string `desensitize:"name"`
    Phone    string `desensitize:"mobilePhone"`
    Email    string `desensitize:"email"`
}

type Address struct {
    Contact Contact        // 嵌套结构体，自动下钻
    Detail  string `desensitize:"address"`
    Zip     string         // 无 tag，原样保留
}

type Item struct {
    SKU   string
    Price int64
}

type Order struct {
    OrderNo  string            `desensitize:"orderNo"`
    Buyer    Contact
    Shipping *Address          // 结构体指针，自动下钻；nil 安全
    Items    []*Item           // 指针切片，逐元素下钻
    CardNo   string            `desensitize:"bankCard"`
    IDCardNo string            `desensitize:"identityCard"`
    Audit    map[string]string `desensitize:"secret"`
    Total    int64             // 非字符串字段不动
    Status   string
}

if err := desensitize.Desensitization(&order); err != nil {
    log.Fatal(err)
}
```

脱敏后：

```json
{
  "OrderNo": "12************56",
  "Buyer": {
    "RealName": "张**",
    "Phone": "181****8789",
    "Email": "z*********ng@example.com"
  },
  "Shipping": {
    "Contact": {
      "RealName": "李**",
      "Phone": "138****8000",
      "Email": "l*si@example.com"
    },
    "Detail": "上海市浦东新***********18层",
    "Zip": "201203"
  },
  "Items": [
    { "SKU": "SKU-1", "Price": 9900 },
    { "SKU": "SKU-2", "Price": 10000 }
  ],
  "CardNo": "6222 **** **** **** 5678",
  "IDCardNo": "310101********5678",
  "Audit": { "operator": "s3cr****oken" },
  "Total": 19900,
  "Status": "PAID"
}
```

要点：`Zip`、`SKU`、`Price`、`Total`、`Status` 都没有 tag，原样保留；`Shipping` 是指针也照样下钻；`Items` 是指针切片，逐元素处理；`Audit` 是映射，逐值处理

### 单值脱敏

```go
desensitize.Desensitize("18175698789", desensitize.MobilePhone) // 181****8789
desensitize.Desensitize("310101199001015678", desensitize.IDCard) // 310101********5678
desensitize.Desensitize("192.168.1.1", desensitize.IPV4)        // 192.*.*.*
desensitize.Desensitize("sk-abcdefghijklmnopqrstuvwxyz", desensitize.Secret) // sk-a*********************wxyz
```

### 可还原的加密脱敏

```go
// 启动阶段装配一次，之后 tag 直接可用
key, _ := base64.StdEncoding.DecodeString(os.Getenv("MASK_KEY")) // 16 / 24 / 32 字节
if err := desensitize.SetDefaultCipher(key); err != nil {
    log.Fatal(err)
}

type Order struct {
    Receiver string `desensitize:"cipher"`      // 加密，可还原
    Phone    string `desensitize:"mobilePhone"` // 掩码，不可还原
}

order := Order{Receiver: "张三丰", Phone: "18175698789"}
_ = desensitize.Desensitization(&order)
// Receiver → enc:v1:4_23fCUS6PeK-EgNPafx...
// Phone    → 181****8789

plain, err := desensitize.DefaultCipher().Decrypt(order.Receiver) // "张三丰"
```

> ⚠️ **本库不提供默认密钥**，两种「默认」都比没有更危险：写死一个等于没加密，拿到源码的人都能解开；启动时随机生成则进程重启就换钥匙，上次写进数据库的值再也解不开
> 未装配密钥时使用 `cipher` tag，字段会被**整体擦除**而不是留下明文——忘记装配的后果应当是「看不到数据」，而不是「以为加密了其实是明文」

### 会话与令牌：关联、定位、泄漏三者的取舍

`session_id`、`token`、`cookie`、`authorization` 默认**整体擦除**，这是有意的：
它们是可重放的凭据，日志会被集中收集、很多人能读、保留数月，
任何看得到的人复制走就能冒用该用户直到过期，而且没有审计痕迹

但运维上有两个真实需求：**把一个登录会话的请求跨行串起来**，以及**出事时定位到底是谁**
为此提供两档中间选项，用 `OverrideKeyAction` 按字段选：

| 做法 | 跨行关联 | 出事定位身份 | 需要密钥 | 泄漏风险 |
|------|:--------:|:------------:|:--------:|----------|
| `KeepAsIs`（明文） | ✅ | ✅ | 否 | **凭据可重放** |
| `WipeValue`（默认） | ❌ | ❌ | 否 | 无 |
| `MaskFingerprint` | ✅ | ❌ | 否 | 仅泄漏「两值相等」 |
| `MaskEncrypt` | ✅ | ✅ | 是 | 仅泄漏「两值相等」 |

```go
// 只要能把一个会话的请求串起来，不需要密钥
desensitize.OverrideKeyAction("session_id", desensitize.MaskFingerprint)
// {"session_id":"***6a9f3e7a","trace_id":"t-xyz","user_id":"u-1001"}
// 同一会话每行都是 ***6a9f3e7a，但无法还原也无法重放

// 还要能在事故复盘时还原出是哪个会话
desensitize.SetDefaultCipher(key)
desensitize.OverrideKeyAction("session_id", desensitize.MaskEncrypt)
// {"session_id":"enc:v1:lFDr0e-L0k777_lQwKkRY8DPwvQek601DxXD10...","trace_id":"t-xyz"}

plain, _ := desensitize.DefaultCipher().Decrypt(sealed) // "sess-abc123def456"
```

`MaskEncrypt` 走的是**确定性加密**（nonce 由明文经 HMAC 派生，SIV 构造），
所以同一会话在所有日志行里是同一串密文——若用随机 nonce，身份能还原但关联就断了

三点要知道：

- 两档都**必然**泄漏「两个字段的值相等」，这正是可关联的前提；连相等关系都不能暴露时只能 `WipeValue`
- `MaskEncrypt` 未装配密钥时字段**整体擦除**而非退回明文：你要的是「可还原」不是「可见」，配置出错不该静默泄漏
- 很多时候根本不需要动它们——`user_id`、`trace_id`、`request_id`、`span_id`、`device_id` 默认就是明文，「追一个用户的请求链」用它们就够了

### 报文脱敏

```go
masker := desensitize.NewMasker()
```

**嵌套 JSON** —— 凭据擦除、联系方式保留尾部、排障字段全部可见：

```go
masker.Mask([]byte(`{
  "requestId": "req-9527",
  "user": {"id":10086,"realName":"张三丰","mobile":"13800138000","email":"zhangsanfeng@example.com"},
  "payment": {"cardNo":"6222025678565678","cvv":"123","amount":19900},
  "trace": {"traceId":"t-abc","statusCode":200,"cacheKey":"ck-1"}
}`))
```

```json
{
  "requestId": "req-9527",
  "user": {
    "id": 10086,
    "realName": "***",
    "mobile": "***8000",
    "email": "z***@example.com"
  },
  "payment": { "cardNo": "***", "cvv": "***", "amount": 19900 },
  "trace": { "traceId": "t-abc", "statusCode": 200, "cacheKey": "ck-1" }
}
```

`id`、`amount`、`requestId` 与整个 `trace` 都保留：排障线索被擦掉的日志等于没有日志

**HTTP 头部** —— 取值延伸到行尾，不会只擦掉 `Bearer` 把 token 留下：

```go
masker.Mask([]byte("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig\n" +
    "X-Request-Id: req-9527\nCookie: sid=abc123\nAccept: application/json"))
```

```
Authorization: ***
X-Request-Id: req-9527
Cookie: ***
Accept: application/json
```

**表单与查询串** —— 止于 `&` 或空白，相邻键值对不受影响：

```go
masker.Mask([]byte("GET /api?user=bob&token=abc123 HTTP/1.1"))
// GET /api?user=bob&token=*** HTTP/1.1

masker.Mask([]byte("ts=2025-12-23 token=abc123 user=bob level=info"))
// ts=2025-12-23 token=*** user=bob level=info
```

> ⚠️ 字段名本身命中规则时，**整个容器**会被擦成一个字符串而不再下钻：一个叫 `credentials` 的对象会整体消失，连里面本该可见的 `publicKey` 一起不要把容器命名成敏感词

### 解密调试台

事故复盘时拿到一行日志，里面是 `enc:v1:...`，需要解回原文
仓库里带了一个离线单文件工具：[tools/decrypt.html](tools/decrypt.html)

直接用浏览器从本地打开，三件事都能做：

- **解密**：整段粘贴日志行，自动找出其中所有密文逐个解开
- **反查**：已经知道要查哪个会话时，反过来算出它在日志里长什么样，然后直接 grep
  （只有确定性加密与指纹能这样用 —— 随机 nonce 的密文每次都不同，没法拿来搜）
- **指纹核对**：指纹不可逆，但可以给出候选原值，看哪个的指纹与日志里那串一致

密钥支持**一行一把填多个**：轮换后旧日志还是旧密钥加的，解密时会逐把试并标出哪把解开的
反查则把每把密钥的结果并排列出来，直接看出「指纹与密钥无关、密文随密钥而变」——
也就是轮换会让旧密文搜不到，而指纹跨轮换依然可用，代价是不可还原

```bash
open tools/decrypt.html          # macOS
xdg-open tools/decrypt.html      # Linux
```

> ⚠️ **只从本地 `file://` 打开，不要部署**
> 带着密钥把它部署成网页，等于给所有能访问它的人开了一个解密预言机，比日志里直接存明文更糟——明文至少还需要先拿到日志
> 该文件不引入任何外部资源、不发网络请求、不保存密钥，全部运算走浏览器自带的 WebCrypto

### 字段名启发式

拿不到 schema 时（日志 KV、上游返回的任意 JSON）按字段名猜，两档强度：

```go
// 严格档：精确 + 后缀匹配，带运维豁免，适合日志
desensitize.ActionForKey("user_password")  // WipeValue
desensitize.ActionForKey("cache_key")      // KeepAsIs（运维字段豁免）
desensitize.ActionForKey("my_token_field") // KeepAsIs（词根不在后缀位置）

// 宽松档：再加字段名内部的词根，适合报文
desensitize.ActionForKeyLoose("my_token_field") // WipeValue
desensitize.ActionForKeyLoose("cache_key")      // KeepAsIs（豁免仍生效）

// 零分配的掩码追加器
buf = desensitize.AppendMaskedPhone(buf, "+86 138-0013-8000") // ***8000
buf = desensitize.AppendMaskedEmail(buf, "a@example.com")     // a***@example.com
```

## 🏗️ 三条入口的分工

这三条路解决的不是同一个问题，取舍方向也不同，选错会既误擦又漏擦：

| 入口 | 判定依据 | 适用场景 | 取舍 |
|------|----------|----------|------|
| `Desensitization(obj)` | 结构体 tag 逐字段声明 | 自己的 Model | 最准，不猜 |
| `ActionForKey(key)` | 字段名严格匹配 | 日志 KV | 保守，宁可漏擦 |
| `ActionForKeyLoose(key)` | 字段名 + 内部词根 | 报文 / 响应体 | 激进，宁可误擦 |
| `DataMasker.Mask(body)` | 同上，整段重写 | 请求 / 响应体 | 激进 |

### 为什么 Model 不走字段名启发式

字段名规则表是按**日志**调出来的，它的取舍对 Model 是错的：

- `name` 不入表：通用日志里 `service_name`、`table_name`、`file_name` 远多于人名
- `status_code`、`cache_key`、`trace_id` 进豁免表：它们是排障主线索，擦掉日志就失去价值

而在一个 Model 里，`Name` 字段通常就是人名，`Address` 通常就是收货地址
所以 Model 这条路**完全不碰规则表**，只认你写的 tag——你掌握 schema 时显式声明永远比猜更准

## 📋 内置脱敏类型

| 类型 | 说明 | 示例输入 | 示例输出 |
|------|------|----------|----------|
| `ChineseName` | 中文姓名 | 张三丰 | `张**` |
| `IDCard` | 身份证号 | 310101199001015678 | `310101********5678` |
| `PhoneNumber` | 固话/号码 | 18175698789 | `181****8789` |
| `MobilePhone` | 手机号 | 18175698789 | `181****8789` |
| `Address` | 地址 | 北京市朝阳区某某路99号 | `北京市朝*****99号` |
| `Email` | 邮箱 | zhangsanfeng@example.com | `z*********ng@example.com` |
| `Password` | 密码 | hunter2 | `h******` |
| `CarLicense` | 车牌号 | 京A12345 | `京A1**45` |
| `BankCard` | 银行卡号 | 6222025678565678 | `6222 **** **** **** 5678` |
| `IPV4` / `IPV6` | IP 地址 | 192.168.1.1 | `192.*.*.*` |
| `PEMKey` | PEM 密钥 | -----BEGIN ... | 首尾行保留，正文掩码 |
| `APIKey` / `Secret` | 密钥 | sk-abcdefghijklmnopqrstuvwxyz | `sk-a*********************wxyz` |
| `UserID` / `PlayerID` / `OrderNo` / `UUID` / `OpenID` / `Account` | 各类 ID | 1234567890 | `12******90` |
| `CustomExtension` | 自定义 | 由 `DesensitizeOptions` 控制 | - |

### 自定义脱敏器

```go
type upperDesensitizer struct{}

func (upperDesensitizer) Desensitize(v string) string { return strings.ToUpper(v) }

desensitize.RegisterDesensitizer("upper", upperDesensitizer{})
// 之后 desensitize:"upper" 即可用
```

### 参数化标签

```go
// jump(开始,结束,跳步)：按跳步掩码指定区间
type Model struct {
    Code string `desensitize:"jump(3,-4,1)"`
}

// 注册自己的参数化工厂
desensitize.RegisterDesensitizerFactory("mine", func(params ...int) desensitize.Desensitizer {
    return myDesensitizer{n: params[0]}
})
```

> 💡 注册会令已缓存的类型计划作废并在下次使用时重建，因此「先脱敏、再注册」同样生效

## 🏗️ 项目结构

```
go-desensitize/
├── doc.go            # 包文档：三条入口的分工与取舍，以及为什么 Model 不用启发式
├── adapter.go        # 脱敏器注册表（写时拷贝 + atomic.Pointer）、类型计划缓存、结构体遍历
├── desensitize.go    # 21 种脱敏类型的具体算法（手机号/身份证/银行卡/邮箱/IP/PEM/各类 ID）
├── constants.go      # DesensitizeType 枚举
├── model.go          # DesensitizeOptions 各类可见长度参数
├── keyrules.go       # 字段名规则表、形状位图、后缀字典树、掩码追加器（两档强度）
├── masker.go         # 报文脱敏器：JSON 与文本双路径的整段重写，无锁
├── cipher.go         # 可还原加密脱敏：AES-GCM、版本标识、全局密钥装配
├── strutil.go        # 内部零依赖字符串辅助（含上游遗留的字节/字符索引行为）
├── *_test.go         # 一源一测，100% 语句覆盖
├── bench_test.go     # 常驻基准：tag 驱动 / 单值 / 报文 / 组件四层，含并发对照
└── tools/decrypt.html # 离线解密调试台：解 enc:v1: 密文、反向核对指纹，不出网不存密钥
```

## 🧰 模块一览

| 模块 | 文件 | 功能描述 |
|------|------|----------|
| 📘 包文档 | [doc.go](doc.go) | 三条入口的分工与取舍 |
| 🏷️ tag 驱动 | [adapter.go](adapter.go) | 脱敏器注册表、类型计划缓存、结构体遍历 |
| 🎯 类型脱敏 | [desensitize.go](desensitize.go) | 21 种脱敏类型的具体算法 |
| 🔎 字段名规则 | [keyrules.go](keyrules.go) | 规则表、形状位图、后缀字典树、掩码追加器 |
| 📦 报文脱敏 | [masker.go](masker.go) | JSON 与文本双路径的整段重写 |
| 🔐 可还原加密 | [cipher.go](cipher.go) | AES-GCM 加解密与全局装配 |
| ⚙️ 选项 | [model.go](model.go) | `DesensitizeOptions` 各类长度参数 |
| 🔢 类型常量 | [constants.go](constants.go) | `DesensitizeType` 枚举 |
| 🔧 字符串工具 | [strutil.go](strutil.go) | 内部零依赖字符串辅助 |

每个不显然的取舍都写在它影响的那个文件里，而不是另立文档：为什么 Model 不走启发式在 `doc.go`，为什么没有默认密钥在 `SetDefaultCipher` 上，日志与报文为何需要两档强度在 `keyrules.go` 文件头，上游遗留的字节/字符索引混用在 `hide` 与 `padMiddle` 上

## 📋 API 速览

### 结构体与单值

| 函数 | 说明 |
| --- | --- |
| `Desensitization(obj) error` | 按 tag 对结构体原地脱敏，支持嵌套、切片、数组、映射 |
| `Desensitize(s, typ, opts...) string` | 按脱敏类型处理单个字符串 |
| `OperateByRule(tag, v) (any, error)` | 按 tag 名处理单个值，支持 `jump(3,-4,1)` 这类带参数标签 |
| `RegisterDesensitizer(name, d)` | 注册自定义脱敏器，令已缓存的类型计划失效重建 |
| `RegisterDesensitizerFactory(name, f)` | 注册参数化脱敏器工厂 |

### 字段名判定

| 函数 | 说明 |
| --- | --- |
| `ActionForKey(key) KeyAction` | 严格档：精确 + 后缀匹配，带运维豁免，零分配 |
| `ActionForKeyLoose(key) KeyAction` | 宽松档：再加字段名内部词根，零分配 |
| `IsCredentialKey(key) bool` | 是否为需整体擦除的凭据 |
| `RegisterSensitiveKeys(keys...)` | 追加自定义敏感字段名，全进程生效 |
| `OverrideKeyAction(key, action)` | 覆盖某字段名的判定，用于把会话类字段调成指纹或加密 |
| `AppendFingerprint(buf, s) []byte` | 指纹掩码追加器，稳定不可逆，零分配 |
| `FingerprintString(s) string` | 指纹掩码的字符串形态 |
| `AppendMaskedPhone(buf, s) []byte` | 号码掩码追加器，写入既有缓冲时零分配 |
| `AppendMaskedEmail(buf, s) []byte` | 邮箱掩码追加器，同上 |

### 报文与加密

| 函数 | 说明 |
| --- | --- |
| `NewMasker(cfg...) *DataMasker` | 创建报文脱敏器，无锁可并发复用 |
| `(*DataMasker).Mask(body) string` | 整段脱敏，JSON 走结构化、其余走单趟文本扫描 |
| `SetDefaultCipher(key) error` | 启动阶段装配全局密钥，之后 `desensitize:"cipher"` 直接可用 |
| `(*Cipher).Encrypt / Decrypt` | 带标识的加解密，密文被改动即报错 |
| `(*Cipher).EncryptDeterministic(s) string` | 确定性加密，同一明文恒产出同一密文，可跨行关联 |
| `(*Cipher).EncryptStruct / DecryptStruct` | 结构体整体加解密，解密只认标识不需清单 |
| `IsEncrypted(v) bool` | 是否带本库的加密标识，无需密钥 |

## 📊 性能

本次从 go-toolbox 提取时做了一轮优化，A/B 对照（`-count=3 -cpu=10 -benchtime=1s`，Apple M4，跑动区间均 <5%）：

| 基准 | 提取时 | 优化后 | 变化 |
|------|-------:|-------:|-----:|
| `Desensitization_Mixed`（10 字段 3 tag） | 1203 ns / 24 allocs | **242 ns / 3 allocs** | **−79.9%** |
| `Desensitization_AllTagged` | 1394 ns / 18 allocs | **547 ns / 7 allocs** | −60.8% |
| `Desensitization_Untagged` | 434 ns / 17 allocs | **9.2 ns / 0 allocs** | **−97.9%** |
| `Desensitization_Mixed_Parallel` | 2130 ns / 24 allocs | **53.9 ns / 3 allocs** | **−97.5%** |
| `Desensitization_Untagged_Parallel` | 1119 ns / 17 allocs | **1.77 ns / 0 allocs** | **−99.8%** |
| `OperateByRule_Plain_Parallel` | 279 ns | **32.2 ns** | −88.5% |
| `parseParameterizedTag_Miss` | 64.4 ns | **2.15 ns** | −96.7% |

提升的来源：

1. **注册表从独占锁换成写时拷贝 + `atomic.Pointer`** —— 原实现每个字段取一次**写锁**，并发脱敏完全串行化，改前并发（2130 ns）比顺序（1203 ns）还慢
2. **按类型缓存处理计划** —— tag 解析、脱敏器绑定、字段偏移每类型只算一次；注册表代数变化时自动重建，不影响「先用后注册」
3. **手写标签扫描替掉正则** —— 原实现每字段每次都跑一遍 `FindStringSubmatch`，普通标签也要先白跑一次
4. **无 tag 字段提前出局** —— 原实现对无 tag 字段也走完整条路并分配一个 error

自测：

```bash
go test -run='^$' -bench='.' -benchmem -benchtime=1s -count=3 -cpu=10 .
```

## 🧪 测试

```bash
# 单元测试
go test ./...

# 竞态检测
go test -race ./...

# 覆盖率（应为 100.0%）
go test -coverprofile=coverage.txt . && go tool cover -func=coverage.txt | tail -1
```

覆盖率里包含几处理论上不可达的防御分支（`json.Marshal` 失败、`aes.NewCipher` 失败等），均以可注入的函数变量留出缝隙，让其行为被测试闸住——而不是靠删掉错误检查来凑数字

## 📦 迁移出处

本库由两处代码合并而成：

| 来源 | 内容 | 对应文件 |
|------|------|----------|
| `[go-toolbox](https://github.com/kamalyes/go-toolbox) **v0.17.0** 的 `pkg/desensitize`` | 按 tag 与按类型的脱敏、报文脱敏器 | `adapter.go`、`desensitize.go`、`masker.go`、`model.go`、`constants.go` |
| [go-logger](https://github.com/kamalyes/go-logger) 的 `sanitize.go` | 按字段名的规则表与判定（不依赖 Logger 的纯逻辑部分） | `keyrules.go` |

`pkg/desensitize` 自 go-toolbox v0.17.0 起未再变动（最后一次功能改动 `4d1f203`，2025-09-07）

提取后：

- go-toolbox 的 `go-argus` 依赖与 go-logger 的规则副本都不再需要，200 余条安全规则只有一处来源
- 移植正确性以差分验证：对照上游实现跑 **14,564 组输入**，不一致 6 处且全部为「原实现崩进程 → 现在返回明确错误或正常工作」，无一处静默改变数据
- go-logger 改为引用本库，`sanitize.go` 从 692 行降到 240 行，依赖闭包只增加本库一个包

### 从 go-toolbox 迁移

```go
// 旧
import "github.com/kamalyes/go-toolbox/pkg/desensitize"

// 新
import "github.com/kamalyes/go-desensitize"
```

包名与绝大多数 API 签名不变，调用点无需改动三处行为变化：

| 变化 | 原实现 | 现在 |
|------|--------|------|
| tag 与字段类型不匹配 | panic | `返回 `*TagMisuseError`` |
| 命名字符串类型（`type Name string`） | panic | 正常脱敏 |
| 非结构体指针入参 | panic | 返回 error |
| `*Struct` 与 `[]*Struct` 字段 | 静默跳过，嵌套数据从未被脱敏 | 与值类型结构体一致地递归下钻 |
| JSON 数组报文 | 静默退回正则文本脱敏 | 走结构化脱敏 |
| 文本路径输出 | `token: x` 压成 `token=***` | 保留原分隔符为 `token: ***` |
| `MaskerConfig.SensitiveKeys` | 整体替换清单 | 只追加，内置规则始终生效 |

## 📄 许可证

[MIT](LICENSE)
