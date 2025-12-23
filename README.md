# Go Desensitize - zero-dependency data masking for Go

> `go-desensitize` splits hiding sensitive data into three paths that do not interfere: **per-field declaration via struct tags**, **field-name heuristics**, and **whole-payload rewriting** — plus reversible, key-recoverable encryption masking
> No third-party dependencies, 100% statement coverage; per-type cached plans and a copy-on-write registry keep the hot path lock-free and allocation-free in most shapes

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

**English** · [中文](README_ZH.md)

## ✨ Features

- 🪶 **Zero third-party dependencies** - a consumer compiles no third-party package; `testify` is test-only and never enters anyone's build graph
- 🧪 **100% statement coverage** - including defensive branches that cannot be reached in practice, each pinned through an injectable seam
- 🏷️ **Struct-tag driven** - `desensitize:"mobilePhone"` declares intent per field, the most accurate option when you own the schema
- 🔎 **Field-name heuristics** - for when you do not own the schema; 200-odd rules at two strengths
- 📦 **Whole-payload masking** - rewrites request and response bodies by field name, with separate JSON and text paths
- 🔐 **Reversible masking** - AES-GCM authenticated encryption, version-marked ciphertext, recoverable with the key
- ⚡ **Per-type cached plans** - tag parsing and desensitizer binding happen once per type; the read path is lock-free
- 🎯 **21 built-in masking types** - phone, ID card, bank card, email, IP, PEM key, assorted identifiers
- 🧩 **Extensible** - custom desensitizers and parameterised factories; tags such as `jump(3,-4,1)` work out of the box
- 🛡️ **Fails closed** - when encryption is unavailable the field is wiped, never left as plaintext

## ⚠️ Defaults worth knowing

These defaults change production behaviour directly, so read them before wiring the library in:

| Default | Behaviour | What to watch for |
| --- | --- | --- |
| **`cipher` tag without a key = wiped** | the field becomes `[REDACTED]` | forgetting `SetDefaultCipher` means **no data visible**, never plaintext leaking; the fail-closed choice is deliberate |
| **No default key is provided** | `SetDefaultCipher` requires a caller-supplied key | a hard-coded key is no encryption at all, a random one loses data on restart; both are worse than none |
| Encryption output differs every time | random nonce, same plaintext encrypts differently | ciphertext **cannot** be compared or deduplicated; keep a separate hash if you need that |
| **`MaskerConfig.SensitiveKeys` is additive** | built-in rules always apply | configuration cannot make `password` non-sensitive — the security baseline must not narrow by accident |
| Payload cap = 10KB | truncate first, then mask | a truncated body is usually no longer valid JSON and falls to the text path; raise it with `WithMaxBodySize(n)` |
| Field-name decisions = two strengths | strict for logs, loose for payloads | the wrong one both over-masks and under-masks; see the table below |
| **Sessions and tokens are wiped by default** | `session_id`, `token`, `cookie` and `authorization` are not visible | they are replayable credentials; when you need correlation or incident identification, move them to fingerprint or encryption with `OverrideKeyAction` rather than to plaintext |
| **Models skip the heuristics** | only `desensitize` tags are honoured | the rule table is tuned for logs, and choices like `name` or `status_code` are wrong for a model |
| Masking is one-way | the `Desensitize` family discards hidden characters | use the `cipher` tag for fields you must recover; a mask cannot be undone |
| **`BankCard` is not idempotent** | each pass inserts grouping spaces and re-pads, so it grows | the only one of the twelve types that is not; masking once in middleware and again in a repository produces ever longer garbage, so make sure it happens once |
| Go version = 1.20 | no 1.21+ symbol is used | a dependency-free library deliberately holds the language version low so older toolchains can consume it |

## 🚀 Quick start

### Install

```bash
go get github.com/kamalyes/go-desensitize
```

The language version is held at `go 1.20`: with no dependencies and no 1.21+ builtin or stdlib symbol in use, the library accepts as old a toolchain as possible

### Struct-tag driven (recommended)

A realistic order model: several levels of nesting, a struct pointer, a pointer slice, a map, and seven tags in play

```go
import "github.com/kamalyes/go-desensitize"

type Contact struct {
    RealName string `desensitize:"name"`
    Phone    string `desensitize:"mobilePhone"`
    Email    string `desensitize:"email"`
}

type Address struct {
    Contact Contact        // nested struct, descended into automatically
    Detail  string `desensitize:"address"`
    Zip     string         // no tag, left as is
}

type Item struct {
    SKU   string
    Price int64
}

type Order struct {
    OrderNo  string            `desensitize:"orderNo"`
    Buyer    Contact
    Shipping *Address          // struct pointer, descended into; nil-safe
    Items    []*Item           // pointer slice, element by element
    CardNo   string            `desensitize:"bankCard"`
    IDCardNo string            `desensitize:"identityCard"`
    Audit    map[string]string `desensitize:"secret"`
    Total    int64             // non-string fields untouched
    Status   string
}

if err := desensitize.Desensitization(&order); err != nil {
    log.Fatal(err)
}
```

After masking:

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

Note that `Zip`, `SKU`, `Price`, `Total` and `Status` carry no tag and survive untouched; `Shipping` is a pointer and is still descended into; `Items` is a pointer slice handled element by element; `Audit` is a map handled value by value

### Single values

```go
desensitize.Desensitize("18175698789", desensitize.MobilePhone) // 181****8789
desensitize.Desensitize("310101199001015678", desensitize.IDCard) // 310101********5678
desensitize.Desensitize("192.168.1.1", desensitize.IPV4)        // 192.*.*.*
desensitize.Desensitize("sk-abcdefghijklmnopqrstuvwxyz", desensitize.Secret) // sk-a*********************wxyz
```

### Reversible masking

```go
// Configure once at startup, then the tag just works
key, _ := base64.StdEncoding.DecodeString(os.Getenv("MASK_KEY")) // 16 / 24 / 32 bytes
if err := desensitize.SetDefaultCipher(key); err != nil {
    log.Fatal(err)
}

type Order struct {
    Receiver string `desensitize:"cipher"`      // encrypted, recoverable
    Phone    string `desensitize:"mobilePhone"` // masked, one-way
}

order := Order{Receiver: "张三丰", Phone: "18175698789"}
_ = desensitize.Desensitization(&order)
// Receiver → enc:v1:4_23fCUS6PeK-EgNPafx...
// Phone    → 181****8789

plain, err := desensitize.DefaultCipher().Decrypt(order.Receiver) // "张三丰"
```

> ⚠️ **There is no default key**, because both kinds of default are worse than none: a hard-coded key is security theatre that anyone holding this source can undo, and a per-process random key silently destroys data at the next restart
> Using the `cipher` tag without a configured key **wipes** the field rather than leaving plaintext — forgetting to configure must mean "no data visible", never "thought it was encrypted"

### Sessions and tokens: correlation, identification, exposure

`session_id`, `token`, `cookie` and `authorization` are **wiped** by default, deliberately:
they are replayable credentials, and logs are centrally collected, widely read and retained
for months, so anyone who can read them can impersonate the user until expiry, without a trace

Two operational needs pull the other way: **following one login's requests across log lines**,
and **identifying who it actually was** during an incident. Two middle options cover them,
selected per field with `OverrideKeyAction`:

| Approach | Correlate | Identify in an incident | Needs a key | Exposure |
|------|:--------:|:------------:|:--------:|----------|
| `KeepAsIs` (plaintext) | ✅ | ✅ | no | **replayable credential** |
| `WipeValue` (default) | ❌ | ❌ | no | none |
| `MaskFingerprint` | ✅ | ❌ | no | reveals only that two values are equal |
| `MaskEncrypt` | ✅ | ✅ | yes | reveals only that two values are equal |

```go
// Just follow one session's requests; no key needed
desensitize.OverrideKeyAction("session_id", desensitize.MaskFingerprint)
// {"session_id":"***6a9f3e7a","trace_id":"t-xyz","user_id":"u-1001"}
// Every line of that session reads ***6a9f3e7a, yet it cannot be inverted or replayed

// Also be able to resolve which session it was during a review
desensitize.SetDefaultCipher(key)
desensitize.OverrideKeyAction("session_id", desensitize.MaskEncrypt)
// {"session_id":"enc:v1:lFDr0e-L0k777_lQwKkRY8DPwvQek601DxXD10...","trace_id":"t-xyz"}

plain, _ := desensitize.DefaultCipher().Decrypt(sealed) // "sess-abc123def456"
```

`MaskEncrypt` uses **deterministic** encryption (the nonce is HMAC-derived from the plaintext,
an SIV construction), so one session is one ciphertext on every line. With a random nonce the
identity would still be recoverable but the correlation would be gone

Three things to know:

- Both strengths necessarily reveal that two values are equal, which is exactly what makes them
  correlatable; use `WipeValue` when even that must not leak
- With no key configured, `MaskEncrypt` **wipes** the field rather than passing it through: you
  asked for recoverable, not visible, and a misconfiguration must not leak silently
- Often none of this is needed - `user_id`, `trace_id`, `request_id`, `span_id` and `device_id`
  are visible by default, and following a user's request chain works with those alone

### Payload masking

```go
masker := desensitize.NewMasker()
```

**Nested JSON** - credentials wiped, contact details keep a tail, diagnostic fields all survive:

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

`id`, `amount`, `requestId` and the whole `trace` object survive: a log with its diagnostic trail erased is no log at all

**HTTP headers** - the value runs to end of line, so it cannot mask only `Bearer` and leave the token behind:

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

**Forms and query strings** - the value stops at `&` or whitespace, leaving neighbouring pairs intact:

```go
masker.Mask([]byte("GET /api?user=bob&token=abc123 HTTP/1.1"))
// GET /api?user=bob&token=*** HTTP/1.1

masker.Mask([]byte("ts=2025-12-23 token=abc123 user=bob level=info"))
// ts=2025-12-23 token=*** user=bob level=info
```

> ⚠️ When a field name itself matches, the **whole container** is wiped to a single string rather than descended into: an object called `credentials` disappears entirely, taking any `publicKey` inside it along. Do not name a container after a sensitive root

### Field-name heuristics

When the schema is not yours (log key-value pairs, arbitrary JSON from upstream), guess from the field name, at two strengths:

```go
// Strict: exact plus suffix matching, with ops-visibility exemptions. For logs
desensitize.ActionForKey("user_password")  // WipeValue
desensitize.ActionForKey("cache_key")      // KeepAsIs (ops field exempted)
desensitize.ActionForKey("my_token_field") // KeepAsIs (root not in suffix position)

// Loose: also scans roots embedded inside the name. For payloads
desensitize.ActionForKeyLoose("my_token_field") // WipeValue
desensitize.ActionForKeyLoose("cache_key")      // KeepAsIs (exemption still applies)

// Allocation-free mask appenders
buf = desensitize.AppendMaskedPhone(buf, "+86 138-0013-8000") // ***8000
buf = desensitize.AppendMaskedEmail(buf, "a@example.com")     // a***@example.com
```

## 🏗️ Three entry points, three jobs

These paths do not solve the same problem and they trade off in different directions; picking the wrong one both over-masks and under-masks:

| Entry point | Decided by | Use for | Trade-off |
|------|----------|----------|------|
| `Desensitization(obj)` | struct tags, declared per field | your own models | most accurate, no guessing |
| `ActionForKey(key)` | strict field-name match | log key-value pairs | conservative, prefers a miss |
| `ActionForKeyLoose(key)` | field name plus embedded roots | payloads and bodies | aggressive, prefers a false positive |
| `DataMasker.Mask(body)` | as above, whole-payload rewrite | request and response bodies | aggressive |

### Why models do not use the field-name heuristics

The rule table is tuned for **logs**, and its trade-offs are wrong for a model:

- `name` is not in the table: in general logs, `service_name`, `table_name` and `file_name` vastly outnumber people's names
- `status_code`, `cache_key` and `trace_id` are exempted: they are the operator's main diagnostic trail, and wiping them robs the log of its value

In a model, however, a `Name` field usually is a person's name and `Address` usually is a shipping address
So the model path **never touches the rule table** and honours only the tags you wrote — when you own the schema, declaring beats guessing every time

## 📋 Built-in masking types

| Type | Description | Example input | Example output |
|------|------|----------|----------|
| `ChineseName` | Chinese name | 张三丰 | `张**` |
| `IDCard` | national ID | 310101199001015678 | `310101********5678` |
| `PhoneNumber` | phone number | 18175698789 | `181****8789` |
| `MobilePhone` | mobile number | 18175698789 | `181****8789` |
| `Address` | address | 北京市朝阳区某某路99号 | `北京市朝*****99号` |
| `Email` | email | zhangsanfeng@example.com | `z*********ng@example.com` |
| `Password` | password | hunter2 | `h******` |
| `CarLicense` | licence plate | 京A12345 | `京A1**45` |
| `BankCard` | bank card | 6222025678565678 | `6222 **** **** **** 5678` |
| `IPV4` / `IPV6` | IP address | 192.168.1.1 | `192.*.*.*` |
| `PEMKey` | PEM key | -----BEGIN ... | header and footer kept, body masked |
| `APIKey` / `Secret` | secret | sk-abcdefghijklmnopqrstuvwxyz | `sk-a*********************wxyz` |
| `UserID` / `PlayerID` / `OrderNo` / `UUID` / `OpenID` / `Account` | identifiers | 1234567890 | `12******90` |
| `CustomExtension` | custom | controlled by `DesensitizeOptions` | - |

### Custom desensitizers

```go
type upperDesensitizer struct{}

func (upperDesensitizer) Desensitize(v string) string { return strings.ToUpper(v) }

desensitize.RegisterDesensitizer("upper", upperDesensitizer{})
// desensitize:"upper" is now available
```

### Parameterised tags

```go
// jump(start,end,step): mask the given range at the given stride
type Model struct {
    Code string `desensitize:"jump(3,-4,1)"`
}

// Register your own parameterised factory
desensitize.RegisterDesensitizerFactory("mine", func(params ...int) desensitize.Desensitizer {
    return myDesensitizer{n: params[0]}
})
```

> 💡 Registering invalidates cached per-type plans, which are rebuilt on next use, so "mask first, register later" still takes effect

## 🏗️ Project layout

```
go-desensitize/
├── doc.go            # package docs: the three entry points, and why models skip the heuristics
├── adapter.go        # desensitizer registry (copy-on-write + atomic.Pointer), plan cache, struct walk
├── desensitize.go    # the algorithms behind 21 masking types (phone/ID/card/email/IP/PEM/identifiers)
├── constants.go      # the DesensitizeType enumeration
├── model.go          # visible-length parameters in DesensitizeOptions
├── keyrules.go       # field-name tables, shape bitmap, suffix trie, mask appenders (two strengths)
├── masker.go         # payload masker: whole-body rewrite over JSON and text paths, lock-free
├── cipher.go         # reversible masking: AES-GCM, version marker, global key configuration
├── strutil.go        # internal dependency-free string helpers (including upstream index quirks)
├── *_test.go         # one test file per source file, 100% statement coverage
└── bench_test.go     # permanent benchmarks across four layers, with parallel counterparts
```

## 🧰 Module map

| Module | File | Description |
|------|------|----------|
| 📘 package docs | [doc.go](doc.go) | the three entry points and their trade-offs |
| 🏷️ tag driven | [adapter.go](adapter.go) | desensitizer registry, per-type plan cache, struct walk |
| 🎯 type masking | [desensitize.go](desensitize.go) | the algorithms behind the 21 masking types |
| 🔎 field-name rules | [keyrules.go](keyrules.go) | rule tables, shape bitmap, suffix trie, mask appenders |
| 📦 payload masking | [masker.go](masker.go) | whole-payload rewrite over JSON and text paths |
| 🔐 reversible masking | [cipher.go](cipher.go) | AES-GCM encryption and global configuration |
| ⚙️ options | [model.go](model.go) | the length parameters in `DesensitizeOptions` |
| 🔢 type constants | [constants.go](constants.go) | the `DesensitizeType` enumeration |
| 🔧 string helpers | [strutil.go](strutil.go) | internal dependency-free string utilities |

## 📋 API at a glance

### Structs and single values

| Function | Description |
| --- | --- |
| `Desensitization(obj) error` | mask a struct in place by tag; handles nesting, slices, arrays and maps |
| `Desensitize(s, typ, opts...) string` | mask one string by masking type |
| `OperateByRule(tag, v) (any, error)` | mask one value by tag name, including parameterised tags such as `jump(3,-4,1)` |
| `RegisterDesensitizer(name, d)` | register a custom desensitizer; invalidates cached per-type plans |
| `RegisterDesensitizerFactory(name, f)` | register a parameterised desensitizer factory |

### Field-name decisions

| Function | Description |
| --- | --- |
| `ActionForKey(key) KeyAction` | strict: exact plus suffix matching with ops exemptions, allocation-free |
| `ActionForKeyLoose(key) KeyAction` | loose: also scans roots embedded in the name, allocation-free |
| `IsCredentialKey(key) bool` | whether the name denotes a credential to wipe entirely |
| `RegisterSensitiveKeys(keys...)` | add custom sensitive field names, process-wide |
| `OverrideKeyAction(key, action)` | override one key's decision, e.g. moving session fields to fingerprint or encryption |
| `AppendFingerprint(buf, s) []byte` | fingerprint appender: stable, non-invertible, allocation-free |
| `FingerprintString(s) string` | the string form of the fingerprint mask |
| `AppendMaskedPhone(buf, s) []byte` | phone mask appender, allocation-free into an existing buffer |
| `AppendMaskedEmail(buf, s) []byte` | email mask appender, likewise |

### Payloads and encryption

| Function | Description |
| --- | --- |
| `NewMasker(cfg...) *DataMasker` | create a payload masker; lock-free and safe to share |
| `(*DataMasker).Mask(body) string` | mask a whole payload: structured for JSON, a single text pass otherwise |
| `SetDefaultCipher(key) error` | configure the global key at startup; `desensitize:"cipher"` then works |
| `(*Cipher).Encrypt / Decrypt` | marked encryption and decryption; an altered ciphertext fails rather than lies |
| `(*Cipher).EncryptDeterministic(s) string` | deterministic encryption: one plaintext is always one ciphertext, so it correlates |
| `(*Cipher).EncryptStruct / DecryptStruct` | whole-struct round trip; decryption needs only the marker, not a registry |
| `IsEncrypted(v) bool` | whether a value carries this library's marker, no key required |

## 📊 Performance

One optimisation pass accompanied the extraction from go-toolbox. A/B comparison (`-count=3 -cpu=10 -benchtime=1s`, Apple M4, run-to-run spread under 5% throughout):

| Benchmark | At extraction | After | Change |
|------|-------:|-------:|-----:|
| `Desensitization_Mixed` (10 fields, 3 tagged) | 1203 ns / 24 allocs | **242 ns / 3 allocs** | **−79.9%** |
| `Desensitization_AllTagged` | 1394 ns / 18 allocs | **547 ns / 7 allocs** | −60.8% |
| `Desensitization_Untagged` | 434 ns / 17 allocs | **9.2 ns / 0 allocs** | **−97.9%** |
| `Desensitization_Mixed_Parallel` | 2130 ns / 24 allocs | **53.9 ns / 3 allocs** | **−97.5%** |
| `Desensitization_Untagged_Parallel` | 1119 ns / 17 allocs | **1.77 ns / 0 allocs** | **−99.8%** |
| `OperateByRule_Plain_Parallel` | 279 ns | **32.2 ns** | −88.5% |
| `parseParameterizedTag_Miss` | 64.4 ns | **2.15 ns** | −96.7% |

Where the gains came from:

1. **The registry moved from an exclusive lock to copy-on-write behind `atomic.Pointer`** - the original took a **write** lock per field, serialising all concurrent masking; before the change the parallel case (2130 ns) was slower than the sequential one (1203 ns)
2. **Per-type cached plans** - tag parsing, desensitizer binding and field offsets are computed once per type, and rebuilt when the registry generation changes so that "use first, register later" still works
3. **A hand-written tag scanner replaced the regexp** - the original ran `FindStringSubmatch` per field per call, and a plain tag had to fail that match first
4. **Untagged fields bail out early** - the original walked the whole path for them and allocated an error

Measure for yourself:

```bash
go test -run='^$' -bench='.' -benchmem -benchtime=1s -count=3 -cpu=10 .
```

## 🧪 Testing

```bash
# Unit tests
go test ./...

# Race detector
go test -race ./...

# Coverage (expected: 100.0%)
go test -coverprofile=coverage.txt . && go tool cover -func=coverage.txt | tail -1
```

The coverage figure includes a few defensive branches that cannot be reached in practice (a failing `json.Marshal`, a failing `aes.NewCipher`). Each sits behind an injectable function variable so its behaviour is pinned by a test, rather than deleting the error check to make the number look good

## 📦 Provenance

This library merges code from two places:

| Source | Content | Files |
|------|------|----------|
| [go-toolbox](https://github.com/kamalyes/go-toolbox) **v0.17.0**, `pkg/desensitize` | tag-driven and type-driven masking, the payload masker | `adapter.go`, `desensitize.go`, `masker.go`, `model.go`, `constants.go` |
| [go-logger](https://github.com/kamalyes/go-logger), `sanitize.go` | the field-name rule tables and decision logic (the parts not depending on Logger) | `keyrules.go` |

`pkg/desensitize` had not changed since go-toolbox v0.17.0 (last functional change `4d1f203`, 2025-09-07)

After the extraction:

- go-toolbox's `go-argus` edge and go-logger's copy of the rules are both gone, leaving one source for the 200-odd security rules
- Port correctness was established by differential testing: **14,564 inputs** against the upstream implementation, with 6 divergences, every one of them "the original crashed the process → now returns a clear error or works correctly", and none silently changing data
- go-logger now depends on this library; its `sanitize.go` shrank from 692 to 240 lines and its dependency closure grew by exactly this one package

### Migrating from go-toolbox

```go
// Before
import "github.com/kamalyes/go-toolbox/pkg/desensitize"

// After
import "github.com/kamalyes/go-desensitize"
```

The package name and nearly all signatures are unchanged, so call sites do not move. Three behaviours differ:

| Change | Before | Now |
|------|--------|------|
| tag on a field whose type is not a string | panic | returns `*TagMisuseError` |
| named string type (`type Name string`) | panic | masked correctly |
| non-struct pointer argument | panic | returns an error |
| `*Struct` and `[]*Struct` fields | silently skipped, nested data never masked | recursed into like value structs |
| JSON array payloads | silently fell back to regex text masking | structured masking |
| text path output | `token: x` collapsed into `token=***` | separator preserved as `token: ***` |
| `MaskerConfig.SensitiveKeys` | replaced the whole list | additive only; built-in rules always apply |

## 📄 License

[MIT](LICENSE)
