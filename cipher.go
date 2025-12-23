/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-12-21 10:26:08
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-12-23 11:52:30
 * @FilePath: \go-desensitize\cipher.go
 * @Description: 可逆脱敏 - 加密后的值带标识，持密钥可还原
 *
 * 全部用标准库的 crypto/aes + crypto/cipher + crypto/rand，零第三方依赖
 * 不自己实现任何密码学原语，只组合标准库的构件
 *
 * 与不可逆脱敏的性质差别必须讲清楚：
 *   - Desensitize / Desensitization 是**单向**的，掩码掉的字符永久丢失
 *   - Cipher 是**加密**，任何持有密钥的人都能看到原文
 * 二者解决的是不同问题：前者让数据永久不可见，后者让数据对无密钥方不可见
 * 把 Cipher 当脱敏用时，密钥的保管强度就是数据的保护强度
 *
 * [EN] Built only from crypto/aes, crypto/cipher and crypto/rand; no primitive
 * is implemented here, only composed. Note the difference in kind: the masking
 * functions are one-way and lose the hidden characters forever, while Cipher is
 * encryption — anyone holding the key sees the plaintext. Used as a masking
 * tool, the protection is exactly as strong as the key custody
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package desensitize

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
)

// 加密值的标识前缀与版本
//
// 带标识的理由有三个：
//   - Decrypt 能自己判断该不该解，混有明文的字段不会被当成坏数据
//   - DecryptStruct 可以只认标识来还原，无需再维护一份「哪些字段加密过」的清单
//   - 带版本号，日后换算法或换参数时旧值仍能被正确识别与解开
//
// [EN] The marker lets Decrypt decide for itself, lets DecryptStruct recover
// fields without a separate registry of which ones were encrypted, and the
// version segment keeps old values readable across an algorithm change
const (
	cipherPrefix  = "enc:"
	cipherVersion = "v1"
	// cipherMarker 完整标识，形如 enc:v1:
	cipherMarker = cipherPrefix + cipherVersion + ":"
)

// 加解密相关错误
var (
	ErrCipherKeySize   = errors.New("desensitize: 密钥长度必须为 16、24 或 32 字节")
	ErrCipherNotSealed = errors.New("desensitize: 值不带加密标识")
	ErrCipherVersion   = errors.New("desensitize: 不支持的加密标识版本")
	ErrCipherCorrupt   = errors.New("desensitize: 密文损坏或密钥不匹配")

	// ErrCipherNotConfigured 未调用 SetDefaultCipher 就使用了全局可逆脱敏
	ErrCipherNotConfigured = errors.New("desensitize: 未装配全局密钥，请在启动阶段调用 SetDefaultCipher")
)

// ==== 全局可逆脱敏器 | Default cipher ====

// defaultCipher 全局可逆脱敏器，未装配时为 nil
var defaultCipher atomic.Pointer[Cipher]

// CipherTagName desensitize tag 里引用可逆脱敏的名字
const CipherTagName = "cipher"

// SetDefaultCipher 以密钥装配全局可逆脱敏器，应在启动阶段调用一次
//
// 装配后即可在 tag 里直接用，不必把 *Cipher 传遍每个调用点：
//
//	func main() {
//	    key, _ := base64.StdEncoding.DecodeString(os.Getenv("MASK_KEY"))
//	    if err := desensitize.SetDefaultCipher(key); err != nil { log.Fatal(err) }
//	}
//
//	type Order struct {
//	    Receiver string `desensitize:"cipher"`      // 加密，可还原
//	    Phone    string `desensitize:"mobilePhone"` // 掩码，不可还原
//	}
//
// # 为什么没有默认密钥
//
// 两种「默认」都比没有更危险，所以本库一个都不提供：
//
//   - 写死一个默认密钥等于没加密：拿到本库源码的人都能解开所有数据，
//     这是看起来像保护的安全剧场，比明文更坏——因为它会让人放松警惕
//   - 启动时随机生成会永久丢数据：进程重启就换一把钥匙，
//     上次加密写进数据库的值再也解不开，而且故障要到下次读取才暴露
//
// 密钥的保管强度就是数据的保护强度，这件事只能由调用方决定
//
// # 未装配时的行为
//
// 未装配而使用 cipher tag，字段会被**整体擦除**而不是留下明文
// 失败关闭是这里唯一安全的选择：忘记装配的后果应当是「看不到数据」，
// 而不是「以为加密了其实是明文」后者不报错、不可见，等到泄漏才发现
//
// [EN] Why there is no default key: a hard-coded one is security theatre that
// anyone holding this source can undo, and a per-process random one silently
// destroys data at the next restart. Key custody is the whole of the
// protection, so only the caller can decide it. Using the cipher tag without a
// configured key wipes the field rather than leaving plaintext — forgetting to
// configure must mean "no data visible", never "thought it was encrypted"
func SetDefaultCipher(key []byte) error {
	c, err := NewCipher(key)
	if err != nil {
		return err
	}
	defaultCipher.Store(c)
	// 注册到脱敏器表，使 desensitize:"cipher" 生效
	// RegisterDesensitizer 会递增注册表代数，已缓存的类型计划随之重建
	RegisterDesensitizer(CipherTagName, c)
	return nil
}

// DefaultCipher 返回全局可逆脱敏器，未装配时返回 nil
func DefaultCipher() *Cipher {
	return defaultCipher.Load()
}

// ClearDefaultCipher 卸载全局可逆脱敏器，之后 cipher tag 回到失败关闭
// 主要供测试复原全局状态
func ClearDefaultCipher() {
	defaultCipher.Store(nil)
	RegisterDesensitizer(CipherTagName, unconfiguredCipher{})
}

// EncryptStructDefault 用全局可逆脱敏器加密结构体字段
// 未装配时报错，而不是静默留下明文
func EncryptStructDefault(obj interface{}) error {
	c := DefaultCipher()
	if c == nil {
		return ErrCipherNotConfigured
	}
	return c.EncryptStruct(obj)
}

// DecryptStructDefault 用全局可逆脱敏器还原结构体字段
func DecryptStructDefault(obj interface{}) error {
	c := DefaultCipher()
	if c == nil {
		return ErrCipherNotConfigured
	}
	return c.DecryptStruct(obj)
}

// unconfiguredCipher 未装配密钥时占位的脱敏器，整体擦除
//
// 预先注册它而不是让 cipher tag 解析失败：解析失败会让字段被**跳过**，
// 也就是留下明文，那正是最不能出现的结果
// [EN] Pre-registered instead of letting the tag fail to resolve: an
// unresolved tag skips the field, leaving plaintext — the one outcome that
// must never happen
type unconfiguredCipher struct{}

func (unconfiguredCipher) Desensitize(string) string { return RedactedText }

// init 预注册失败关闭的占位脱敏器
func init() {
	RegisterDesensitizer(CipherTagName, unconfiguredCipher{})
}

// Cipher 可逆脱敏器，基于 AES-GCM
//
// AES-GCM 是带认证的加密：密文被改动一个字节，Decrypt 就会报错而不是返回错数据
// 这对脱敏场景很关键——无声地还原出错误原文比直接失败危险得多
//
// 每次加密取一个随机 nonce，因此同一明文每次加密结果都不同
// 这是有意的：确定性输出会泄漏「两个字段的值相等」，而相等关系本身常常就是信息
// 代价是密文不能用于比较与去重，需要这类能力时应当另存一份哈希
//
// [EN] AES-GCM is authenticated, so a single altered byte fails the Decrypt
// rather than yielding wrong plaintext — silently recovering the wrong value
// would be worse than failing. A fresh random nonce per encryption means the
// same plaintext encrypts differently every time, deliberately: deterministic
// output would leak equality between fields, which is itself information. The
// cost is that ciphertexts cannot be compared or deduplicated
type Cipher struct {
	aead cipher.AEAD
	// macKey 确定性模式派生 nonce 用的独立密钥，见 EncryptDeterministic
	macKey []byte
	// randRead 随机源，以字段形式存在以便测试注入失败
	randRead func([]byte) (int, error)
}

// NewCipher 以密钥创建可逆脱敏器
// key 长度须为 16、24 或 32 字节，分别对应 AES-128、AES-192、AES-256
//
// 密钥由调用方保管：本库不生成也不持久化密钥
// 丢失密钥等于数据永久不可还原，这是加密的固有性质而非缺陷
func NewCipher(key []byte) (*Cipher, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, ErrCipherKeySize
	}

	block, err := newBlockCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(block)
	if err != nil {
		return nil, err
	}
	// 确定性模式的 nonce 由 HMAC 派生，其密钥必须与加密密钥分开
	// 同一把密钥既做加密又做 MAC 是跨原语复用，属于应当避免的用法
	// 这里用带标签的 HMAC 派生一把独立子密钥，标签含版本以便日后更换构造
	// [EN] The deterministic nonce is HMAC-derived, and that HMAC key must be
	// separate from the encryption key: using one key across two primitives is
	// the kind of reuse to avoid. A labelled HMAC derives an independent
	// subkey, with the label versioned so the construction can change later
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("go-desensitize/siv/v1"))

	return &Cipher{
		aead:     aead,
		macKey:   mac.Sum(nil),
		randRead: func(b []byte) (int, error) { return io.ReadFull(rand.Reader, b) },
	}, nil
}

// 分组密码与 AEAD 的构造入口，以变量形式存在以便测试替换
//
// 两者在当前用法下都不会失败：aes.NewCipher 只因密钥长度非法报错而长度已在
// 上面挡掉，cipher.NewGCM 只因分组长度不是 16 报错而 AES 恒为 16
// 但失败分支的行为仍需被闸住——日后若换成分组长度不同的算法，
// 正确结果是构造报错，而不是带着半初始化的 Cipher 继续跑
//
// [EN] Both constructors are behind variables so tests can force their failure
// branches. Neither can fail as used: the key length is already validated and
// AES always has a 16-byte block. The branches still matter, because swapping
// in a cipher with a different block size must fail construction rather than
// yield a half-initialised Cipher
var (
	newBlockCipher = aes.NewCipher
	newAEAD        = cipher.NewGCM
)

// Encrypt 加密明文，返回带标识的值，形如 enc:v1:<base64url>
// 空串原样返回：对空值加密只会产生一串看不懂的东西，没有意义
func (c *Cipher) Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := c.randRead(nonce); err != nil {
		return "", err
	}

	// nonce 前置在密文之前，Decrypt 据此切分
	sealed := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return cipherMarker + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// EncryptDeterministic 确定性加密：同一明文恒产出同一密文
//
// 解决「既要跨行关联、又要出事能定位身份」这对需求：
// 随机 nonce 的 Encrypt 让同一 session_id 每次密文都不同，身份能还原但关联断了；
// 这里把 nonce 由明文确定性派生（SIV 构造），于是同一会话在所有日志行里
// 都是同一串密文，既能串起来，持密钥的人又能解出到底是哪个会话
//
// nonce = HMAC-SHA256(独立派生的子密钥, 明文) 截断到 GCM 的 nonce 长度
// 确定性意味着**必然**泄漏「两个字段的值相等」，这正是可关联的前提；
// 若连相等关系都不能暴露，请用 Encrypt 或整体擦除
//
// 密文格式与 Encrypt 完全一致，因此 Decrypt 不需要区分两者
//
// [EN] Resolves the tension between correlating across log lines and being
// able to identify the session during an incident: the random-nonce Encrypt
// yields a different ciphertext every time, so identity survives but
// correlation does not. Here the nonce is derived from the plaintext (an SIV
// construction), so one session is one ciphertext everywhere while a key holder
// can still resolve it. Determinism necessarily reveals that two values are
// equal — the very property that makes it correlatable; use Encrypt or wiping
// when even that must not leak. The output format matches Encrypt, so Decrypt
// needs no distinction
// 不返回 error：nonce 由明文经 HMAC 派生，不消耗随机数，
// 因此与 Encrypt 不同，这条路没有任何可失败的环节
// 给它配一个永远为 nil 的 error 只会让调用方写出永不执行的分支
// [EN] No error return: the nonce is HMAC-derived from the plaintext and
// consumes no randomness, so unlike Encrypt nothing here can fail. An error
// that is always nil would only make callers write a branch that never runs
func (c *Cipher) EncryptDeterministic(plain string) string {
	if plain == "" {
		return ""
	}

	mac := hmac.New(sha256.New, c.macKey)
	mac.Write([]byte(plain))
	nonce := mac.Sum(nil)[:c.aead.NonceSize()]

	sealed := c.aead.Seal(nonce[:len(nonce):len(nonce)], nonce, []byte(plain), nil)
	return cipherMarker + base64.RawURLEncoding.EncodeToString(sealed)
}

// MustEncrypt 加密明文，失败时回落为整体擦除
//
// 供不便处理错误的调用点使用（如实现 Desensitizer 接口）
// 失败时返回 RedactedText 而非原文：加密不可用时宁可什么都看不到，
// 也不能把明文漏出去——这是必须失败关闭的地方
func (c *Cipher) MustEncrypt(plain string) string {
	out, err := c.Encrypt(plain)
	if err != nil {
		return RedactedText
	}
	return out
}

// Decrypt 还原带标识的值
// 不带标识的值原样返回并报 ErrCipherNotSealed，便于调用方区分「本来就是明文」
func (c *Cipher) Decrypt(value string) (string, error) {
	if !strings.HasPrefix(value, cipherPrefix) {
		return value, ErrCipherNotSealed
	}

	rest := value[len(cipherPrefix):]
	sep := strings.IndexByte(rest, ':')
	if sep < 0 {
		return value, ErrCipherNotSealed
	}
	if rest[:sep] != cipherVersion {
		return value, ErrCipherVersion
	}

	sealed, err := base64.RawURLEncoding.DecodeString(rest[sep+1:])
	if err != nil {
		return value, ErrCipherCorrupt
	}
	nonceSize := c.aead.NonceSize()
	if len(sealed) < nonceSize {
		return value, ErrCipherCorrupt
	}

	plain, err := c.aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], nil)
	if err != nil {
		// GCM 的认证失败，密文被改动或密钥不对，不区分二者以免成为预言机
		return value, ErrCipherCorrupt
	}
	return string(plain), nil
}

// IsEncrypted 报告值是否带本库的加密标识
// 只看标识，不验证密文完整性，故不需要密钥
func IsEncrypted(value string) bool {
	if !strings.HasPrefix(value, cipherPrefix) {
		return false
	}
	rest := value[len(cipherPrefix):]
	sep := strings.IndexByte(rest, ':')
	return sep > 0
}

// Desensitize 实现 Desensitizer 接口，使 Cipher 可注册为脱敏器
//
// 注册后即可在 tag 里使用：
//
//	c, _ := desensitize.NewCipher(key)
//	desensitize.RegisterDesensitizer("cipher", c)
//
//	type Order struct {
//	    Receiver string `desensitize:"cipher"` // 加密，可还原
//	    Phone    string `desensitize:"mobilePhone"` // 掩码，不可还原
//	}
func (c *Cipher) Desensitize(value string) string {
	return c.MustEncrypt(value)
}

// ==== 结构体整体加解密 | Whole-struct round trip ====

// EncryptStruct 按 tag 加密结构体字段
// 等价于注册 cipher 脱敏器后调用 Desensitization，这里只是省掉注册步骤
//
// obj 须为指向结构体的非 nil 指针
func (c *Cipher) EncryptStruct(obj interface{}) error {
	return c.walkStrings(obj, func(s string) (string, bool) {
		if s == "" || IsEncrypted(s) {
			return s, false // 空值与已加密的值不重复加密
		}
		out, err := c.Encrypt(s)
		if err != nil {
			return s, false
		}
		return out, true
	})
}

// DecryptStruct 还原结构体中所有带加密标识的字符串字段
//
// 只认标识，不需要「哪些字段加密过」的清单——这正是加密值带标识的用处
// 混在同一结构体里的明文字段不会被动，解不开的值也原样保留，
// 这样一次失败不会把整个对象变成不可读
func (c *Cipher) DecryptStruct(obj interface{}) error {
	return c.walkStrings(obj, func(s string) (string, bool) {
		if !IsEncrypted(s) {
			return s, false
		}
		out, err := c.Decrypt(s)
		if err != nil {
			return s, false
		}
		return out, true
	})
}

// walkStrings 遍历结构体里可设置的字符串字段并逐个变换
//
// 覆盖的形态与 Desensitization 一致：字符串字段、字符串切片与数组、
// 字符串值的映射，以及嵌套结构体与结构体切片
// 判定按 reflect.Kind，故命名字符串类型（type Name string）同样适用
func (c *Cipher) walkStrings(obj interface{}, transform func(string) (string, bool)) error {
	value := reflect.ValueOf(obj)
	if value.Kind() != reflect.Ptr || value.IsNil() {
		return errors.New("expected a non-nil pointer to a struct")
	}
	elem := value.Elem()
	if elem.Kind() != reflect.Struct {
		return errors.New("expected a non-nil pointer to a struct")
	}
	walkStringFields(elem, transform)
	return nil
}

// walkStringFields 递归遍历结构体里可设置的字符串字段并逐个变换
func walkStringFields(sv reflect.Value, transform func(string) (string, bool)) {
	t := sv.Type()
	for i := 0; i < t.NumField(); i++ {
		if !t.Field(i).IsExported() {
			continue
		}
		applyStringTransform(sv.Field(i), transform)
	}
}

// applyStringTransform 对单个值施加变换，按 Kind 分派
func applyStringTransform(fv reflect.Value, transform func(string) (string, bool)) {
	switch fv.Kind() {
	case reflect.String:
		if out, changed := transform(fv.String()); changed {
			fv.SetString(out)
		}
	case reflect.Struct:
		walkStringFields(fv, transform)
	case reflect.Ptr:
		if !fv.IsNil() {
			applyStringTransform(fv.Elem(), transform)
		}
	case reflect.Slice, reflect.Array:
		for j := 0; j < fv.Len(); j++ {
			applyStringTransform(fv.Index(j), transform)
		}
	case reflect.Map:
		// 映射元素不可直接寻址，需取出、变换、再写回
		if fv.Type().Elem().Kind() != reflect.String {
			return
		}
		for _, key := range fv.MapKeys() {
			if out, changed := transform(fv.MapIndex(key).String()); changed {
				masked := reflect.New(fv.Type().Elem()).Elem()
				masked.SetString(out)
				fv.SetMapIndex(key, masked)
			}
		}
	}
}
