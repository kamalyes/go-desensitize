/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-12-21 10:38:52
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-12-23 11:52:30
 * @FilePath: \go-desensitize\cipher_test.go
 * @Description: 可逆脱敏测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package desensitize

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKey 测试用密钥，固定值便于复现
var testKey = []byte("0123456789abcdef0123456789abcdef") // 32 字节 → AES-256

func TestNewCipher_KeySizes(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		c, err := NewCipher(make([]byte, n))
		assert.NoError(t, err, "%d 字节密钥应被接受", n)
		assert.NotNil(t, c)
	}
	for _, n := range []int{0, 1, 15, 17, 31, 33, 64} {
		_, err := NewCipher(make([]byte, n))
		assert.ErrorIs(t, err, ErrCipherKeySize, "%d 字节密钥应被拒绝", n)
	}
}

func TestCipher_RoundTrip(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)

	cases := []string{
		"13800138000",
		"zhangsanfeng@example.com",
		"张三丰",
		"310101199001015678",
		"sk-abcdefghijklmnopqrstuvwxyz0123456789",
		"北京市朝阳区某某路99号",
		"a",
		strings.Repeat("x", 4096),
		"含特殊字符 \n\t\"'&=:{}[]",
		"用户🎉emoji",
	}
	for _, plain := range cases {
		t.Run(plain[:min(len(plain), 16)], func(t *testing.T) {
			sealed, err := c.Encrypt(plain)
			require.NoError(t, err)
			assert.True(t, IsEncrypted(sealed), "加密结果必须带标识")
			assert.True(t, strings.HasPrefix(sealed, cipherMarker))
			// 只对足够长的明文做此检查：单字符明文必然会在 base64 里偶然出现
			if len(plain) >= 8 {
				assert.NotContains(t, sealed, plain, "密文里不应出现明文")
			}

			back, err := c.Decrypt(sealed)
			require.NoError(t, err)
			assert.Equal(t, plain, back)
		})
	}
}

// TestCipher_EmptyString 空值原样返回，不产生看不懂的密文
func TestCipher_EmptyString(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)

	sealed, err := c.Encrypt("")
	assert.NoError(t, err)
	assert.Equal(t, "", sealed)
	assert.False(t, IsEncrypted(""))
}

// TestCipher_NonDeterministic 同一明文每次加密结果不同，避免泄漏相等关系
func TestCipher_NonDeterministic(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)

	const plain = "13800138000"
	a, err := c.Encrypt(plain)
	require.NoError(t, err)
	b, err := c.Encrypt(plain)
	require.NoError(t, err)

	assert.NotEqual(t, a, b, "随机 nonce 应让同一明文产生不同密文")

	// 两者都能解回同一明文
	for _, v := range []string{a, b} {
		back, err := c.Decrypt(v)
		require.NoError(t, err)
		assert.Equal(t, plain, back)
	}
}

// TestCipher_WrongKey 换密钥解不开，且不返回错误原文
func TestCipher_WrongKey(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)
	sealed, err := c.Encrypt("13800138000")
	require.NoError(t, err)

	other, err := NewCipher([]byte("ffffffffffffffffffffffffffffffff"))
	require.NoError(t, err)

	out, err := other.Decrypt(sealed)
	assert.ErrorIs(t, err, ErrCipherCorrupt)
	assert.Equal(t, sealed, out, "解不开时原样返回，不得返回错误的明文")
}

// TestCipher_TamperDetected 密文被改动必须报错而不是返回错数据
//
// 这是选用 AES-GCM 的理由：无声地还原出错误原文比直接失败危险得多
func TestCipher_TamperDetected(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)
	sealed, err := c.Encrypt("13800138000")
	require.NoError(t, err)

	// 改动 base64 载荷里的一个字符
	payload := sealed[len(cipherMarker):]
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	require.NoError(t, err)
	raw[len(raw)-1] ^= 0x01
	tampered := cipherMarker + base64.RawURLEncoding.EncodeToString(raw)

	out, err := c.Decrypt(tampered)
	assert.ErrorIs(t, err, ErrCipherCorrupt)
	assert.Equal(t, tampered, out)
}

func TestCipher_DecryptMalformed(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)

	cases := []struct {
		name  string
		value string
		want  error
	}{
		{"明文无标识", "13800138000", ErrCipherNotSealed},
		{"空串", "", ErrCipherNotSealed},
		{"只有前缀", "enc:", ErrCipherNotSealed},
		{"缺少第二个冒号", "enc:v1", ErrCipherNotSealed},
		{"版本不支持", "enc:v9:abcd", ErrCipherVersion},
		{"base64 非法", "enc:v1:!!!not-base64!!!", ErrCipherCorrupt},
		{"载荷短于 nonce", "enc:v1:" + base64.RawURLEncoding.EncodeToString([]byte("short")), ErrCipherCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := c.Decrypt(tc.value)
			assert.ErrorIs(t, err, tc.want)
			assert.Equal(t, tc.value, out, "失败时原样返回")
		})
	}
}

func TestIsEncrypted(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)
	sealed, err := c.Encrypt("x")
	require.NoError(t, err)

	assert.True(t, IsEncrypted(sealed))
	assert.True(t, IsEncrypted("enc:v1:anything"))
	assert.True(t, IsEncrypted("enc:v9:anything"), "只看标识形状，不校验版本")
	assert.False(t, IsEncrypted(""))
	assert.False(t, IsEncrypted("enc:"))
	assert.False(t, IsEncrypted("enc:novalue"))
	assert.False(t, IsEncrypted("plain text"))
	assert.False(t, IsEncrypted(":enc:v1:x"))
}

// TestCipher_RandFailureFailsClosed 随机源不可用时必须失败关闭
func TestCipher_RandFailureFailsClosed(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)
	c.randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }

	_, err = c.Encrypt("13800138000")
	assert.Error(t, err, "拿不到随机数时不得加密")

	// MustEncrypt 回落为整体擦除，绝不返回明文
	assert.Equal(t, RedactedText, c.MustEncrypt("13800138000"))
}

func TestCipher_MustEncrypt(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)

	out := c.MustEncrypt("13800138000")
	assert.True(t, IsEncrypted(out))
	back, err := c.Decrypt(out)
	require.NoError(t, err)
	assert.Equal(t, "13800138000", back)

	assert.Equal(t, "", c.MustEncrypt(""))
}

// TestCipher_AsDesensitizer 注册为脱敏器后可在 tag 里使用，并能还原
func TestCipher_AsDesensitizer(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)
	RegisterDesensitizer("testcipher", c)

	type order struct {
		Receiver string `desensitize:"testcipher"`
		Phone    string `desensitize:"mobilePhone"`
		Remark   string
	}

	v := order{Receiver: "张三丰", Phone: "18175698789", Remark: "加急"}
	require.NoError(t, Desensitization(&v))

	assert.True(t, IsEncrypted(v.Receiver), "cipher tag 的字段应被加密")
	assert.Contains(t, v.Phone, "*", "掩码 tag 的字段仍是不可逆掩码")
	assert.Equal(t, "加急", v.Remark, "无 tag 字段不动")

	back, err := c.Decrypt(v.Receiver)
	require.NoError(t, err)
	assert.Equal(t, "张三丰", back)
}

// cipherNested 覆盖 walkStrings 的各类字段形态
type cipherInner struct {
	Secret string
}

type cipherNamed string

type cipherNested struct {
	Plain    string
	Named    cipherNamed
	Ptr      *cipherInner
	NilPtr   *cipherInner
	Inner    cipherInner
	Items    []cipherInner
	Strs     []string
	Arr      [2]string
	Dict     map[string]string
	Numbers  map[string]int
	Count    int
	unexport string
}

func TestCipher_EncryptDecryptStruct(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)

	orig := cipherNested{
		Plain:    "13800138000",
		Named:    "张三丰",
		Ptr:      &cipherInner{Secret: "ptr-secret"},
		Inner:    cipherInner{Secret: "inner-secret"},
		Items:    []cipherInner{{Secret: "item-0"}, {Secret: "item-1"}},
		Strs:     []string{"s0", "s1"},
		Arr:      [2]string{"a0", "a1"},
		Dict:     map[string]string{"k": "v"},
		Numbers:  map[string]int{"n": 1},
		Count:    7,
		unexport: "untouched",
	}
	v := orig
	v.Ptr = &cipherInner{Secret: "ptr-secret"}

	require.NoError(t, c.EncryptStruct(&v))

	assert.True(t, IsEncrypted(v.Plain))
	assert.True(t, IsEncrypted(string(v.Named)), "命名字符串类型同样加密")
	assert.True(t, IsEncrypted(v.Ptr.Secret))
	assert.Nil(t, v.NilPtr, "nil 指针不应被解引用")
	assert.True(t, IsEncrypted(v.Inner.Secret))
	assert.True(t, IsEncrypted(v.Items[0].Secret))
	assert.True(t, IsEncrypted(v.Strs[1]))
	assert.True(t, IsEncrypted(v.Arr[0]))
	assert.True(t, IsEncrypted(v.Dict["k"]))
	assert.Equal(t, 1, v.Numbers["n"], "非字符串值的映射不动")
	assert.Equal(t, 7, v.Count, "非字符串字段不动")
	assert.Equal(t, "untouched", v.unexport, "不可导出字段不动")

	// 再加密一次不应重复包裹
	before := v.Plain
	require.NoError(t, c.EncryptStruct(&v))
	assert.Equal(t, before, v.Plain, "已加密的值不应被重复加密")

	require.NoError(t, c.DecryptStruct(&v))
	assert.Equal(t, orig.Plain, v.Plain)
	assert.Equal(t, orig.Named, v.Named)
	assert.Equal(t, "ptr-secret", v.Ptr.Secret)
	assert.Equal(t, orig.Inner.Secret, v.Inner.Secret)
	assert.Equal(t, orig.Items[1].Secret, v.Items[1].Secret)
	assert.Equal(t, orig.Strs, v.Strs)
	assert.Equal(t, orig.Arr, v.Arr)
	assert.Equal(t, "v", v.Dict["k"])
}

// TestCipher_DecryptStructLeavesPlaintext 混在一起的明文字段不被动
func TestCipher_DecryptStructLeavesPlaintext(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)

	type mixed struct {
		Sealed string
		Plain  string
	}
	sealed, err := c.Encrypt("secret")
	require.NoError(t, err)

	v := mixed{Sealed: sealed, Plain: "visible"}
	require.NoError(t, c.DecryptStruct(&v))
	assert.Equal(t, "secret", v.Sealed)
	assert.Equal(t, "visible", v.Plain, "无标识的字段必须原样保留")
}

// TestCipher_DecryptStructKeepsUndecryptable 解不开的值原样保留
// 一次失败不该把整个对象变成不可读
func TestCipher_DecryptStructKeepsUndecryptable(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)

	type one struct{ F string }
	v := one{F: "enc:v1:!!!bad!!!"}
	require.NoError(t, c.DecryptStruct(&v))
	assert.Equal(t, "enc:v1:!!!bad!!!", v.F)
}

func TestCipher_StructInvalidInput(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)

	assert.Error(t, c.EncryptStruct(nil))
	assert.Error(t, c.DecryptStruct(nil))

	var p *cipherInner
	assert.Error(t, c.EncryptStruct(p), "nil 指针应报错")
	assert.Error(t, c.EncryptStruct(cipherInner{}), "非指针应报错")

	s := "x"
	assert.Error(t, c.EncryptStruct(&s), "非结构体指针应报错")
}

// TestCipher_EncryptStructRandFailureKeepsPlaintext 加密失败时字段保持原值
//
// EncryptStruct 不能把失败的字段写成 RedactedText：那会在一次偶发失败里
// 永久销毁数据而调用方毫无察觉，原样保留并由上层决定更安全
func TestCipher_EncryptStructRandFailureKeepsPlaintext(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)
	c.randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }

	type one struct{ F string }
	v := one{F: "13800138000"}
	require.NoError(t, c.EncryptStruct(&v))
	assert.Equal(t, "13800138000", v.F, "加密失败时保留原值，不得静默销毁数据")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestNewCipher_ConstructionFailure 构造失败必须返回错误，而非半初始化的 Cipher
//
// 两条分支在当前用法下不可达（密钥长度已校验、AES 分组恒为 16），
// 但日后换算法时它们就是唯一的防线
func TestNewCipher_ConstructionFailure(t *testing.T) {
	t.Run("分组密码构造失败", func(t *testing.T) {
		orig := newBlockCipher
		t.Cleanup(func() { newBlockCipher = orig })
		newBlockCipher = func([]byte) (cipher.Block, error) { return nil, errors.New("forced block failure") }

		c, err := NewCipher(testKey)
		assert.Error(t, err)
		assert.Nil(t, c, "构造失败不得返回可用对象")
	})

	t.Run("AEAD 构造失败", func(t *testing.T) {
		orig := newAEAD
		t.Cleanup(func() { newAEAD = orig })
		newAEAD = func(cipher.Block) (cipher.AEAD, error) { return nil, errors.New("forced aead failure") }

		c, err := NewCipher(testKey)
		assert.Error(t, err)
		assert.Nil(t, c)
	})
}

// ==== 全局装配 | Default cipher ====

// TestDefaultCipher_FailsClosedWhenUnconfigured 未装配密钥时必须整体擦除
//
// 这是本库最不能出错的一条：忘记装配的后果应当是「看不到数据」，
// 而不是「以为加密了其实是明文」后者不报错、不可见，等到泄漏才发现
func TestDefaultCipher_FailsClosedWhenUnconfigured(t *testing.T) {
	ClearDefaultCipher()
	t.Cleanup(ClearDefaultCipher)
	assert.Nil(t, DefaultCipher())

	type order struct {
		Receiver string `desensitize:"cipher"`
	}
	v := order{Receiver: "张三丰"}
	require.NoError(t, Desensitization(&v))
	assert.Equal(t, RedactedText, v.Receiver, "未装配时必须整体擦除，绝不留明文")
	assert.NotEqual(t, "张三丰", v.Receiver)

	// 全局结构体入口直接报错，不静默跳过
	v2 := order{Receiver: "张三丰"}
	assert.ErrorIs(t, EncryptStructDefault(&v2), ErrCipherNotConfigured)
	assert.ErrorIs(t, DecryptStructDefault(&v2), ErrCipherNotConfigured)
	assert.Equal(t, "张三丰", v2.Receiver, "报错时不改动字段")
}

// TestSetDefaultCipher_TagWorksAfterConfigure 装配后 tag 直接可用且可还原
func TestSetDefaultCipher_TagWorksAfterConfigure(t *testing.T) {
	ClearDefaultCipher()
	t.Cleanup(ClearDefaultCipher)

	require.NoError(t, SetDefaultCipher(testKey))
	require.NotNil(t, DefaultCipher())

	type order struct {
		Receiver string `desensitize:"cipher"`
		Phone    string `desensitize:"mobilePhone"`
		Remark   string
	}
	v := order{Receiver: "张三丰", Phone: "18175698789", Remark: "加急"}
	require.NoError(t, Desensitization(&v))

	assert.True(t, IsEncrypted(v.Receiver), "装配后 cipher tag 应加密")
	assert.Contains(t, v.Phone, "*", "掩码 tag 仍不可逆")
	assert.Equal(t, "加急", v.Remark)

	back, err := DefaultCipher().Decrypt(v.Receiver)
	require.NoError(t, err)
	assert.Equal(t, "张三丰", back)
}

// TestSetDefaultCipher_RebuildsCachedPlans 装配前已缓存的类型计划必须失效重建
// 否则「先用后装配」会让 cipher tag 永久停在失败关闭状态
func TestSetDefaultCipher_RebuildsCachedPlans(t *testing.T) {
	ClearDefaultCipher()
	t.Cleanup(ClearDefaultCipher)

	type late struct {
		F string `desensitize:"cipher"`
	}
	v := late{F: "张三丰"}
	require.NoError(t, Desensitization(&v))
	assert.Equal(t, RedactedText, v.F, "装配前失败关闭")

	require.NoError(t, SetDefaultCipher(testKey))

	v2 := late{F: "张三丰"}
	require.NoError(t, Desensitization(&v2))
	assert.True(t, IsEncrypted(v2.F), "装配后必须对已缓存类型生效")
}

func TestSetDefaultCipher_BadKey(t *testing.T) {
	ClearDefaultCipher()
	t.Cleanup(ClearDefaultCipher)

	assert.ErrorIs(t, SetDefaultCipher(make([]byte, 7)), ErrCipherKeySize)
	assert.Nil(t, DefaultCipher(), "装配失败不得留下半成品")
}

func TestEncryptDecryptStructDefault(t *testing.T) {
	ClearDefaultCipher()
	t.Cleanup(ClearDefaultCipher)
	require.NoError(t, SetDefaultCipher(testKey))

	type payload struct {
		Receiver string
		Plain    string
	}
	v := payload{Receiver: "张三丰", Plain: "visible"}
	require.NoError(t, EncryptStructDefault(&v))
	assert.True(t, IsEncrypted(v.Receiver))
	assert.True(t, IsEncrypted(v.Plain), "EncryptStruct 不看 tag，所有字符串字段都加密")

	require.NoError(t, DecryptStructDefault(&v))
	assert.Equal(t, "张三丰", v.Receiver)
	assert.Equal(t, "visible", v.Plain)
}

func TestUnconfiguredCipher_Desensitize(t *testing.T) {
	assert.Equal(t, RedactedText, unconfiguredCipher{}.Desensitize("anything"))
	assert.Equal(t, RedactedText, unconfiguredCipher{}.Desensitize(""))
}

// ==== 确定性加密 | Deterministic encryption ====

// TestCipher_Deterministic 同一明文恒产出同一密文，且仍可解回
//
// 这是「既要跨行关联、又要出事能定位身份」的解：
// 随机 nonce 的 Encrypt 让同一会话每行密文都不同，关联断了
func TestCipher_Deterministic(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)

	const sess = "sess-abc123def456"
	a := c.EncryptDeterministic(sess)
	b := c.EncryptDeterministic(sess)

	assert.Equal(t, a, b, "确定性加密必须恒产出同一串，否则无法跨行关联")
	assert.True(t, IsEncrypted(a))
	assert.NotContains(t, a, sess)

	// 仍可解回，这是它与指纹的关键差别
	back, err := c.Decrypt(a)
	require.NoError(t, err)
	assert.Equal(t, sess, back, "持密钥必须能还原出身份")

	// 不同明文产出不同密文
	assert.NotEqual(t, a, c.EncryptDeterministic("sess-other"))

	// 与随机 nonce 的 Encrypt 产出不同，但两者都能被同一个 Decrypt 解开
	rnd, err := c.Encrypt(sess)
	require.NoError(t, err)
	assert.NotEqual(t, a, rnd, "两种模式的密文不应相同")
	backRnd, err := c.Decrypt(rnd)
	require.NoError(t, err)
	assert.Equal(t, sess, backRnd, "Decrypt 不需要区分两种模式")

	// 空值原样返回
	assert.Equal(t, "", c.EncryptDeterministic(""))
}

// TestCipher_DeterministicDifferentKeys 换密钥后密文不同且解不开
func TestCipher_DeterministicDifferentKeys(t *testing.T) {
	c1, err := NewCipher(testKey)
	require.NoError(t, err)
	c2, err := NewCipher([]byte("ffffffffffffffffffffffffffffffff"))
	require.NoError(t, err)

	const sess = "sess-abc123"
	a := c1.EncryptDeterministic(sess)
	b := c2.EncryptDeterministic(sess)
	assert.NotEqual(t, a, b, "不同密钥的 nonce 派生子密钥不同，密文须不同")

	_, err = c2.Decrypt(a)
	assert.ErrorIs(t, err, ErrCipherCorrupt)
}

// TestCipher_DeterministicNonceIsolated nonce 派生用的是独立子密钥
//
// 同一把密钥既做加密又做 MAC 属于跨原语复用，应当避免
// 这里间接验证：派生子密钥与原密钥不同
func TestCipher_DeterministicNonceIsolated(t *testing.T) {
	c, err := NewCipher(testKey)
	require.NoError(t, err)
	assert.NotEqual(t, testKey, c.macKey, "nonce 派生必须用独立子密钥")
	assert.Len(t, c.macKey, 32, "HMAC-SHA256 派生结果为 32 字节")
}

// TestMaskEncrypt_FailsClosedWithoutKey MaskEncrypt 未装配密钥时整体擦除
//
// 调用方选 MaskEncrypt 要的是「可还原」而非「可见」，
// 密钥没装配好时退回明文等于把本该保护的凭据原样写出去
func TestMaskEncrypt_FailsClosedWithoutKey(t *testing.T) {
	ClearDefaultCipher()
	t.Cleanup(func() {
		ClearDefaultCipher()
		OverrideKeyAction("session_id", WipeValue)
	})
	OverrideKeyAction("session_id", MaskEncrypt)

	m := NewMasker()
	out := m.Mask([]byte(`{"session_id":"sess-abc123","user":"bob"}`))
	assert.NotContains(t, out, "sess-abc123", "未装配密钥时不得留下明文")
	assert.Contains(t, out, defaultSensitiveMask)
	assert.Contains(t, out, "bob", "无关字段不受影响")

	// 装配密钥后同一会话在多次调用里产出同一串，并可解回
	require.NoError(t, SetDefaultCipher(testKey))
	first := m.Mask([]byte(`{"session_id":"sess-abc123"}`))
	second := m.Mask([]byte(`{"session_id":"sess-abc123"}`))
	assert.Equal(t, first, second, "确定性加密让同一会话跨行可关联")
	assert.NotContains(t, first, "sess-abc123")

	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(first), &d))
	back, err := DefaultCipher().Decrypt(d["session_id"].(string))
	require.NoError(t, err)
	assert.Equal(t, "sess-abc123", back, "事故复盘时持密钥可还原身份")

	// 文本路径同样走加密分支，且同样确定性、同样可还原
	txt := m.Mask([]byte("session_id=sess-abc123 user=bob"))
	assert.NotContains(t, txt, "sess-abc123")
	assert.Contains(t, txt, "user=bob", "无关字段不受影响")
	assert.Equal(t, txt, m.Mask([]byte("session_id=sess-abc123 user=bob")),
		"文本路径同样确定性，同一会话跨行可关联")

	sealed := strings.TrimSuffix(strings.TrimPrefix(txt, "session_id="), " user=bob")
	require.True(t, IsEncrypted(sealed), "文本路径应产出带标识的密文，实得 %q", sealed)
	back, err = DefaultCipher().Decrypt(sealed)
	require.NoError(t, err)
	assert.Equal(t, "sess-abc123", back)

	// 未装配密钥时文本路径同样失败关闭
	ClearDefaultCipher()
	txt = m.Mask([]byte("session_id=sess-abc123 user=bob"))
	assert.NotContains(t, txt, "sess-abc123", "未装配密钥时文本路径不得留明文")
	assert.Contains(t, txt, defaultSensitiveMask)
}

// TestMaskFingerprint_InMasker 指纹档在报文脱敏里生效且不需要密钥
func TestMaskFingerprint_InMasker(t *testing.T) {
	t.Cleanup(func() { OverrideKeyAction("session_id", WipeValue) })
	OverrideKeyAction("session_id", MaskFingerprint)

	m := NewMasker()
	a := m.Mask([]byte(`{"session_id":"sess-abc123","user":"bob"}`))
	b := m.Mask([]byte(`{"session_id":"sess-abc123","user":"amy"}`))

	var da, db map[string]any
	require.NoError(t, json.Unmarshal([]byte(a), &da))
	require.NoError(t, json.Unmarshal([]byte(b), &db))

	assert.Equal(t, da["session_id"], db["session_id"], "同一会话指纹一致，可关联")
	assert.NotContains(t, a, "sess-abc123")
	assert.Equal(t, "bob", da["user"])

	// 不同会话指纹不同
	cOut := m.Mask([]byte(`{"session_id":"sess-other"}`))
	var dc map[string]any
	require.NoError(t, json.Unmarshal([]byte(cOut), &dc))
	assert.NotEqual(t, da["session_id"], dc["session_id"])

	// 文本路径同样生效
	txt := m.Mask([]byte("session_id=sess-abc123 user=bob"))
	assert.NotContains(t, txt, "sess-abc123")
	assert.Contains(t, txt, "user=bob")
	assert.Equal(t, txt, m.Mask([]byte("session_id=sess-abc123 user=bob")), "文本路径同样确定性")
}

// TestMaskEncrypt_NonStringValue 非字符串值没有安全的加密方式，整体擦除
func TestMaskEncrypt_NonStringValue(t *testing.T) {
	ClearDefaultCipher()
	require.NoError(t, SetDefaultCipher(testKey))
	t.Cleanup(func() {
		ClearDefaultCipher()
		OverrideKeyAction("session_id", WipeValue)
	})
	OverrideKeyAction("session_id", MaskEncrypt)

	m := NewMasker()
	out := m.Mask([]byte(`{"session_id":12345}`))
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &d))
	assert.Equal(t, defaultSensitiveMask, d["session_id"])
	assert.NotContains(t, out, "12345")
}
