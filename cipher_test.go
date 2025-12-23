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
