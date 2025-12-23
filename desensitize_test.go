/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2023-07-28 00:50:58
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-12-23 11:52:30
 * @FilePath: \go-desensitize\desensitize_test.go
 * @Description:
 *
 * Copyright (c) 2024 by kamalyes, All Rights Reserved.
 */
package desensitize

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSensitiveData(t *testing.T) {
	assert.Equal(t, "1***", SensitiveData("1234", 0, 0))
	assert.Equal(t, "1***", SensitiveData("1234", 2, 2))
	assert.Equal(t, "12*4", SensitiveData("1234", 2, 3))
	assert.Equal(t, "1***", SensitiveData("1234", 0, 5))
	assert.Equal(t, "", SensitiveData("", 0, 0))
}

func TestDesensitizeAllTypes(t *testing.T) {
	desensitizeOptions := NewDesensitizeOptions()
	testCases := map[string]struct {
		input           string
		expected        string
		desensitizeType DesensitizeType
		option          DesensitizeOptions
	}{
		"TestSensitiveData": {
			input:           "123456789",
			expected:        "123****89",
			desensitizeType: CustomExtension,
			option:          DesensitizeOptions{CustomExtensionStartIndex: 3, CustomExtensionEndIndex: 7},
		},
		"TestChineseName": {
			input:           "李四",
			expected:        "李*",
			desensitizeType: ChineseName,
		},
		"TestIDCard": {
			input:           "123456789012345678",
			expected:        "123456********5678",
			desensitizeType: IDCard,
			option:          desensitizeOptions,
		},
		"TestPassWord": {
			input:           "12678",
			expected:        "1****",
			desensitizeType: Password,
		},
		"TestPhoneNumber": {
			input:           "18175698789",
			expected:        "181****8789",
			desensitizeType: PhoneNumber,
			option:          desensitizeOptions,
		},
		"TestMobilePhone": {
			input:           "13812345678",
			expected:        "138****5678",
			desensitizeType: MobilePhone,
			option:          desensitizeOptions,
		},
		"TestAddress": {
			input:           "北京市朝阳区某某街道123号",
			expected:        "北京市朝*******23号",
			desensitizeType: Address,
			option:          desensitizeOptions,
		},
		"TestEmail": {
			input:           "example@test.com",
			expected:        "e****le@test.com",
			desensitizeType: Email,
			option:          desensitizeOptions,
		},
		"TestCarLicense": {
			input:           "浙A12345B",
			expected:        "浙A1***5B",
			desensitizeType: CarLicense,
		},
		"TestBankCard": {
			input:           "1234567890123456",
			expected:        "1234 **** **** **** 3456",
			desensitizeType: BankCard,
			option:          desensitizeOptions,
		},
		"TestIPv4": {
			input:           "192.168.1.1",
			expected:        "192.*.*.*",
			desensitizeType: IPV4,
		},
		"TestIPv6": {
			input:           "2001:0db8:86a3:08d3:1319:8a2e:0370:7344",
			expected:        "2001:*:*:*:*:*:*:*",
			desensitizeType: IPV6,
		},
		"TestPEMKey": {
			input: strings.Join([]string{
				"-----BEGIN PRIVATE KEY-----",
				"1234567890abcdef1234567890abcdef12345678",
				"-----END PRIVATE KEY-----",
			}, "\r\n"),
			expected: strings.Join([]string{
				"-----BEGIN PRIVATE KEY-----",
				"1234567890abcdef********90abcdef12345678",
				"-----END PRIVATE KEY-----",
			}, "\n"),
			desensitizeType: PEMKey,
			option:          desensitizeOptions,
		},
		"TestUserID": {
			input:           "1000234567",
			expected:        "10******67",
			desensitizeType: UserID,
			option:          desensitizeOptions,
		},
		"TestPlayerID": {
			input:           "P202400123",
			expected:        "P2******23",
			desensitizeType: PlayerID,
			option:          desensitizeOptions,
		},
		"TestOrderNo": {
			input:           "ORD2024010112345",
			expected:        "OR************45",
			desensitizeType: OrderNo,
			option:          desensitizeOptions,
		},
		"TestUUID": {
			input:           "550e8400-e29b-41d4-a716-446655440000",
			expected:        "55" + strings.Repeat("*", 32) + "00",
			desensitizeType: UUID,
			option:          desensitizeOptions,
		},
		"TestOpenID": {
			input:           "o6_bmjrPTlm6_2sgVt7hMZ3",
			expected:        "o6" + strings.Repeat("*", 19) + "Z3",
			desensitizeType: OpenID,
			option:          desensitizeOptions,
		},
		"TestAccount": {
			input:           "zhangsan",
			expected:        "zh****an",
			desensitizeType: Account,
			option:          desensitizeOptions,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expected, Desensitize(tc.input, tc.desensitizeType, tc.option))
		})
	}
}

func TestPhoneNumber(t *testing.T) {
	assert.Equal(t, "", SensitizePhoneNumber("", 3, 7))
	assert.Equal(t, "181****8789", SensitizePhoneNumber("18175698789", 3, 7))
	assert.Equal(t, "181*****789", SensitizePhoneNumber("1817789", 3, 7))
}

func TestBankCard(t *testing.T) {
	assert.Equal(t, "1234 **** **** *** 6789", SensitizeBankCard("123456789", 16))
	assert.Equal(t, "1234 **** **** *** 6789", SensitizeBankCard("1234 5678 9", 16))
	assert.Equal(t, "1234 **** **** **** 6789", SensitizeBankCard("123456789", 19))
	assert.Equal(t, "1234 **** **** **** 6789", SensitizeBankCard("1234 5678 9", 19))
	assert.Equal(t, "", SensitizeBankCard("", 19))
}

func TestIPv4(t *testing.T) {
	assert.Equal(t, "127.*.*.*", SensitizeIpv4("127.0.0.1"))
	assert.Equal(t, "", SensitizeIpv4(""))
}

func TestIPv6(t *testing.T) {
	assert.Equal(t, "2001:*:*:*:*:*:*:*", SensitizeIpv6("2001:0db8:86a3:08d3:1319:8a2e:0370:7344"))
	assert.Equal(t, "", SensitizeIpv6(""))
}

func TestSensitizePEMKey(t *testing.T) {
	assert.Equal(t, strings.Repeat("*", len("short-secret")), SensitizePEMKey("short-secret", 16, 16))
}

func TestDesensitizeIDCustomOptions(t *testing.T) {
	opt := NewDesensitizeOptions()
	opt.IDPrefixVisibleLen = 4
	opt.IDSuffixVisibleLen = 4
	assert.Equal(t, "1000**4567", Desensitize("1000234567", UserID, opt))
	assert.Equal(t, "ORD2********2345", Desensitize("ORD2024010112345", OrderNo, opt))

	// 短字符串：前后缀可见长度之和大于等于长度时全掩码
	assert.Equal(t, "****", Desensitize("1234", UserID, NewDesensitizeOptions()))
	// 空字符串直接返回
	assert.Equal(t, "", Desensitize("", PlayerID))
}

func TestSensitizeJump(t *testing.T) {
	// 连续掩码：end=-4 动态保留末尾 4 位，等价手机号脱敏效果
	assert.Equal(t, "181****8789", SensitizeJump("18175698789", 3, -4, 1))
	// 跳步 2：从索引 1 开始隔位掩码，end=-1 动态保留最后 1 位
	assert.Equal(t, "1*1*5*9*7*9", SensitizeJump("18175698789", 1, -1, 2))
	// 固定区间 [1,4)，跳步默认按 1 处理
	assert.Equal(t, "1***56789", SensitizeJump("123456789", 1, 4, 1))
	// end=0 表示到末尾
	assert.Equal(t, "18*********", SensitizeJump("18175698789", 2, 0, 1))
	// 跳步数非法时按 1 处理
	assert.Equal(t, "181****8789", SensitizeJump("18175698789", 3, -4, 0))
	// 开始位置不小于结束位置时不处理
	assert.Equal(t, "12345", SensitizeJump("12345", 3, 2, 1))
	// 负数开始索引：-1 表示最后一个字符
	assert.Equal(t, "1234*", SensitizeJump("12345", -1, 0, 1))
	// 负数开始索引超出长度时从 0 开始
	assert.Equal(t, "*****", SensitizeJump("12345", -20, 0, 1))
	// 结束索引超出长度时截断到末尾
	assert.Equal(t, "*****", SensitizeJump("12345", 0, 100, 1))
	// 中文字符按字符计数
	assert.Equal(t, "北****区", SensitizeJump("北京市朝阳区", 1, -1, 1))
	// 空字符串直接返回
	assert.Equal(t, "", SensitizeJump("", 1, -1, 2))
}

// ==== 边界与全类型覆盖 | Boundaries and full type coverage ====

// TestDesensitize_AllTypes 遍历每个脱敏类型，确保 switch 的每个分支都被执行
// 未知类型落到 default 分支原样返回
func TestDesensitize_AllTypes(t *testing.T) {
	cases := []struct {
		name string
		typ  DesensitizeType
		in   string
	}{
		{"CustomExtension", CustomExtension, "abcdef"},
		{"ChineseName", ChineseName, "张三丰"},
		{"IDCard", IDCard, "310101199001015678"},
		{"PhoneNumber", PhoneNumber, "18175698789"},
		{"MobilePhone", MobilePhone, "18175698789"},
		{"Address", Address, "北京市朝阳区某某路99号"},
		{"Email", Email, "zhangsanfeng@example.com"},
		{"Password", Password, "hunter2"},
		{"CarLicense", CarLicense, "京A12345"},
		{"BankCard", BankCard, "6222025678565678"},
		{"IPV4", IPV4, "192.168.1.1"},
		{"IPV6", IPV6, "2001:db8::8a2e:370:7334"},
		{"PEMKey", PEMKey, "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabcdefgh\n-----END RSA PRIVATE KEY-----"},
		{"APIKey", APIKey, "sk-abcdefghijklmnopqrstuvwxyz"},
		{"Secret", Secret, "sk-abcdefghijklmnopqrstuvwxyz"},
		{"UserID", UserID, "1234567890"},
		{"PlayerID", PlayerID, "1234567890"},
		{"OrderNo", OrderNo, "1234567890"},
		{"UUID", UUID, "550e8400-e29b-41d4-a716-446655440000"},
		{"OpenID", OpenID, "oabc123def456"},
		{"Account", Account, "account12345"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Desensitize(c.in, c.typ)
			assert.NotEmpty(t, got)
			assert.Contains(t, got, "*", "类型 %s 应产生掩码", c.name)
		})
	}

	// 未知类型走 default 分支，原样返回
	assert.Equal(t, "abcdef", Desensitize("abcdef", DesensitizeType(9999)))
	// 空与全空白提前返回
	assert.Equal(t, "", Desensitize("", Email))
	assert.Equal(t, "   ", Desensitize("   ", Email))
}

// TestDesensitize_WithOptions 自定义选项生效
func TestDesensitize_WithOptions(t *testing.T) {
	opt := NewDesensitizeOptions()
	opt.APIKeyPrefixVisibleLen = 2
	opt.APIKeySuffixVisibleLen = 2
	assert.Equal(t, "ab******ij", Desensitize("abcdefghij", APIKey, opt))
}

// TestSensitizePEMKey_Variants PEM 的各种形态
func TestSensitizePEMKey_Variants(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabcdefghijklmnop\n-----END RSA PRIVATE KEY-----"
	got := SensitizePEMKey(pem, 4, 4)
	lines := strings.Split(got, "\n")
	assert.Len(t, lines, 3)
	assert.Equal(t, "-----BEGIN RSA PRIVATE KEY-----", lines[0])
	assert.Equal(t, "-----END RSA PRIVATE KEY-----", lines[2])
	assert.True(t, strings.HasPrefix(lines[1], "MIIE"))
	assert.Contains(t, lines[1], "*")

	// CRLF 换行先被归一化
	assert.Len(t, strings.Split(SensitizePEMKey(strings.ReplaceAll(pem, "\n", "\r\n"), 4, 4), "\n"), 3)

	// 空与全空白提前返回
	assert.Equal(t, "", SensitizePEMKey("", 4, 4))
	assert.Equal(t, "  ", SensitizePEMKey("  ", 4, 4))

	// isBlank 不认的空白（如 \v）会被 TrimSpace 清空，走 normalized == "" 分支
	assert.Equal(t, "\v", SensitizePEMKey("\v", 4, 4))

	// 非 PEM 形态退回密钥片段掩码
	got = SensitizePEMKey("just-a-plain-secret-value", 4, 4)
	assert.Contains(t, got, "*")
	assert.NotContains(t, got, "\n")

	// 行数不足三行
	assert.Contains(t, SensitizePEMKey("-----BEGIN X-----\n-----END X-----", 4, 4), "*")
	// 首行不是 BEGIN
	assert.Contains(t, SensitizePEMKey("header\nbody\n-----END X-----", 4, 4), "*")
}

// TestSensitizeSecretSegment 密钥片段掩码的边界
func TestSensitizeSecretSegment(t *testing.T) {
	assert.Equal(t, "abcd********wxyz", sensitizeSecretSegment("abcdefghijklwxyz", 4, 4))
	assert.Equal(t, "", sensitizeSecretSegment("", 4, 4))

	// 负数长度夹到 0
	assert.Equal(t, "**********", sensitizeSecretSegment("abcdefghij", -1, -1))
	assert.Equal(t, "abcdefghi*", sensitizeSecretSegment("abcdefghij", 9, -1))
	assert.Equal(t, "*bcdefghij", sensitizeSecretSegment("abcdefghij", -1, 9))

	// 可见长度之和不小于总长时整体掩码
	assert.Equal(t, "****", sensitizeSecretSegment("abcd", 2, 2))
	assert.Equal(t, "****", sensitizeSecretSegment("abcd", 5, 5))
}

// TestSensitiveData_Boundaries 通用掩码的索引夹取
func TestSensitiveData_Boundaries(t *testing.T) {
	assert.Equal(t, "", SensitiveData("", 1, 3))
	assert.Equal(t, "   ", SensitiveData("   ", 1, 3))
	// 起止相等时重置为 1..charCount，即「保留首字符、其余掩码」
	assert.Equal(t, "a****", SensitiveData("abcde", 3, 3))
	// 越界被夹取
	assert.Equal(t, "a****", SensitiveData("abcde", 1, 99))
	assert.Equal(t, "a****", SensitiveData("abcde", -5, 99))
}

// TestSensitizeJump_Boundaries 跳步脱敏的索引换算
func TestSensitizeJump_Boundaries(t *testing.T) {
	assert.Equal(t, "", SensitizeJump("", 0, 0, 1))
	assert.Equal(t, "   ", SensitizeJump("   ", 0, 0, 1))
	// 起点不小于终点时无需脱敏
	assert.Equal(t, "abcdef", SensitizeJump("abcdef", 4, 2, 1))
	// 跳步非法按 1 处理
	assert.Equal(t, "******", SensitizeJump("abcdef", 0, 0, -5))
	// 负数索引按长度换算
	assert.Equal(t, "ab**ef", SensitizeJump("abcdef", -4, -2, 1))
	// 终点超长被夹取
	assert.Equal(t, "******", SensitizeJump("abcdef", 0, 99, 1))
	// 起点为极小负数被夹到 0
	assert.Equal(t, "******", SensitizeJump("abcdef", -99, 0, 1))
}

// TestSensitizeBankCard_Variants 银行卡号的清理、补位与分组
func TestSensitizeBankCard_Variants(t *testing.T) {
	got := SensitizeBankCard("6222025678565678", 19)
	assert.Contains(t, got, "6222")
	assert.Contains(t, got, "5678")
	assert.Contains(t, got, "*")
	// 含空格的卡号先被清理，结果应与无空格一致
	assert.Equal(t, got, SensitizeBankCard("6222 0256 7856 5678", 19))
	// cardLength 为 16 时走另一条末尾长度分支
	assert.Contains(t, SensitizeBankCard("6222025678565678", 16), "*")
	assert.Equal(t, "", SensitizeBankCard("", 19))
}

// TestSensitizeIPv4AndIPv6_Variants IP 脱敏
func TestSensitizeIPv4AndIPv6_Variants(t *testing.T) {
	assert.Equal(t, "192.*.*.*", SensitizeIpv4("192.168.1.1"))
	assert.Equal(t, "", SensitizeIpv4(""))
	assert.Equal(t, "2001:*:*:*:*:*:*:*", SensitizeIpv6("2001:db8::1"))
	assert.Equal(t, "", SensitizeIpv6(""))
}

// TestSensitizePhoneNumber_Variants 手机号补位后掩码
func TestSensitizePhoneNumber_Variants(t *testing.T) {
	assert.Equal(t, "", SensitizePhoneNumber("", 3, 7))
	assert.Equal(t, "181****8789", SensitizePhoneNumber("18175698789", 3, 7))
	// 短输入先被补位到 11 位
	assert.Contains(t, SensitizePhoneNumber("1817789", 3, 7), "*")
}
