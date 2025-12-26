/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2023-07-28 00:50:58
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-12-23 11:52:30
 * @FilePath: \go-desensitize\desensitize.go
 * @Description: 按脱敏类型对单个字符串值做脱敏
 *
 * Copyright (c) 2024 by kamalyes, All Rights Reserved.
 */

package desensitize

import (
	"strings"
	"unicode/utf8"
)

// Desensitize 数据脱敏
func Desensitize(str string, DesensitizeType DesensitizeType, options ...DesensitizeOptions) string {
	// 如果数据为空，则返回空字符串
	if isBlank(str) {
		return str
	}
	opt := NewDesensitizeOptions()
	if len(options) > 0 {
		opt = options[0]
	}
	var newStr string
	switch DesensitizeType {
	case CustomExtension:
		newStr = SensitiveData(str, opt.CustomExtensionStartIndex, opt.CustomExtensionEndIndex)
	case ChineseName:
		n := runeLen(str)
		newStr = sensitiveDataN(str, opt.ChineseNameStartIndex, 1+(n-2)/2, n)
	case IDCard:
		n := runeLen(str)
		newStr = sensitiveDataN(str, opt.IdCardStartIndex, n-4, n)
	case PhoneNumber:
		newStr = SensitizePhoneNumber(str, opt.PhoneNumberStartIndex, opt.PhoneNumberEndIndex)
	case MobilePhone:
		n := runeLen(str)
		newStr = sensitiveDataN(str, opt.MobilePhoneStartIndex, n-4, n)
	case Address:
		// 原先这一行里 runeLen 被调两次，加上 SensitiveData 内部与 hide 各一遍，
		// 一次脱敏要把字符串扫四趟，多字节地址上尤其明显
		n := runeLen(str)
		newStr = sensitiveDataN(str, n/3, n-3, n)
	case Email:
		newStr = sensitiveDataN(str, opt.EmailStartIndex, indexOf(str, "@")-2, runeLen(str))
	case Password:
		n := runeLen(str)
		newStr = sensitiveDataN(str, 0, n, n)
	case CarLicense:
		n := runeLen(str)
		newStr = sensitiveDataN(str, 3, n-2, n)
	case BankCard:
		newStr = SensitizeBankCard(str, opt.IdCardLength)
	case IPV4:
		newStr = SensitizeIpv4(str)
	case IPV6:
		newStr = SensitizeIpv6(str)
	case PEMKey:
		newStr = SensitizePEMKey(str, opt.PEMBodyPrefixVisibleLen, opt.PEMBodySuffixVisibleLen)
	case APIKey:
		newStr = sensitizeSecretSegment(str, opt.APIKeyPrefixVisibleLen, opt.APIKeySuffixVisibleLen)
	case Secret:
		newStr = sensitizeSecretSegment(str, opt.SecretPrefixVisibleLen, opt.SecretSuffixVisibleLen)
	case UserID, PlayerID, OrderNo, UUID, OpenID, Account:
		newStr = sensitizeSecretSegment(str, opt.IDPrefixVisibleLen, opt.IDSuffixVisibleLen)
	default:
		newStr = str
	}

	return newStr
}

// 通用脱敏函数
func SensitiveData(str string, start, end int) string {
	// 如果数据为空，则返回空字符串
	if isBlank(str) {
		return str
	}

	return sensitiveDataN(str, start, end, utf8.RuneCountInString(str))
}

// sensitiveDataN 与 SensitiveData 相同，但字符数由调用方传入
//
// Desensitize 的多个分支本就要先知道字符数才能算出 start/end，
// 原先那个结果被丢掉、进了 SensitiveData 又重新数一遍
// 多字节输入下每一趟都是完整解码，省掉它比省一次分配更划算
//
// [EN] Several branches of Desensitize already need the rune count to compute
// start and end, and the original threw that result away so SensitiveData could
// count again. Each pass is a full decode for multi-byte input, so dropping one
// buys more than dropping an allocation
// 前置条件：str 非空白，charCount 为其字符数
// 两个调用方（Desensitize 与 SensitiveData）都已在入口查过空白，这里不再重复扫一遍
//
// [EN] Precondition: str is non-blank and charCount is its rune count. Both
// callers already check for blank at their entry, so the scan is not repeated
func sensitiveDataN(str string, start, end, charCount int) string {
	// 调整起始位置和结束位置
	if start <= 0 || start >= charCount {
		start = 1
	}

	if end <= 0 || end >= charCount {
		end = charCount
	}

	// 如果起始位置和结束位置相等，则视为需要处理整个文本
	if start == end {
		start = 1
		end = charCount
	}

	// 对指定位置的敏感数据进行隐藏处理
	return hide(str, start, end, charCount)
}

// SensitizeJump 跳步脱敏：掩码 [start, end) 区间内从 start 开始、以 step 为步长跳步选取的字符
// start：开始索引（含），支持负数（-1 表示最后一个字符，按实际长度动态换算）
// end：结束索引（不含），支持负数动态换算（-N 表示保留末尾 N 个字符，0 表示到末尾）
// step：跳步数（<=0 时按 1 处理，1 为连续掩码，2 为隔位掩码）
func SensitizeJump(str string, start, end, step int) string {
	// 如果数据为空，则返回空字符串
	if isBlank(str) {
		return str
	}

	// 获取字符数量
	charCount := utf8.RuneCountInString(str)

	// 负数开始索引按实际长度动态换算为绝对索引
	if start < 0 {
		start += charCount
	}

	// 结束索引 <=0 时按实际长度动态换算：-N 即保留末尾 N 个字符，0 表示到末尾
	if end <= 0 {
		end += charCount
	}

	// 边界修正
	if start < 0 {
		start = 0
	}
	if end > charCount {
		end = charCount
	}

	// 开始位置不小于结束位置时无需脱敏
	if start >= end {
		return str
	}

	// 跳步数非法时按连续掩码处理
	if step <= 0 {
		step = 1
	}

	// 按跳步掩码指定位置的字符
	runes := []rune(str)
	for i := start; i < end; i += step {
		runes[i] = '*'
	}
	return string(runes)
}

// 手机号脱敏
func SensitizePhoneNumber(str string, start, end int) string {
	// 空判断
	if isBlank(str) {
		return str
	}
	return SensitiveData(padMiddle(str, 11), start, end)
}

// 银行卡号脱敏
func SensitizeBankCard(str string, cardLength int) string {
	// 如果卡号为空，则直接返回原卡号
	if isBlank(str) {
		return str
	}

	// 清理卡号中的空格
	cleanCardNo := cleanSpaces(str)
	// 使用指定的长度填充卡号
	cleanCardNo = padMiddle(cleanCardNo, cardLength)
	// 获取卡号长度
	length := runeLen(cleanCardNo)
	// 默认间隔为4
	interval := 4

	// 根据卡号长度和特殊情况调整末尾长度
	endLength := length % interval
	if cardLength == 16 {
		endLength = length % 3
	}
	// 计算中间部分长度
	midLength := length - interval - endLength

	// 生成新的卡号切片，初始包含前4位
	newCardNo := []rune(cleanCardNo[:interval])
	for i := 0; i < midLength; i++ {
		// 每隔4位插入一个空格
		if i%interval == 0 {
			newCardNo = append(newCardNo, ' ')
		}
		// 其余字符用*替换
		newCardNo = append(newCardNo, '*')
	}
	// 在中间部分的最末尾插入一个空格
	newCardNo = append(newCardNo, ' ')
	// 添加卡号的最后4位
	// 复用上面已求出的 length：此处沿用上游按字节索引的语义，取值完全相同
	lastFour := cleanCardNo[length-4:]
	newCardNo = append(newCardNo, []rune(lastFour)...)

	// 返回格式化后的卡号
	return string(newCardNo)
}

// ipv4 脱敏
func SensitizeIpv4(str string) string {
	if isBlank(str) {
		return str
	}
	newIP := subBefore(str, ".")
	return newIP + ".*.*.*"
}

// ipv6 脱敏
func SensitizeIpv6(str string) string {
	if isBlank(str) {
		return str
	}
	newIP := subBefore(str, ":")
	return newIP + ":*:*:*:*:*:*:*"
}

// PEM 密钥脱敏
func SensitizePEMKey(str string, prefixVisibleLen, suffixVisibleLen int) string {
	if isBlank(str) {
		return str
	}

	normalized := strings.TrimSpace(strings.ReplaceAll(str, "\r\n", "\n"))
	if normalized == "" {
		return str
	}

	// 只定位首尾两个换行，不切行也不拼接正文
	// 原实现是 Split 出整个行切片、Join 出正文、再 Join 出结果，三次中间分配，
	// 而正文在掩码后其实只剩「首若干字符 + 星号 + 末若干字符」，用不着先拼出来
	//
	// [EN] Locates only the first and last newline instead of splitting into a
	// line slice, joining the body and joining the result again — three
	// intermediate allocations for a body that, once masked, is just a few
	// leading runes, a run of stars and a few trailing ones
	firstNL := strings.IndexByte(normalized, '\n')
	lastNL := strings.LastIndexByte(normalized, '\n')
	// firstNL == lastNL 等价于原先的 len(lines) < 3（少于两个换行）
	if firstNL < 0 || firstNL == lastNL ||
		!strings.HasPrefix(normalized, "-----BEGIN ") ||
		!strings.HasPrefix(normalized[lastNL+1:], "-----END ") {
		return sensitizeSecretSegment(normalized, prefixVisibleLen, suffixVisibleLen)
	}

	header := normalized[:firstNL]
	bodyRegion := normalized[firstNL+1 : lastNL]
	footer := normalized[lastNL+1:]

	if prefixVisibleLen < 0 {
		prefixVisibleLen = 0
	}
	if suffixVisibleLen < 0 {
		suffixVisibleLen = 0
	}

	// 正文字符数按「去掉换行后」计，与原先先 Join 再数的结果一致
	bodyRunes := 0
	for _, r := range bodyRegion {
		if r != '\n' {
			bodyRunes++
		}
	}

	var b strings.Builder
	// 上界：掩码只会让字节数变少（多字节字符换成单字节星号）
	b.Grow(len(header) + len(footer) + len(bodyRegion) + 2)
	b.WriteString(header)
	b.WriteByte('\n')
	if prefixVisibleLen+suffixVisibleLen >= bodyRunes {
		for i := 0; i < bodyRunes; i++ {
			b.WriteByte('*')
		}
	} else {
		idx := 0
		for _, r := range bodyRegion {
			if r == '\n' {
				continue
			}
			if idx < prefixVisibleLen || idx >= bodyRunes-suffixVisibleLen {
				b.WriteRune(r)
			} else {
				b.WriteByte('*')
			}
			idx++
		}
	}
	b.WriteByte('\n')
	b.WriteString(footer)
	return b.String()
}

func sensitizeSecretSegment(secret string, prefixVisibleLen, suffixVisibleLen int) string {
	charCount := utf8.RuneCountInString(secret)
	if charCount == 0 {
		return secret
	}

	if prefixVisibleLen < 0 {
		prefixVisibleLen = 0
	}
	if suffixVisibleLen < 0 {
		suffixVisibleLen = 0
	}

	if prefixVisibleLen+suffixVisibleLen >= charCount {
		return strings.Repeat("*", charCount)
	}

	return hide(secret, prefixVisibleLen, charCount-suffixVisibleLen, charCount)
}
