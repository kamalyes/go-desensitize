/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-12-20 09:28:51
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-12-23 11:52:30
 * @FilePath: \go-desensitize\strutil_test.go
 * @Description: 内部字符串工具的测试与基准，含上游遗留的字节/字符索引混用行为
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package desensitize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBlank(t *testing.T) {
	for _, s := range []string{"", " ", "\t", "\n", "\r", " \t\n\r "} {
		assert.True(t, isBlank(s), "%q 应判为空", s)
	}
	for _, s := range []string{"a", " a ", "0", "\x00", "　"} { // 末项为全角空格，不在判定集内
		assert.False(t, isBlank(s), "%q 不应判为空", s)
	}
}

func TestRuneLenAndIndexOf(t *testing.T) {
	assert.Equal(t, 0, runeLen(""))
	assert.Equal(t, 3, runeLen("abc"))
	assert.Equal(t, 3, runeLen("张三丰"))
	assert.Equal(t, 2, runeLen("a🎉"))

	assert.Equal(t, 1, indexOf("abc", "b"))
	assert.Equal(t, -1, indexOf("abc", "z"))
	assert.Equal(t, 0, indexOf("abc", ""))
}

func TestCleanSpaces(t *testing.T) {
	assert.Equal(t, "abc", cleanSpaces("a b c"))
	assert.Equal(t, "abc", cleanSpaces("abc"), "无空格应原样返回")
	assert.Equal(t, "", cleanSpaces("   "))
	// 只过滤半角空格，制表与换行保留，与上游一致
	assert.Equal(t, "a\tb\nc", cleanSpaces("a\tb\nc"))
	assert.Equal(t, "张三丰", cleanSpaces("张 三 丰"))
}

func TestHide(t *testing.T) {
	assert.Equal(t, "a***e", hide("abcde", 1, 4))
	assert.Equal(t, "*****", hide("abcde", 0, 5))
	assert.Equal(t, "abcde", hide("abcde", 4, 1), "起点大于终点原样返回")
	// count <= 0 分支：起点等于终点，拼接两段即原串
	assert.Equal(t, "abcde", hide("abcde", 2, 2))
	// 负数起点夹到 0
	assert.Equal(t, "***de", hide("abcde", -3, 3))
	// 终点超过字节长度被夹到字节长度
	assert.Equal(t, "*****", hide("abcde", 0, 99))
	assert.Equal(t, "", hide("", 0, 0))
}

// TestHide_ByteVsRune 上游遗留的索引混用：边界按字节夹取，切片按字符
//
// 多字节输入下二者不一致，本库所有调用点都先把索引夹到字符数区间内，
// 因此走不到越界那条路这里把现状记录下来，以免日后「顺手修一下」而静默改变输出
func TestHide_ByteVsRune(t *testing.T) {
	// "张三丰" 字节长 9、字符数 3终点 5 不超过字节长度 9，故不被夹取，
	// 但按字符切片时 runes[5:] 会越界
	assert.Panics(t, func() { hide("张三丰", 0, 5) },
		"多字节输入下终点介于字符数与字节数之间会越界，这是上游既有行为")
	// 终点在字符数之内时正常
	assert.Equal(t, "*三丰", hide("张三丰", 0, 1))
}

func TestPadMiddle(t *testing.T) {
	assert.Equal(t, "abcde", padMiddle("abcde", 3), "已达长度原样返回")
	assert.Equal(t, "abcde", padMiddle("abcde", 5))
	// leftPadLen 下限被抬到 4
	assert.Equal(t, "1817****789", padMiddle("1817789", 11))
	assert.Equal(t, "hell*****o", padMiddle("hello", 10))
}

// TestPadMiddle_ShortInputPanics 上游遗留行为：短输入越界 panic
//
// leftPadLen 被强行抬到 4，而两段按字节切片，输入短于 4 字节即越界
// 记录为已知行为，调用方（SensitizePhoneNumber）需自行保证输入长度
func TestPadMiddle_ShortInputPanics(t *testing.T) {
	assert.Panics(t, func() { padMiddle("ab", 11) },
		"输入短于 4 字节时 s[:4] 越界，这是上游既有行为")
	assert.Panics(t, func() { padMiddle("a", 11) })
}

func TestSubBefore(t *testing.T) {
	assert.Equal(t, "192", subBefore("192.168.1.1", "."))
	assert.Equal(t, "2001", subBefore("2001:db8::1", ":"))
	assert.Equal(t, "noseparator", subBefore("noseparator", "."), "分隔符未出现原样返回")
	assert.Equal(t, "", subBefore(".leading", "."), "分隔符在开头返回空串")
	// 入参任一为空或全空白时原样返回
	assert.Equal(t, "", subBefore("", "."))
	assert.Equal(t, "  ", subBefore("  ", "."))
	assert.Equal(t, "a.b", subBefore("a.b", ""))
	assert.Equal(t, "a.b", subBefore("a.b", " "))
}
