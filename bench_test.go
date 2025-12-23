/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-12-22 11:08:52
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-12-23 11:52:30
 * @FilePath: \go-desensitize\bench_test.go
 * @Description: 常驻性能基准 - 覆盖三条入口与其组件
 *
 * 分四层，先整体后分解，这样退化能被归因而不只是被看见：
 *   1. 结构体 tag 驱动（Desensitization）—— 实际使用中最热，含并发
 *   2. 单值脱敏（Desensitize / OperateByRule）
 *   3. 报文脱敏（DataMasker）—— 命中与未命中分别测，后者才是日志场景的多数
 *   4. 组件（字段名判定 / 掩码追加器 / 字符串工具）—— 判断代价是否在自己手里
 *
 * 全部输入在计时区间外预构造，不让分配或类型装箱漏进测量
 * 判读时注意：并发基准若慢于同形态的顺序基准，说明有锁在串行化
 *
 * [EN] Four layers, whole-operation first then decomposed, so a regression can
 * be attributed rather than merely observed. Inputs are prepared outside the
 * timed region. A parallel benchmark slower than its sequential counterpart
 * means a lock is serialising the work
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package desensitize

import (
	"reflect"
	"strings"
	"testing"
)

// ==== 固定输入 | Fixtures ====

// benchMixed 贴近真实的用户模型：10 个字段，3 个带脱敏 tag
// 未打 tag 的字段占多数，这是实际形态，也是最容易被忽略的开销来源
type benchMixed struct {
	ID        uint64
	Name      string `desensitize:"name"`
	Email     string `desensitize:"email"`
	Phone     string `desensitize:"mobilePhone"`
	Nickname  string
	Age       int
	City      string
	Score     float64
	Active    bool
	CreatedAt string
}

// benchAllTagged 全字段带 tag，测脱敏本身的吞吐上限
type benchAllTagged struct {
	Name  string `desensitize:"name"`
	Email string `desensitize:"email"`
	Phone string `desensitize:"mobilePhone"`
	Card  string `desensitize:"bankCard"`
	Key   string `desensitize:"secret"`
}

// benchUntagged 全字段无 tag，测「什么都不用做」的纯开销
type benchUntagged struct {
	A, B, C, D, E string
	F, G, H       int
}

// benchNested 嵌套结构体与结构体切片，测递归下钻的代价
type benchNested struct {
	Head  benchAllTagged
	Items []benchAllTagged
	Plain string
}

func newBenchMixed() benchMixed {
	return benchMixed{
		ID: 10086, Name: "张三丰", Email: "zhangsanfeng@example.com",
		Phone: "18175698789", Nickname: "sanfeng", Age: 72,
		City: "武当山", Score: 99.5, Active: true, CreatedAt: "2025-12-22",
	}
}

func newBenchAllTagged() benchAllTagged {
	return benchAllTagged{
		Name: "张三丰", Email: "zhangsanfeng@example.com", Phone: "18175698789",
		Card: "6222025678565678", Key: "sk-abcdefghijklmnopqrstuvwxyz0123456789",
	}
}

func newBenchUntagged() benchUntagged {
	return benchUntagged{A: "a", B: "b", C: "c", D: "d", E: "e", F: 1, G: 2, H: 3}
}

func newBenchNested() benchNested {
	return benchNested{
		Head:  newBenchAllTagged(),
		Items: []benchAllTagged{newBenchAllTagged(), newBenchAllTagged(), newBenchAllTagged()},
		Plain: "untouched",
	}
}

var (
	benchJSONHit  = []byte(`{"user":"bob","password":"hunter2","token":"abc123","nested":{"secret":"s3cr3t","ok":1}}`)
	benchJSONMiss = []byte(`{"user":"bob","city":"wudang","age":72,"nested":{"score":99.5,"ok":1}}`)
	benchJSONArr  = []byte(`[{"user":"bob","password":"hunter2"},{"user":"amy","password":"s3cr3t"}]`)
	benchTextHit  = []byte(`GET /api?user=bob&password=hunter2&token=abc123 HTTP/1.1`)
	benchTextMiss = []byte(`GET /api?user=bob&city=wudang&age=72 HTTP/1.1`)
	benchBigMiss  = []byte(`{"data":"` + strings.Repeat("x", 4000) + `"}`)
	benchBigHit   = []byte(`{"data":"` + strings.Repeat("x", 4000) + `","password":"hunter2"}`)
)

// ==== 第 1 层：结构体 tag 驱动 ====

// BenchmarkDesensitization_Mixed 10 字段 3 个带 tag，最贴近真实用法
func BenchmarkDesensitization_Mixed(b *testing.B) {
	tmpl := newBenchMixed()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := tmpl
		if err := Desensitization(&v); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDesensitization_AllTagged 全字段带 tag
func BenchmarkDesensitization_AllTagged(b *testing.B) {
	tmpl := newBenchAllTagged()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := tmpl
		if err := Desensitization(&v); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDesensitization_Untagged 全字段无 tag
// 这条应当接近零成本：计划里没有任何字段，连一次脱敏都不该发生
func BenchmarkDesensitization_Untagged(b *testing.B) {
	tmpl := newBenchUntagged()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := tmpl
		if err := Desensitization(&v); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDesensitization_Nested 嵌套结构体与结构体切片的递归下钻
func BenchmarkDesensitization_Nested(b *testing.B) {
	tmpl := newBenchNested()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := tmpl
		v.Items = append([]benchAllTagged(nil), tmpl.Items...)
		if err := Desensitization(&v); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDesensitization_Mixed_Parallel 并发脱敏
// 注册表若用独占锁，这条会比顺序版本更慢，顺序基准看不出来
func BenchmarkDesensitization_Mixed_Parallel(b *testing.B) {
	tmpl := newBenchMixed()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			v := tmpl
			if err := Desensitization(&v); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkDesensitization_Untagged_Parallel 并发且无 tag
// 理想情况下完全不碰注册表，不该有任何争用
func BenchmarkDesensitization_Untagged_Parallel(b *testing.B) {
	tmpl := newBenchUntagged()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			v := tmpl
			if err := Desensitization(&v); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkPlanCache_Lookup 类型计划的命中查找，剥离脱敏本身的开销
func BenchmarkPlanCache_Lookup(b *testing.B) {
	t := reflect.TypeOf(benchMixed{})
	state := loadRegistry()
	_ = planFor(t, state)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if planFor(t, loadRegistry()) == nil {
			b.Fatal("nil plan")
		}
	}
}

// ==== 第 2 层：单值脱敏 ====

func BenchmarkDesensitize_Email(b *testing.B) {
	benchDesensitize(b, "zhangsanfeng@example.com", Email)
}

func BenchmarkDesensitize_MobilePhone(b *testing.B) {
	benchDesensitize(b, "18175698789", MobilePhone)
}

func BenchmarkDesensitize_IDCard(b *testing.B) {
	benchDesensitize(b, "310101199001015678", IDCard)
}

func BenchmarkDesensitize_BankCard(b *testing.B) {
	benchDesensitize(b, "6222025678565678", BankCard)
}

func BenchmarkDesensitize_Secret(b *testing.B) {
	benchDesensitize(b, "sk-abcdefghijklmnopqrstuvwxyz0123456789", Secret)
}

func BenchmarkDesensitize_ChineseName(b *testing.B) {
	benchDesensitize(b, "张三丰", ChineseName)
}

func BenchmarkDesensitize_Address(b *testing.B) {
	benchDesensitize(b, "北京市朝阳区某某路99号某某大厦18层", Address)
}

func BenchmarkDesensitize_PEMKey(b *testing.B) {
	benchDesensitize(b, "-----BEGIN RSA PRIVATE KEY-----\n"+strings.Repeat("MIIEowIBAAKCAQEA", 8)+"\n-----END RSA PRIVATE KEY-----", PEMKey)
}

// BenchmarkDesensitize_Unknown 未知类型走 default 分支，测纯分派开销
func BenchmarkDesensitize_Unknown(b *testing.B) {
	benchDesensitize(b, "abcdef", DesensitizeType(9999))
}

// benchDesensitize 单值脱敏基准的公共形状
func benchDesensitize(b *testing.B, in string, typ DesensitizeType) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if Desensitize(in, typ) == "" {
			b.Fatal("empty")
		}
	}
}

// BenchmarkOperateByRule_Plain 普通 tag，走注册表精确匹配
func BenchmarkOperateByRule_Plain(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := OperateByRule("email", "zhangsanfeng@example.com"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOperateByRule_Parameterized 带参数 tag，走标签解析 + 工厂
func BenchmarkOperateByRule_Parameterized(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := OperateByRule("jump(3,-4,1)", "18175698789"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOperateByRule_Unknown 未注册 tag，这是无 tag 字段实际走的路
func BenchmarkOperateByRule_Unknown(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := OperateByRule("", "value"); err == nil {
			b.Fatal("expected error")
		}
	}
}

// BenchmarkOperateByRule_Plain_Parallel 并发解析，暴露注册表锁的争用
func BenchmarkOperateByRule_Plain_Parallel(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := OperateByRule("email", "zhangsanfeng@example.com"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// ==== 第 3 层：报文脱敏 ====

func BenchmarkMask_JSONHit(b *testing.B) { benchMask(b, benchJSONHit) }

// BenchmarkMask_JSONMiss 没有敏感字段，理想情况下应比命中便宜
func BenchmarkMask_JSONMiss(b *testing.B) { benchMask(b, benchJSONMiss) }

// BenchmarkMask_JSONArray 数组形态，移植前这条根本走不到结构化脱敏
func BenchmarkMask_JSONArray(b *testing.B) { benchMask(b, benchJSONArr) }

func BenchmarkMask_TextHit(b *testing.B) { benchMask(b, benchTextHit) }

// BenchmarkMask_TextMiss 文本且无敏感字段，是日志场景的绝大多数
func BenchmarkMask_TextMiss(b *testing.B) { benchMask(b, benchTextMiss) }

// BenchmarkMask_BigMiss 4KB 无敏感字段报文
// 原实现为做存在性预筛要整体转小写复制一份，这条就是用来闸住那笔开销的
func BenchmarkMask_BigMiss(b *testing.B) { benchMask(b, benchBigMiss) }

// BenchmarkMask_BigHit 4KB 且含敏感字段
func BenchmarkMask_BigHit(b *testing.B) { benchMask(b, benchBigHit) }

// benchMask 报文脱敏基准的公共形状
func benchMask(b *testing.B, data []byte) {
	m := NewMasker()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if m.Mask(data) == "" {
			b.Fatal("empty")
		}
	}
}

// BenchmarkMask_TextMiss_Parallel 并发报文脱敏
// DataMasker 已无锁，这条应随核数线性扩展
func BenchmarkMask_TextMiss_Parallel(b *testing.B) {
	m := NewMasker()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if m.Mask(benchTextMiss) == "" {
				b.Fatal("empty")
			}
		}
	})
}

// BenchmarkMask_TextHit_Parallel 并发且命中
func BenchmarkMask_TextHit_Parallel(b *testing.B) {
	m := NewMasker()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if m.Mask(benchTextHit) == "" {
				b.Fatal("empty")
			}
		}
	})
}

// ==== 第 4 层：组件 ====

// BenchmarkActionForKey_Miss 业务字段名未命中，生产日志里的绝大多数
// 形状位图与后缀字典树就是为压低这条而存在的
func BenchmarkActionForKey_Miss(b *testing.B) {
	benchKeyAction(b, ActionForKey, "region", KeepAsIs)
}

// BenchmarkActionForKey_ExactHit 规范形态一次查表命中
func BenchmarkActionForKey_ExactHit(b *testing.B) {
	benchKeyAction(b, ActionForKey, "password", WipeValue)
}

// BenchmarkActionForKey_CamelHit 非规范形态，需退回栈上缓冲做一次归一化后重查
func BenchmarkActionForKey_CamelHit(b *testing.B) {
	benchKeyAction(b, ActionForKey, "accessToken", WipeValue)
}

// BenchmarkActionForKey_SuffixHit 精确表落空，由后缀字典树命中
func BenchmarkActionForKey_SuffixHit(b *testing.B) {
	benchKeyAction(b, ActionForKey, "stripe_secret", WipeValue)
}

// BenchmarkActionForKey_OpsVisible 命中后缀但被运维豁免压回
func BenchmarkActionForKey_OpsVisible(b *testing.B) {
	benchKeyAction(b, ActionForKey, "cache_key", KeepAsIs)
}

// BenchmarkActionForKeyLoose_Miss 宽松档未命中，要把每个结束位置都回溯一遍
// 这是宽松档的最坏情况，也是它比严格档贵的地方
func BenchmarkActionForKeyLoose_Miss(b *testing.B) {
	benchKeyAction(b, ActionForKeyLoose, "created_at_timestamp", KeepAsIs)
}

// BenchmarkActionForKeyLoose_EmbeddedHit 宽松档命中内部词根，严格档测不到
func BenchmarkActionForKeyLoose_EmbeddedHit(b *testing.B) {
	benchKeyAction(b, ActionForKeyLoose, "my_token_field", WipeValue)
}

// BenchmarkActionForKeyLoose_FastPath 严格档就能命中时宽松档不该有额外代价
func BenchmarkActionForKeyLoose_FastPath(b *testing.B) {
	benchKeyAction(b, ActionForKeyLoose, "password", WipeValue)
}

// benchKeyAction 字段名判定基准的公共形状，顺带断言判定结果不漂移
func benchKeyAction(b *testing.B, fn func(string) KeyAction, key string, want KeyAction) {
	if got := fn(key); got != want {
		b.Fatalf("字段 %q 判定为 %d，期望 %d", key, got, want)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fn(key)
	}
}

// BenchmarkAppendMaskedPhone 号码掩码追加到既有缓冲，应零分配
func BenchmarkAppendMaskedPhone(b *testing.B) {
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(AppendMaskedPhone(buf[:0], "+86 138-0013-8000")) == 0 {
			b.Fatal("empty")
		}
	}
}

// BenchmarkAppendMaskedEmail 邮箱掩码追加到既有缓冲，应零分配
func BenchmarkAppendMaskedEmail(b *testing.B) {
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(AppendMaskedEmail(buf[:0], "zhangsanfeng@example.com")) == 0 {
			b.Fatal("empty")
		}
	}
}

// BenchmarkMaskPhoneString 字符串形态，比追加器多一次分配
func BenchmarkMaskPhoneString(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if MaskPhoneString("13800138000") == "" {
			b.Fatal("empty")
		}
	}
}

func BenchmarkComponent_hide(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if hide("310101199001015678", 6, 14) == "" {
			b.Fatal("empty")
		}
	}
}

func BenchmarkComponent_padMiddle(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if padMiddle("1817789", 11) == "" {
			b.Fatal("empty")
		}
	}
}

func BenchmarkComponent_isBlank(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if isBlank("zhangsanfeng@example.com") {
			b.Fatal("not blank")
		}
	}
}

func BenchmarkComponent_containsFold(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !containsFold("UserPassWordField", "password") {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkComponent_parseParameterizedTag(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := parseParameterizedTag("jump(3,-4,1)"); !ok {
			b.Fatal("not parsed")
		}
	}
}

// BenchmarkComponent_parseParameterizedTag_Miss 普通 tag 也要先过一遍解析
func BenchmarkComponent_parseParameterizedTag_Miss(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := parseParameterizedTag("email"); ok {
			b.Fatal("unexpectedly parsed")
		}
	}
}
