/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2023-07-28 00:50:58
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-12-23 11:52:30
 * @FilePath: \go-desensitize\adapter_test.go
 * @Description: 脱敏器注册表、类型计划缓存、结构体 tag 驱动的测试与基准
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package desensitize

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 定义一个测试结构体
type TestJsonDesensitizationStruct struct {
	Email       string `desensitize:"email"`
	PhoneNumber string `desensitize:"phoneNumber"`
	Name        string `desensitize:"name"`
	Age         int
}

// 定义 ID 类脱敏测试结构体
type TestIDDesensitizationStruct struct {
	UserID     string `desensitize:"userId"`
	PlayerID   string `desensitize:"playerId"`
	OpenID     string `desensitize:"openId"`
	UnionID    string `desensitize:"unionId"`
	OrderNo    string `desensitize:"orderNo"`
	DeviceUUID string `desensitize:"uuid"`
	Account    string `desensitize:"account"`
}

// 自定义脱敏器示例
type MyCustomDesensitizer struct{}

func (d *MyCustomDesensitizer) Desensitize(value string) string {
	// 自定义脱敏逻辑
	return "*****" // 示例：返回固定的脱敏值
}

func init() {
	// 注册自定义脱敏器
	RegisterDesensitizer("myCustom", &MyCustomDesensitizer{})
}

func TestDesensitization(t *testing.T) {
	// 创建一个测试对象
	testObj := &TestJsonDesensitizationStruct{
		Email:       "test@example.com",
		PhoneNumber: "1234567890",
		Name:        "张三",
		Age:         30,
	}

	// 执行脱敏操作
	err := Desensitization(testObj)

	// 断言没有错误
	assert.NoError(t, err)

	// 断言脱敏后的结果
	assert.Equal(t, "t*st@example.com", testObj.Email)
	assert.Equal(t, "123****7890", testObj.PhoneNumber)
	assert.Equal(t, "张*", testObj.Name)
	assert.Equal(t, 30, testObj.Age) // 确保年龄没有被脱敏
}

func TestDesensitization_IDTypes(t *testing.T) {
	testObj := &TestIDDesensitizationStruct{
		UserID:     "1000234567",
		PlayerID:   "P202400123",
		OpenID:     "o6_bmjrPTlm6_2sgVt7hMZ3",
		UnionID:    "o6_bmjrPTlm6_2sgVt7hMZ3fQ",
		OrderNo:    "ORD2024010112345",
		DeviceUUID: "550e8400-e29b-41d4-a716-446655440000",
		Account:    "zhangsan",
	}

	err := Desensitization(testObj)

	assert.NoError(t, err)
	assert.Equal(t, "10******67", testObj.UserID)
	assert.Equal(t, "P2******23", testObj.PlayerID)
	assert.Equal(t, "o6"+strings.Repeat("*", 19)+"Z3", testObj.OpenID)
	assert.Equal(t, "o6"+strings.Repeat("*", 21)+"fQ", testObj.UnionID)
	assert.Equal(t, "OR************45", testObj.OrderNo)
	assert.Equal(t, "55"+strings.Repeat("*", 32)+"00", testObj.DeviceUUID)
	assert.Equal(t, "zh****an", testObj.Account)
}

// 定义跳步脱敏测试结构体
type TestJumpDesensitizationStruct struct {
	Phone   string `desensitize:"jump(3,-4,1)"`   // 等价手机号脱敏：保留前 3 后 4
	Serial  string `desensitize:"jump(0,-2,2)"`   // 从头隔位掩码，保留末尾 2 位
	Fixed   string `desensitize:"jump(1,4)"`      // 固定区间 [1,4)，跳步默认 1
	Default string `desensitize:"jump"`           // 默认从头到尾连续掩码
	Spaced  string `desensitize:"jump(2, -3, 2)"` // 支持参数间空格
	Chinese string `desensitize:"jump(1,-1,1)"`   // 中文内容按字符计数
	Empty   string `desensitize:"jump()"`         // 空参数使用默认值
}

func TestDesensitization_Jump(t *testing.T) {
	testObj := &TestJumpDesensitizationStruct{
		Phone:   "18175698789",
		Serial:  "ABCDEFGHIJ",
		Fixed:   "123456789",
		Default: "secret",
		Spaced:  "1357924680",
		Chinese: "北京市朝阳区",
		Empty:   "abcdef",
	}

	err := Desensitization(testObj)

	assert.NoError(t, err)
	assert.Equal(t, "181****8789", testObj.Phone)
	assert.Equal(t, "*B*D*F*HIJ", testObj.Serial)
	assert.Equal(t, "1***56789", testObj.Fixed)
	assert.Equal(t, "******", testObj.Default)
	assert.Equal(t, "13*7*2*680", testObj.Spaced)
	assert.Equal(t, "北****区", testObj.Chinese)
	assert.Equal(t, "******", testObj.Empty)
}

func TestDesensitization_JumpInvalid(t *testing.T) {
	// 未注册的参数化脱敏器和非法参数：字段均保持原值
	type TestJumpInvalidStruct struct {
		Unknown string `desensitize:"jumpUnknown(1,2)"`
		BadArg  string `desensitize:"jump(1,abc)"`
	}

	testObj := &TestJumpInvalidStruct{
		Unknown: "10",
		BadArg:  "20",
	}

	err := Desensitization(testObj)
	assert.NoError(t, err)
	assert.Equal(t, "10", testObj.Unknown)
	assert.Equal(t, "20", testObj.BadArg)
}

func TestDesensitization_NonStruct(t *testing.T) {
	// 测试非结构体输入
	err := Desensitization("not a struct")
	assert.Error(t, err)
	assert.Equal(t, "expected a non-nil pointer to a struct", err.Error())
}

func TestDesensitization_EmptyDesensitizer(t *testing.T) {
	// 测试未注册脱敏器的情况
	type TestEmptyDesensitizerStruct struct {
		A string `desensitize:"abc"`
	}

	testObj := &TestEmptyDesensitizerStruct{
		A: "10",
	}

	err := Desensitization(testObj)
	assert.NoError(t, err)           // 不会报错
	assert.Equal(t, "10", testObj.A) // 应保持原值
}

func TestDesensitization_CustomDesensitizer(t *testing.T) {
	// 定义一个测试结构体，使用自定义脱敏器
	type TestCustomDesensitizationStruct struct {
		SecretField string `desensitize:"myCustom"`
	}

	// 创建一个测试对象
	testObj := &TestCustomDesensitizationStruct{
		SecretField: "SensitiveData",
	}

	// 执行脱敏操作
	err := Desensitization(testObj)

	// 断言没有错误
	assert.NoError(t, err)

	// 断言脱敏后的结果
	assert.Equal(t, "*****", testObj.SecretField) // 应该被自定义脱敏器处理
}

func TestDesensitization_Slice(t *testing.T) {
	// 定义一个包含切片的结构体
	type TestSliceStruct struct {
		Emails []string `desensitize:"email"`
	}

	testObj := &TestSliceStruct{
		Emails: []string{"user123@example.com", "a123568@example.com"},
	}

	err := Desensitization(testObj)
	assert.NoError(t, err)

	expectedEmails := []string{"u****23@example.com", "a****68@example.com"}
	assert.Equal(t, expectedEmails, testObj.Emails)
}

func TestDesensitization_Array(t *testing.T) {
	// 定义一个包含数组的结构体
	type TestArrayStruct struct {
		PhoneNumbers [2]string `desensitize:"phoneNumber"`
	}

	testObj := &TestArrayStruct{
		PhoneNumbers: [2]string{"1234567890", "0987654321"},
	}

	err := Desensitization(testObj)
	assert.NoError(t, err)

	expectedPhoneNumbers := [2]string{"123****7890", "098****4321"}
	assert.Equal(t, expectedPhoneNumbers, testObj.PhoneNumbers)
}

func TestDesensitization_Map(t *testing.T) {
	// 定义一个包含映射的结构体
	type TestMapStruct struct {
		Contacts map[string]string `desensitize:"phoneNumber"`
	}

	testObj := &TestMapStruct{
		Contacts: map[string]string{
			"John": "1234567890",
			"Jane": "098321",
		},
	}

	err := Desensitization(testObj)
	assert.NoError(t, err)

	expectedContacts := map[string]string{
		"John": "123****7890",
		"Jane": "098******21",
	}
	assert.Equal(t, expectedContacts, testObj.Contacts)
}

func TestDesensitization_ComplexStruct(t *testing.T) {

	// 定义嵌套结构体
	type Other struct {
		PhoneNumber string `desensitize:"phoneNumber"`
	}

	type UserProfile struct {
		Username string `desensitize:"name"`
		Email    string `desensitize:"email"`
		Other    Other
	}

	// 定义包含用户资料的复合结构体
	type ComplexStruct struct {
		Profiles []UserProfile
		Names    map[string]string `desensitize:"name"`
	}

	// 创建一个复杂结构体的测试对象
	testObj := &ComplexStruct{
		Profiles: []UserProfile{
			{
				Username: "jo",
				Email:    "john@example.com",
				Other: Other{
					PhoneNumber: "18169967587",
				},
			},
			{
				Username: "jane_doe",
				Email:    "ane12368@example.com",
				Other: Other{
					PhoneNumber: "18199687567",
				},
			},
		},
		Names: map[string]string{
			"theme": "dark",
			"lang":  "en",
		},
	}

	// 执行脱敏操作
	err := Desensitization(testObj)

	// 断言没有错误
	assert.NoError(t, err)

	// 断言脱敏后的结果
	assert.Equal(t, "j*", testObj.Profiles[0].Username)
	assert.Equal(t, "j*hn@example.com", testObj.Profiles[0].Email)
	assert.Equal(t, "181****7587", testObj.Profiles[0].Other.PhoneNumber)

	assert.Equal(t, "j***_doe", testObj.Profiles[1].Username)
	assert.Equal(t, "a*****68@example.com", testObj.Profiles[1].Email)
	assert.Equal(t, "181****7567", testObj.Profiles[1].Other.PhoneNumber)

	// Settings 应该保持原值，因为没有注册脱敏器
	assert.Equal(t, "d*rk", testObj.Names["theme"])
	assert.Equal(t, "e*", testObj.Names["lang"])
}

// upperDesensitizer 测试用自定义脱敏器
type upperDesensitizer struct{}

func (upperDesensitizer) Desensitize(v string) string { return strings.ToUpper(v) }

func TestOperateByRule(t *testing.T) {
	v, err := OperateByRule("email", "zhangsanfeng@example.com")
	assert.NoError(t, err)
	assert.Equal(t, "z*********ng@example.com", v)

	// 带参数形式
	v, err = OperateByRule("jump(0,0,2)", "abcdef")
	assert.NoError(t, err)
	assert.Equal(t, "*b*d*f", v)

	// 无参数形式走工厂默认值
	_, err = OperateByRule("jump", "abcdef")
	assert.NoError(t, err)

	// 未注册的普通名称
	_, err = OperateByRule("nope", "x")
	assert.ErrorIs(t, err, errDesensitizerNotFound)

	// 带参数但工厂未注册
	_, err = OperateByRule("unknownfactory(1,2)", "x")
	assert.ErrorIs(t, err, errFactoryNotFound)

	// 参数非整数视为非法标签，退回普通名称查找
	_, err = OperateByRule("jump(bad)", "x")
	assert.ErrorIs(t, err, errDesensitizerNotFound)
}

func TestRegisterDesensitizerFactory(t *testing.T) {
	RegisterDesensitizerFactory("testupper", func(params ...int) Desensitizer {
		return upperDesensitizer{}
	})

	v, err := OperateByRule("testupper(1,2,3)", "abc")
	assert.NoError(t, err)
	assert.Equal(t, "ABC", v)

	// 无括号形式也应通过工厂默认参数命中
	v, err = OperateByRule("testupper", "abc")
	assert.NoError(t, err)
	assert.Equal(t, "ABC", v)
}

func TestParseParameterizedTag(t *testing.T) {
	cases := []struct {
		tag    string
		name   string
		params []int
		ok     bool
	}{
		{"jump(3,-4,1)", "jump", []int{3, -4, 1}, true},
		{"jump()", "jump", nil, true},
		{"jump(3)", "jump", []int{3}, true},
		{"jump( 2 , -2 )", "jump", []int{2, -2}, true},
		{"email", "", nil, false},
		{"", "", nil, false},
		{"(3)", "", nil, false},
		{"jump(3", "", nil, false},
		{"jump3)", "", nil, false},
		{"jump(bad)", "", nil, false},
		{"jump(1,bad)", "", nil, false},
		{"ju mp(1)", "", nil, false},
		{"ju,mp(1)", "", nil, false},
		{"ju(mp(1)", "", nil, false},
		{"jump(1))", "", nil, false},
	}
	for _, c := range cases {
		t.Run(c.tag, func(t *testing.T) {
			name, params, ok := parseParameterizedTag(c.tag)
			assert.Equal(t, c.ok, ok)
			assert.Equal(t, c.name, name)
			assert.Equal(t, c.params, params)
		})
	}
}

// tagMisuseModel tag 与字段类型不匹配
type tagMisuseModel struct {
	Age int `desensitize:"name"`
}

// tagMisuseSlice 切片元素不是字符串
type tagMisuseSlice struct {
	Nums []int `desensitize:"name"`
}

// tagMisuseMap 映射值不是字符串
type tagMisuseMap struct {
	M map[string]int `desensitize:"name"`
}

func TestTagMisuseError(t *testing.T) {
	var v tagMisuseModel
	err := Desensitization(&v)
	assert.Error(t, err)

	var misuse *TagMisuseError
	assert.True(t, errors.As(err, &misuse))
	assert.Equal(t, "Age", misuse.Field)
	assert.Equal(t, "name", misuse.Tag)
	assert.Equal(t, "int", misuse.Type)
	assert.Contains(t, misuse.Error(), "要求字符串字段")
	assert.Contains(t, misuse.Error(), "Age")

	// 重复调用应返回同样的错误（计划已缓存）
	assert.Error(t, Desensitization(&v))

	assert.Error(t, Desensitization(&tagMisuseSlice{Nums: []int{1}}))
	assert.Error(t, Desensitization(&tagMisuseMap{M: map[string]int{"a": 1}}))
}

// namedString 命名字符串类型，Kind 为 String 故应可用
type namedString string

type namedStringModel struct {
	N namedString `desensitize:"name"`
}

func TestNamedStringTypeWorks(t *testing.T) {
	v := namedStringModel{N: "张三丰"}
	assert.NoError(t, Desensitization(&v))
	assert.Equal(t, namedString("张**"), v.N)
}

// namedSliceModel 命名字符串类型的切片与映射
type namedSliceModel struct {
	S []namedString          `desensitize:"name"`
	M map[string]namedString `desensitize:"name"`
}

func TestNamedStringCollections(t *testing.T) {
	v := namedSliceModel{
		S: []namedString{"张三丰"},
		M: map[string]namedString{"k": "张三丰"},
	}
	assert.NoError(t, Desensitization(&v))
	assert.Equal(t, namedString("张**"), v.S[0])
	assert.Equal(t, namedString("张**"), v.M["k"])
}

func TestDesensitization_InvalidInput(t *testing.T) {
	assert.Error(t, Desensitization(nil))
	assert.Error(t, Desensitization(tagMisuseModel{}), "非指针应报错")

	var p *tagMisuseModel
	assert.Error(t, Desensitization(p), "nil 指针应报错")

	s := "x"
	assert.Error(t, Desensitization(&s), "非结构体指针应报错而非 panic")
}

// lateModel 验证「先用后注册」：计划缓存必须随注册表代数失效
type lateModel struct {
	F string `desensitize:"testlate"`
}

func TestPlanCacheInvalidatedByRegistration(t *testing.T) {
	v := lateModel{F: "abc"}
	assert.NoError(t, Desensitization(&v))
	assert.Equal(t, "abc", v.F, "注册前未命中任何脱敏器，应原样保留")

	RegisterDesensitizer("testlate", upperDesensitizer{})

	v2 := lateModel{F: "abc"}
	assert.NoError(t, Desensitization(&v2))
	assert.Equal(t, "ABC", v2.F, "注册后必须对已缓存类型生效")
}

// nestedModel 嵌套结构体、结构体切片、不可导出字段
type innerModel struct {
	Secret string `desensitize:"secret"`
}

type nestedModel struct {
	Inner  innerModel
	Items  []innerModel
	Arr    [1]innerModel
	Plain  string
	hidden string `desensitize:"name"`
}

func TestDesensitization_Nested(t *testing.T) {
	v := nestedModel{
		Inner:  innerModel{Secret: "0123456789abcdef"},
		Items:  []innerModel{{Secret: "0123456789abcdef"}},
		Arr:    [1]innerModel{{Secret: "0123456789abcdef"}},
		Plain:  "untouched",
		hidden: "张三丰",
	}
	assert.NoError(t, Desensitization(&v))
	assert.Contains(t, v.Inner.Secret, "*")
	assert.Contains(t, v.Items[0].Secret, "*")
	assert.Contains(t, v.Arr[0].Secret, "*")
	assert.Equal(t, "untouched", v.Plain)
	assert.Equal(t, "张三丰", v.hidden, "不可导出字段不应被改写")
}

// TestDesensitization_Concurrent 并发脱敏期间穿插注册，验证写时拷贝的安全性
func TestDesensitization_Concurrent(t *testing.T) {
	type model struct {
		Name  string `desensitize:"name"`
		Email string `desensitize:"email"`
	}

	var wg sync.WaitGroup
	for w := 0; w < 12; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				v := model{Name: "张三丰", Email: "zhangsanfeng@example.com"}
				if err := Desensitization(&v); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	// 并发注册，迫使计划缓存反复失效重建
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			RegisterDesensitizer("churn", upperDesensitizer{})
		}
	}()
	wg.Wait()
}

func TestDefaultDesensitizer(t *testing.T) {
	d := &DefaultDesensitizer{Email}
	assert.Equal(t, "z*********ng@example.com", d.Desensitize("zhangsanfeng@example.com"))
}

func TestNewJumpDesensitizer(t *testing.T) {
	assert.Equal(t, "******", NewJumpDesensitizer().Desensitize("abcdef"))
	assert.Equal(t, "ab****", NewJumpDesensitizer(2).Desensitize("abcdef"))
	assert.Equal(t, "ab**ef", NewJumpDesensitizer(2, -2).Desensitize("abcdef"))
	assert.Equal(t, "ab*d*f", NewJumpDesensitizer(2, 0, 2).Desensitize("abcdef"))
}

// badTagInner tag 与类型不匹配的内嵌结构体
type badTagInner struct {
	Age int `desensitize:"name"`
}

// badTagOuterStruct 结构体字段的类型本身有 tag 用法错误
type badTagOuterStruct struct {
	Inner badTagInner
}

// badTagOuterSlice 结构体切片的元素类型有 tag 用法错误
type badTagOuterSlice struct {
	Items []badTagInner
}

// TestTagMisuseError_PropagatesFromNested 嵌套层的 tag 错误要向上冒泡
// 否则外层看起来成功，而内层字段根本没被处理
func TestTagMisuseError_PropagatesFromNested(t *testing.T) {
	err := Desensitization(&badTagOuterStruct{})
	assert.Error(t, err, "结构体字段的内层错误应冒泡")
	var misuse *TagMisuseError
	assert.True(t, errors.As(err, &misuse))
	assert.Equal(t, "Age", misuse.Field)

	err = Desensitization(&badTagOuterSlice{Items: []badTagInner{{Age: 1}}})
	assert.Error(t, err, "结构体切片元素的错误应冒泡")
	assert.True(t, errors.As(err, &misuse))
}

// TestLoadRegistry_LazyInit 注册表未初始化时按需重建
//
// 懒初始化是为了不依赖同包 init() 的文件名顺序（cipher.go 的 init 也要注册），
// 这条用例把快照清空来走那条分支，并在结束时复原，避免影响其它用例
func TestLoadRegistry_LazyInit(t *testing.T) {
	prev := registry.Load()
	require.NotNil(t, prev)
	t.Cleanup(func() { registry.Store(prev) })

	registry.Store(nil)
	state := loadRegistry()
	require.NotNil(t, state, "快照为空时必须重建而不是返回 nil")
	assert.NotEmpty(t, state.byName, "重建出的快照应含内置脱敏器")
	assert.Contains(t, state.byName, "email")
	assert.Contains(t, state.factories, "jump")

	// 重建后仍可正常脱敏
	assert.Equal(t, "张**", Desensitize("张三丰", ChineseName))
}

// ==== 复杂形态 | Complex shapes ====

// 贴近真实的电商订单模型：五层嵌套、七种 tag 混用、指针与集合交织
type cxContact struct {
	RealName string            `desensitize:"name"`
	Phone    string            `desensitize:"mobilePhone"`
	Email    string            `desensitize:"email"`
	Extra    map[string]string `desensitize:"name"`
	Labels   []string          `desensitize:"name"`
	Zone     string            // 无 tag，必须原样
}

type cxAddress struct {
	Contact  cxContact
	Province string
	Detail   string `desensitize:"address"`
	Postcode string
}

type cxPayment struct {
	Card   string `desensitize:"bankCard"`
	Secret string `desensitize:"secret"`
	Jumped string `desensitize:"jump(2,-2,2)"`
	Amount int64
}

type cxItem struct {
	SKU      string
	Note     string `desensitize:"name"`
	Shipping cxAddress
}

type cxOrder struct {
	OrderNo  string `desensitize:"orderNo"`
	Buyer    cxContact
	Billing  *cxAddress
	NilAddr  *cxAddress
	Items    []cxItem
	Fixed    [2]cxItem
	Payment  cxPayment
	Audit    map[string]string `desensitize:"secret"`
	Internal string
	hidden   string `desensitize:"name"`
}

func newCxOrder() cxOrder {
	contact := func() cxContact {
		return cxContact{
			RealName: "张三丰",
			Phone:    "18175698789",
			Email:    "zhangsanfeng@example.com",
			Extra:    map[string]string{"emergency": "李四娘", "backup": "王五"},
			Labels:   []string{"赵六", "孙七"},
			Zone:     "CN-SH",
		}
	}
	addr := func() cxAddress {
		return cxAddress{
			Contact:  contact(),
			Province: "上海市",
			Detail:   "浦东新区张江路99号某某大厦18层",
			Postcode: "201203",
		}
	}
	item := func(sku string) cxItem {
		return cxItem{SKU: sku, Note: "周八", Shipping: addr()}
	}
	billing := addr()
	return cxOrder{
		OrderNo: "1234567890123456",
		Buyer:   contact(),
		Billing: &billing,
		Items:   []cxItem{item("SKU-1"), item("SKU-2"), item("SKU-3")},
		Fixed:   [2]cxItem{item("FIX-1"), item("FIX-2")},
		Payment: cxPayment{
			Card:   "6222025678565678",
			Secret: "sk-abcdefghijklmnopqrstuvwxyz0123456789",
			Jumped: "ABCDEFGHIJ",
			Amount: 19900,
		},
		Audit:    map[string]string{"op": "s3cr3tvalue", "by": "anothersecret"},
		Internal: "internal-note",
		hidden:   "张三丰",
	}
}

// assertContactMasked 校验一个联系人结构体的每个字段都按各自 tag 处理过
func assertContactMasked(t *testing.T, c cxContact, where string) {
	t.Helper()
	assert.Equal(t, "张**", c.RealName, "%s: 姓名", where)
	assert.Equal(t, "181****8789", c.Phone, "%s: 手机号", where)
	assert.Equal(t, "z*********ng@example.com", c.Email, "%s: 邮箱", where)
	assert.Equal(t, "李**", c.Extra["emergency"], "%s: 映射值", where)
	assert.Equal(t, "王*", c.Extra["backup"], "%s: 映射值", where)
	assert.Equal(t, []string{"赵*", "孙*"}, c.Labels, "%s: 切片元素", where)
	assert.Equal(t, "CN-SH", c.Zone, "%s: 无 tag 字段必须原样", where)
}

// TestDesensitization_DeeplyNestedOrder 五层嵌套、七种 tag 混用的完整校验
//
// 逐字段断言而非只看「含 *」：只校验含星号的话，错配的 tag、漏处理的集合元素、
// 被误改的无 tag 字段全都查不出来
func TestDesensitization_DeeplyNestedOrder(t *testing.T) {
	v := newCxOrder()
	require.NoError(t, Desensitization(&v))

	// 顶层
	assert.Equal(t, "12************56", v.OrderNo)
	assert.Equal(t, "internal-note", v.Internal, "无 tag 字段必须原样")
	assert.Equal(t, "张三丰", v.hidden, "不可导出字段必须原样")

	// 第二层：买家联系人
	assertContactMasked(t, v.Buyer, "Buyer")

	// 指针字段下钻，以及它内部的第三层联系人
	require.NotNil(t, v.Billing)
	assert.Contains(t, v.Billing.Detail, "*", "Billing 地址")
	assert.Equal(t, "上海市", v.Billing.Province, "Billing 无 tag 字段")
	assert.Equal(t, "201203", v.Billing.Postcode)
	assertContactMasked(t, v.Billing.Contact, "Billing.Contact")

	assert.Nil(t, v.NilAddr, "nil 指针不得被解引用或赋值")

	// 结构体切片的每个元素都要下钻到第四层
	require.Len(t, v.Items, 3)
	for i, item := range v.Items {
		assert.Equal(t, []string{"SKU-1", "SKU-2", "SKU-3"}[i], item.SKU, "SKU 无 tag")
		assert.Equal(t, "周*", item.Note, "Items[%d].Note", i)
		assert.Contains(t, item.Shipping.Detail, "*", "Items[%d] 地址", i)
		assertContactMasked(t, item.Shipping.Contact, "Items["+item.SKU+"].Shipping.Contact")
	}

	// 定长数组同样要逐元素下钻
	for i, item := range v.Fixed {
		assert.Equal(t, "周*", item.Note, "Fixed[%d].Note", i)
		assertContactMasked(t, item.Shipping.Contact, "Fixed.Shipping.Contact")
	}

	// 支付信息：三种不同算法共存
	assert.Equal(t, "6222 **** **** **** 5678", v.Payment.Card)
	assert.True(t, strings.HasPrefix(v.Payment.Secret, "sk-a"), "密钥保留前缀")
	assert.True(t, strings.HasSuffix(v.Payment.Secret, "6789"), "密钥保留后缀")
	assert.Contains(t, v.Payment.Secret, "*")
	// end 为开区间：-2 换算为 8，故掩码下标 2、4、6，下标 8 不在范围内
	assert.Equal(t, "AB*D*F*HIJ", v.Payment.Jumped, "跳步脱敏按步长掩码")
	assert.Equal(t, int64(19900), v.Payment.Amount, "非字符串字段必须原样")

	// 顶层映射
	assert.Contains(t, v.Audit["op"], "*")
	assert.NotEqual(t, "s3cr3tvalue", v.Audit["op"])
	assert.NotEqual(t, "anothersecret", v.Audit["by"])
}

// TestDesensitize_Idempotency 哪些类型可以重复脱敏，哪些不行
//
// 实测 12 个内置类型里 11 个幂等：它们按位置掩码且不改变长度，
// 第二遍算出同样的区间、写入同样的星号
// 唯一例外是 BankCard —— 它会插入分组空格并按目标长度重新补位，
// 于是每跑一遍都变长（16 位卡号第二遍多出一组 ****）
//
// 这件事对接入者是实际风险：中间件和仓储层各脱一次很常见，
// 对 BankCard 就会产出越来越长的垃圾
//
// [EN] Eleven of the twelve built-in types are idempotent: they mask by
// position without changing length, so a second pass computes the same range.
// BankCard is the exception — it inserts grouping spaces and re-pads to a
// target length, growing on every pass. This matters in practice, because
// masking once in middleware and again in the repository layer is common
func TestDesensitize_Idempotency(t *testing.T) {
	idempotent := []struct {
		name string
		typ  DesensitizeType
		in   string
	}{
		{"ChineseName", ChineseName, "张三丰李四王五"},
		{"IDCard", IDCard, "310101199001015678"},
		{"MobilePhone", MobilePhone, "18175698789"},
		{"PhoneNumber", PhoneNumber, "18175698789"},
		{"Email", Email, "zhangsanfeng@example.com"},
		{"Secret", Secret, "sk-abcdefghijklmnopqrstuvwxyz"},
		{"Address", Address, "北京市朝阳区某某路99号"},
		{"IPV4", IPV4, "192.168.1.1"},
		{"CarLicense", CarLicense, "京A12345"},
		{"Password", Password, "hunter2"},
		{"UserID", UserID, "1234567890"},
	}
	for _, c := range idempotent {
		t.Run(c.name, func(t *testing.T) {
			first := Desensitize(c.in, c.typ)
			second := Desensitize(first, c.typ)
			assert.Equal(t, first, second, "%s 应当幂等，重复脱敏结果须一致", c.name)
		})
	}

	t.Run("BankCard 不幂等", func(t *testing.T) {
		first := Desensitize("6222025678565678", BankCard)
		second := Desensitize(first, BankCard)
		assert.Equal(t, "6222 **** **** **** 5678", first)
		assert.Equal(t, "6222 **** **** **** **** 5678", second,
			"BankCard 每遍都会插入分组空格并重新补位，因此越跑越长")
		assert.NotEqual(t, first, second)
	})
}

// TestDesensitization_UnicodeHeavy 多字节与组合字符不得被截断成非法 UTF-8
func TestDesensitization_UnicodeHeavy(t *testing.T) {
	type one struct {
		Name  string `desensitize:"name"`
		Email string `desensitize:"email"`
		Addr  string `desensitize:"address"`
	}
	cases := []one{
		{Name: "張三丰", Email: "張三丰@例子.中国", Addr: "台北市信義區松高路11號"},
		{Name: "🎉派对🎊", Email: "🎉party@example.com", Addr: "🏠家🏡住址🏘"},
		{Name: "José", Email: "josé@example.com", Addr: "Calle Ñ 42"},
		{Name: "АБВ", Email: "абв@example.com", Addr: "Улица Ленина 1"},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			v := c
			require.NoError(t, Desensitization(&v))
			for _, got := range []string{v.Name, v.Email, v.Addr} {
				assert.True(t, utf8.ValidString(got), "输出必须是合法 UTF-8：%q", got)
			}
		})
	}
}

// TestDesensitization_ConcurrentMixedTypes 多类型并发脱敏，期间穿插注册
//
// 同时施压三件事：类型计划缓存的并发命中、注册导致的代数失效重建、
// 以及不同类型对之间不会互相污染计划
func TestDesensitization_ConcurrentMixedTypes(t *testing.T) {
	type a struct {
		Name string `desensitize:"name"`
	}
	type b struct {
		Phone string `desensitize:"mobilePhone"`
		Email string `desensitize:"email"`
	}
	type c struct {
		Plain string
	}

	var wg sync.WaitGroup
	errs := make(chan error, 64)

	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				va := a{Name: "张三丰"}
				if err := Desensitization(&va); err != nil {
					errs <- err
					return
				}
				if va.Name != "张**" {
					errs <- errors.New("类型 a 结果不对: " + va.Name)
					return
				}

				vb := b{Phone: "18175698789", Email: "zhangsanfeng@example.com"}
				if err := Desensitization(&vb); err != nil {
					errs <- err
					return
				}
				if vb.Phone != "181****8789" {
					errs <- errors.New("类型 b 结果不对: " + vb.Phone)
					return
				}

				vc := c{Plain: "untouched"}
				if err := Desensitization(&vc); err != nil {
					errs <- err
					return
				}
				if vc.Plain != "untouched" {
					errs <- errors.New("无 tag 类型被改动")
					return
				}

				vo := newCxOrder()
				if err := Desensitization(&vo); err != nil {
					errs <- err
					return
				}
			}
		}()
	}

	// 并发注册，迫使计划缓存反复失效重建
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			RegisterDesensitizer("churn-complex", upperDesensitizer{})
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestDesensitization_PointerShapes 指针形态的下钻与 nil 保护
//
// 这些形状在上游原实现里被整体跳过，嵌套数据从未脱敏，属于静默漏擦
func TestDesensitization_PointerShapes(t *testing.T) {
	type inner struct {
		Name string `desensitize:"name"`
	}
	type holder struct {
		Ptr     *inner
		NilPtr  *inner
		PtrSl   []*inner
		PtrArr  [2]*inner
		WithNil []*inner
		// 带 tag 的结构体指针：tag 被忽略，按结构体规则递归，与值类型一致
		Tagged *inner `desensitize:"name"`
	}

	v := holder{
		Ptr:     &inner{Name: "张三丰"},
		PtrSl:   []*inner{{Name: "李四娘"}, {Name: "王五郎"}},
		PtrArr:  [2]*inner{{Name: "赵六"}, {Name: "孙七"}},
		WithNil: []*inner{{Name: "周八"}, nil},
		Tagged:  &inner{Name: "吴九"},
	}
	require.NoError(t, Desensitization(&v))

	assert.Equal(t, "张**", v.Ptr.Name, "结构体指针应下钻")
	assert.Nil(t, v.NilPtr, "nil 指针不得被解引用或赋值")
	assert.Equal(t, "李**", v.PtrSl[0].Name, "指针切片元素应下钻")
	assert.Equal(t, "王**", v.PtrSl[1].Name)
	assert.Equal(t, "赵*", v.PtrArr[0].Name, "指针数组元素应下钻")
	assert.Equal(t, "孙*", v.PtrArr[1].Name)
	assert.Equal(t, "周*", v.WithNil[0].Name)
	assert.Nil(t, v.WithNil[1], "切片里的 nil 元素须跳过而非 panic")
	assert.Equal(t, "吴*", v.Tagged.Name, "带 tag 的结构体指针按结构体规则递归")
}

// TestTagMisuseError_PropagatesFromPointerShapes 指针形态里的 tag 错误同样要冒泡
func TestTagMisuseError_PropagatesFromPointerShapes(t *testing.T) {
	type holder struct {
		Ptr *badTagInner
	}
	type sliceHolder struct {
		Items []*badTagInner
	}

	err := Desensitization(&holder{Ptr: &badTagInner{}})
	assert.Error(t, err, "结构体指针内层的 tag 错误应冒泡")
	var misuse *TagMisuseError
	assert.True(t, errors.As(err, &misuse))
	assert.Equal(t, "Age", misuse.Field)

	err = Desensitization(&sliceHolder{Items: []*badTagInner{{}}})
	assert.Error(t, err, "指针切片元素的 tag 错误应冒泡")
	assert.True(t, errors.As(err, &misuse))

	// nil 元素先被跳过，不触发错误
	assert.NoError(t, Desensitization(&sliceHolder{Items: []*badTagInner{nil}}))
	assert.NoError(t, Desensitization(&holder{}))
}

// TestDesensitization_NonStructPointerField 指向非结构体的指针仍按 tag 用法错误处理
func TestDesensitization_NonStructPointerField(t *testing.T) {
	type holder struct {
		P *string `desensitize:"name"`
	}
	s := "张三丰"
	err := Desensitization(&holder{P: &s})
	assert.Error(t, err, "脱敏器只接受字符串，*string 属 tag 用法错误")
	var misuse *TagMisuseError
	assert.True(t, errors.As(err, &misuse))
	assert.Equal(t, "*string", misuse.Type)
}

// TestNewDefaultDesensitizer 把内置类型注册到自定义 tag 名下
//
// 包外无法写 &DefaultDesensitizer{...}（字段不导出），所以这个构造函数是
// 「用内置算法 + 自定义 tag 名」的唯一入口
func TestNewDefaultDesensitizer(t *testing.T) {
	d := NewDefaultDesensitizer(Email)
	assert.Equal(t, "z*********ng@example.com", d.Desensitize("zhangsanfeng@example.com"))

	RegisterDesensitizer("mycustomemail", NewDefaultDesensitizer(Email))
	v, err := OperateByRule("mycustomemail", "zhangsanfeng@example.com")
	require.NoError(t, err)
	assert.Equal(t, "z*********ng@example.com", v)

	// 在 tag 里同样可用
	type model struct {
		Addr string `desensitize:"mycustomemail"`
	}
	m := model{Addr: "zhangsanfeng@example.com"}
	require.NoError(t, Desensitization(&m))
	assert.Equal(t, "z*********ng@example.com", m.Addr)

	// 每种内置类型都能这样包一层
	assert.Equal(t, "181****8789", NewDefaultDesensitizer(MobilePhone).Desensitize("18175698789"))
	assert.Equal(t, "张**", NewDefaultDesensitizer(ChineseName).Desensitize("张三丰"))
}

// prefixDesensitizer 固定前缀的桩脱敏器，用于区分「重解析前后用的是哪一个」
type prefixDesensitizer struct{ prefix string }

func (p prefixDesensitizer) Desensitize(v string) string { return p.prefix + v }

// TestResolveRule_PlainAndParameterized 普通名称与带参数形式都能解析，未命中各自报错
func TestResolveRule_PlainAndParameterized(t *testing.T) {
	mask, err := ResolveRule("email")
	require.NoError(t, err)
	assert.Equal(t, "z*****an@example.com", mask("zhangsan@example.com"))

	// 带参数形式经工厂创建：保留前 3 位与后 4 位
	jump, err := ResolveRule("jump(3,-4,1)")
	require.NoError(t, err)
	assert.Equal(t, "138****8000", jump("13800138000"))

	// 工厂名已注册但未带参数时，以默认参数创建
	bare, err := ResolveRule("jump")
	require.NoError(t, err)
	assert.Equal(t, "***********", bare("13800138000"))

	// 未注册的普通名称与未注册的工厂名，命中不同哨兵错误
	_, err = ResolveRule("no_such_rule")
	assert.ErrorIs(t, err, errDesensitizerNotFound)
	_, err = ResolveRule("no_such_factory(1,2)")
	assert.ErrorIs(t, err, errFactoryNotFound)
}

// TestResolveRule_RefreshesAfterRegistration 注册表代数变化后自动重解析
//
// 这是 ResolveRule 与「调用方自己缓存 Desensitizer」的关键差别：
// 覆盖同名脱敏器之后，先前解析出的 MaskFunc 必须跟着改变，而不是固化旧实现
func TestResolveRule_RefreshesAfterRegistration(t *testing.T) {
	const name = "resolve_rule_refresh"
	RegisterDesensitizer(name, prefixDesensitizer{prefix: "old:"})

	mask, err := ResolveRule(name)
	require.NoError(t, err)
	assert.Equal(t, "old:v", mask("v"))

	// 覆盖同名实现会递增代数，MaskFunc 下次调用即自检并重解析
	RegisterDesensitizer(name, prefixDesensitizer{prefix: "new:"})
	assert.Equal(t, "new:v", mask("v"))
}

// TestResolveRule_KeepsPreviousWhenRefreshFails 重解析失败时沿用上次结果
//
// 该分支实际不可达（注册只增不减），但必须保证它不会发布 nil 脱敏器
func TestResolveRule_KeepsPreviousWhenRefreshFails(t *testing.T) {
	const name = "resolve_rule_refresh_fail"
	RegisterDesensitizer(name, prefixDesensitizer{prefix: "kept:"})

	mask, err := ResolveRule(name)
	require.NoError(t, err)
	assert.Equal(t, "kept:v", mask("v"))

	orig := refreshRule
	refreshRule = func(*registryState, string) (Desensitizer, error) {
		return nil, errDesensitizerNotFound
	}
	defer func() { refreshRule = orig }()

	// 递增代数迫使 MaskFunc 走重解析，而重解析被强制失败
	RegisterDesensitizer("resolve_rule_bump_gen", prefixDesensitizer{prefix: "x:"})
	assert.Equal(t, "kept:v", mask("v"), "重解析失败应沿用上次解析结果")
}

// TestResolveRule_ConcurrentCallsAreSafe 并发调用与并发代数变化下不崩不竞争
func TestResolveRule_ConcurrentCallsAreSafe(t *testing.T) {
	const name = "resolve_rule_concurrent"
	RegisterDesensitizer(name, prefixDesensitizer{prefix: "a:"})
	mask, err := ResolveRule(name)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				assert.True(t, strings.HasSuffix(mask("v"), ":v"))
			}
		}()
	}
	// 另一侧持续递增代数，逼出「自检 → 重解析 → 发布」与读取的交错
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			RegisterDesensitizer(name, prefixDesensitizer{prefix: "b:"})
		}
	}()
	wg.Wait()
}

// TestBuiltinRegistry_EveryTypeHasRegisteredName 每个脱敏类型都必须至少有一个 tag 名
//
// PEMKey 曾经一个名字都没有：desensitize:"pemKey" 解析不到任何脱敏器，
// 既不报错也不脱敏，私钥内容原样输出
// 这类缺口不会让任何测试变红，只会在泄漏时才被发现，所以在这里闸住
func TestBuiltinRegistry_EveryTypeHasRegisteredName(t *testing.T) {
	named := make(map[DesensitizeType]string)
	for name, d := range builtinRegistry().byName {
		if dd, ok := d.(*DefaultDesensitizer); ok {
			named[dd.desensitizerType] = name
		}
	}

	// CustomExtension 的语义依赖起止下标，由 jump 工厂以带参数形式覆盖，不占固定名
	for typ := ChineseName; typ <= Account; typ++ {
		assert.NotEmpty(t, named[typ], "脱敏类型 %d 没有任何注册名，对应 tag 会静默失效", typ)
	}
}

// TestBuiltinRegistry_AliasesResolveToSameRule 别名与规范名脱敏结果一致
//
// 这些写法（snake_case 与简称）在真实代码里与规范名同样常见，
// 过去只能由每个下游各自维护一份别名表，表一漂移就有 tag 静默不再命中
func TestBuiltinRegistry_AliasesResolveToSameRule(t *testing.T) {
	cases := []struct{ alias, canonical, sample string }{
		{"phone", "phoneNumber", "13800138000"},
		{"mobile", "mobilePhone", "13800138000"},
		{"idCard", "identityCard", "11010119900307123X"},
		{"ip", "ipv4", "192.168.1.100"},
		{"api_key", "apiKey", "ak-abcdefghijklmnop"},
		{"secret_key", "secretKey", "sk-abcdefghijklmnop"},
	}
	for _, c := range cases {
		t.Run(c.alias, func(t *testing.T) {
			alias, err := ResolveRule(c.alias)
			require.NoError(t, err)
			canonical, err := ResolveRule(c.canonical)
			require.NoError(t, err)
			assert.Equal(t, canonical(c.sample), alias(c.sample))
			assert.NotEqual(t, c.sample, alias(c.sample), "别名必须真的脱敏，排除原样返回的假通过")
		})
	}

	// pemKey 没有规范名的对照，单独断言它确实生效
	pem, err := ResolveRule("pemKey")
	require.NoError(t, err)
	const key = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAabcdefghij-----END RSA PRIVATE KEY-----"
	assert.NotEqual(t, key, pem(key), "pemKey 必须生效，否则私钥原样输出")
}
