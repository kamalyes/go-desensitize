module github.com/kamalyes/go-desensitize

// 零运行时依赖，因此把语言版本压到 1.20 以吃下尽量旧的工具链
// 本库只用到 strings / reflect / regexp / sync / unicode / encoding/json，
// 没有任何 1.21+ 的内建或标准库符号
// [EN] Zero runtime dependencies, so the language version is held at 1.20 to
// accept as old a toolchain as possible; nothing here needs a 1.21+ builtin
go 1.20

// testify 仅测试使用，不会进入任何使用者的构建图
// [EN] testify is test-only and never enters a consumer's build graph
require github.com/stretchr/testify v1.11.1

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
