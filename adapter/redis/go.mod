module github.com/kamalyes/go-casbin/adapter/redis

go 1.25.0

require github.com/kamalyes/go-casbin/adapter/base v0.0.0

// 同仓模块：本地开发直接用源码，发版时需先给 adapter/base 打 tag
replace github.com/kamalyes/go-casbin/adapter/base => ../base

require (
	github.com/alicebob/miniredis/v2 v2.38.0
	github.com/casbin/casbin/v3 v3.11.0
	github.com/redis/go-redis/v9 v9.18.0
)

require (
	github.com/bmatcuk/doublestar/v4 v4.6.1 // indirect
	github.com/casbin/govaluate v1.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
)
