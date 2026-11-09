module github.com/kamalyes/go-casbin/adapter/nats

go 1.25.0

require github.com/kamalyes/go-casbin/adapter/base v0.0.0

// 同仓模块：本地开发直接用源码，发版时需先给 adapter/base 打 tag
replace github.com/kamalyes/go-casbin/adapter/base => ../base

require (
	github.com/casbin/casbin/v3 v3.11.0
	github.com/nats-io/nats.go v1.39.1
)

require (
	github.com/bmatcuk/doublestar/v4 v4.6.1 // indirect
	github.com/casbin/govaluate v1.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/nats-io/nkeys v0.4.9 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)
