module github.com/contextforge-org/contextforge-plugins-framework/examples/go-demo

go 1.25.4

require github.com/contextforge-org/contextforge-plugins-framework/go/cpex v0.0.0

require (
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
)

replace github.com/contextforge-org/contextforge-plugins-framework/go/cpex => ../../go/cpex
