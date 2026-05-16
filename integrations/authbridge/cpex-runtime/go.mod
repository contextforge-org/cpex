module github.com/contextforge-org/contextforge-plugins-framework/integrations/authbridge/cpex-runtime

go 1.25.4

require (
	github.com/contextforge-org/contextforge-plugins-framework/go/cpex v0.0.0
	github.com/envoyproxy/go-control-plane/envoy v1.37.0
	github.com/kagenti/kagenti-extensions/authbridge/authlib v0.0.0
	google.golang.org/grpc v1.80.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cncf/xds/go v0.0.0-20251210132809-ee656c7534f5 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.0 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/lestrrat-go/blackmagic v1.0.3 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx/v2 v2.1.6 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace (
	github.com/contextforge-org/contextforge-plugins-framework/go/cpex => ../../../go/cpex
	github.com/kagenti/kagenti-extensions/authbridge/authlib => ../../../kagenti-extensions/authbridge/authlib
)
