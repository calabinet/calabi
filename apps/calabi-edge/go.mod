module github.com/calabi/calabi/apps/calabi-edge

go 1.25.0

require (
	github.com/calabi/calabi/pkg/mesh-proto v0.0.0
	github.com/calabi/calabi/pkg/observability v0.0.0
	github.com/calabi/calabi/pkg/protocol v0.0.0
	github.com/calabi/calabi/pkg/relay v0.0.0
	github.com/calabi/calabi/pkg/stunserver v0.0.0
	github.com/fsnotify/fsnotify v1.10.1
	github.com/hashicorp/yamux v0.1.2
	github.com/prometheus/client_golang v1.23.2
	golang.org/x/time v0.15.0
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/calabi/calabi/pkg/certevents v0.0.0
	github.com/calabi/calabi/pkg/edge-proto v0.0.0
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.51.0
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace (
	github.com/calabi/calabi/pkg/mesh-proto => ../../pkg/mesh-proto
	github.com/calabi/calabi/pkg/observability => ../../pkg/observability
	github.com/calabi/calabi/pkg/protocol => ../../pkg/protocol
	github.com/calabi/calabi/pkg/relay => ../../pkg/relay
	github.com/calabi/calabi/pkg/stunserver => ../../pkg/stunserver
)

replace github.com/calabi/calabi/pkg/edge-proto => ../../pkg/edge-proto

replace github.com/calabi/calabi/pkg/certevents => ../../pkg/certevents
