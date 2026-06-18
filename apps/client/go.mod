module github.com/calabi/calabi/apps/client

go 1.25.0

require (
	github.com/calabi/calabi/pkg/protocol v0.0.0
	github.com/gofrs/flock v0.12.1
	github.com/hashicorp/yamux v0.1.2
	github.com/kardianos/service v1.2.2
	github.com/prometheus/client_golang v1.23.2
	golang.org/x/crypto v0.50.0
	golang.org/x/sys v0.46.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/calabi/calabi/pkg/protocol => ../../pkg/protocol
