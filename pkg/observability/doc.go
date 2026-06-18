// Package observability is the shared baseline that every Calabi process
// imports to get a uniform operational surface:
//
//   - /healthz   liveness, always 200 once Run() has started.
//   - /readyz    readiness, 503 during boot and shutdown.
//   - /metrics   Prometheus exposition (process + service-local collectors).
//
// It also wires the standard Go runtime + process collectors and a constant
// build_info gauge labelled with service name, version, Go version, and
// VCS revision -- so a single Grafana dashboard can join across the whole
// fleet (calabi-edge, identity-svc, tenant-svc, ...).
//
// Domain-specific collectors stay in each service's internal/metrics; this
// package just gives them a registry and a place to bind.
package observability
