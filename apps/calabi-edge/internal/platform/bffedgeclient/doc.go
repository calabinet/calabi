// Package bffedgeclient is the calabi-edge-side adapter layer that lets
// the edge route every control-plane call through a single mTLS gRPC
// connection to bff-edge.
//
// Why it exists: cross-region edges (e.g. cn-hangzhou ECS) can't dial
// the in-cluster identity-svc / tunnel-svc / cert-svc / quota-svc /
// config-svc ClusterIPs, and they can't reach the cluster NATS broker
// either. bff-edge fronts all of that on one public mTLS gRPC port;
// this package gives the existing edge code paths the right shape to
// dial through it without rewrites.
//
// Public surface:
//
//	Dial(ctx, cfg)           – open the long-lived mTLS conn
//	QuotaAdapter             – bff_edge.GetEffectiveQuota → pb.Quota.GetEffective shape
//	ConfigAdapter            – bff_edge.SubscribeConfig   → pb.Config.Subscribe shape
//	NewBus(ctx, client)      – eventbus.Bus impl backed by SubscribeXxx + ReportUsage
//
// Identity / TunnelControl / Cert RPC methods already match between
// pb.*Client and bff_edge.BFFEdgeClient by name + signature, so for
// those services edge code passes the raw bff_edge.BFFEdgeClient
// through the existing narrow interface and no wrapper is needed.
package bffedgeclient
