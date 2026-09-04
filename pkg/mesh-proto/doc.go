// Package meshproto is the SINGLE, intentionally-public contract for Calabi's
// mesh ("Connect") data plane: the node<->coordinator coordination API and the
// node<->DERP relay wire frame. It is the "third-class" contract described in — deliberately public, minimal, versioned —
// as opposed to the two existing categories:
//
//   - pkg/protocol       : the Publish (reverse-tunnel) data-plane wire frame.
//   - pkg/api            : the control-plane gRPC contract. NEVER open-sourced.
//
// ISOLATION INVARIANT (enforced by scripts/export-community.sh):
//
//	This module and the client's mesh subsystem MUST NOT import
//	github.com/calabi/calabi/pkg/api. meshproto exists precisely so the OPEN
//	mesh client can link the coordination contract without dragging in any
//	control-plane surface. The export guard fails the build the day that
//	invariant is violated.
//
// STABILITY: ProtocolVersion may change freely until the community coordinator
// ships (MESH.9); after that it is a frozen, backward-compatible contract
// negotiated via capabilities. 条件3.
package meshproto
