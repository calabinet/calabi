// Package protocol implements the Calabi wire-protocol frame codec.
//
// This package handles only the 16-byte fixed-length frame header and the
// raw payload bytes. It does NOT depend on protobuf at runtime; callers are
// responsible for marshaling/unmarshaling the typed payload messages
// defined in proto/calabi/v1/*.proto.
//
// Frame layout:
//
//	+-------+-------+-------+-------+
//	| Magic (2B)    | Ver   | Type  |
//	+-------+-------+-------+-------+
//	| Length (4B)                   |
//	+-------+-------+-------+-------+
//	| RequestID (8B)                |
//	|                               |
//	+-------+-------+-------+-------+
//	| Payload (0.16 MiB)           |
//	+-------------------------------+
//
// Numbering is big-endian throughout.
package protocol
