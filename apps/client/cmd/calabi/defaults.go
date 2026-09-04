package main

// defaults.go — build-wide defaults for the single calabi binary.
//
// There is no longer a platform-vs-open-source BUILD split: one binary ships, and
// what it does is decided at runtime.
// A pair of build-tagged files used to define an `edition` constant and two
// different sets of defaults; both are gone.

// defaultClientMode is the client mode when nothing else says otherwise (no
// CALABI_MODE, no persisted creds.Config.Mode). It stays "platform": this
// binary can reach the managed control plane, and that is what someone who
// just installed it expects. A self-hoster opts out explicitly with
// `calabi mode standalone` (or CALABI_MODE=standalone), which is also what
// makes the edge stop trusting client-supplied policy — Read by resolveClientMode in mode.go.
const defaultClientMode = clientModePlatform
