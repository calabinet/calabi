// Package mobilecheck holds no code. Its test guards the packages the phone
// clients build on.
//
// GOOS=android satisfies every `linux` build constraint and GOOS=ios every
// `darwin` one, so a desktop backend that shells out to ip/iptables/ifconfig
// or rewrites /etc/resolv.conf compiles into a phone build without a word and
// only fails when it runs. The test cross-builds the set for both and refuses
// any dependency on os/exec (iOS forbids fork; Android apps have no root) or on
// the desktop-only packages that bring it in.
package mobilecheck
