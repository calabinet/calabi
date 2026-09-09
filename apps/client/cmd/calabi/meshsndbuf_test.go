package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The send-buffer line's whole job is to render the size as TIME as well as
// bytes. Bytes were never the problem: 8 MB behind a relay socket was a problem
// because on a 3 Mbit/s link it was 21 seconds of queue, and no reader converts
// that in their head. A status line that shows only "8.0 MB" hides exactly the
// thing that went wrong.
func TestSndbufLineRendersTheQueueAsTime(t *testing.T) {
	// An exact case first, so the parsing below is anchored on arithmetic that can
	// be checked by hand: 1,500,000 bytes at 12 Mbit/s is one second on the nose.
	if got := sndbufLine(1_500_000, 12_000_000); !strings.Contains(got, "1s of queue") {
		t.Errorf("sndbufLine(1.5MB, 12Mbit/s) = %q, want exactly 1s of queue", got)
	}

	// And the shape that mattered in the field: the 8 MiB the kernel auto-tuned to
	// on a 3 Mbit/s link. Twenty-plus seconds is the whole reason this line exists,
	// so parse the number rather than matching a substring that a rounding change
	// would silently break.
	got := sndbufLine(8<<20, 3_000_000)
	secs, ok := queueSeconds(got)
	if !ok {
		t.Fatalf("sndbufLine(8MiB, 3Mbit/s) = %q, want a queue time in seconds", got)
	}
	if secs < 20 {
		t.Errorf("sndbufLine(8MiB, 3Mbit/s) reported %.1fs of queue; 8 MiB at 3 Mbit/s is over 22s", secs)
	}
	if !strings.Contains(got, "3.0 Mbit/s") {
		t.Errorf("sndbufLine = %q, want the measured rate it was derived from", got)
	}
}

// queueSeconds pulls "<n>s of queue" out of the rendered line. Returns false for
// a line that reports milliseconds, which is the healthy case and not what this
// particular assertion is about.
func queueSeconds(line string) (float64, bool) {
	m := regexp.MustCompile(`([0-9.]+)s of queue`).FindStringSubmatch(line)
	if m == nil || strings.Contains(line, "ms of queue") {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	return v, err == nil
}

// Zero is not a broken buffer and not a failed measurement — it is the kernel's
// own auto-tuning still in charge, which is the state before the controller has
// both inputs and the state CALABI_MESH_RELAY_SNDBUF=0 asks for outright.
// Printing "0 B" would read as a fault and send someone looking for one.
func TestSndbufLineSaysKernelRatherThanZeroBytes(t *testing.T) {
	got := sndbufLine(0, 0)
	if strings.Contains(got, "0 B") {
		t.Errorf("sndbufLine(0,0) = %q, want it to name the kernel rather than print a zero size", got)
	}
	if !strings.Contains(strings.ToLower(got), "kernel") {
		t.Errorf("sndbufLine(0,0) = %q, want it to say the kernel is in charge", got)
	}
}

// A PINNED buffer must say so. This line first shipped reporting a socket held
// at 64 KB by CALABI_MESH_RELAY_SNDBUF as "kernel auto-tuned (no cap applied)",
// because the pinned path had no controller and the size was read off the
// controller. The reader was at that moment trying to find out why their link
// was slow, and the answer was the setting the line denied existed.
func TestSndbufLineNamesAPinnedBufferInsteadOfDenyingIt(t *testing.T) {
	got := sndbufLine(65536, 0)
	if strings.Contains(got, "no cap applied") || strings.Contains(got, "auto-tuned") {
		t.Fatalf("sndbufLine(64KB pinned) = %q, want it to admit the cap", got)
	}
	if !strings.Contains(got, "pinned") {
		t.Errorf("sndbufLine(64KB pinned) = %q, want it to say the size is pinned", got)
	}
	if !strings.Contains(got, "CALABI_MESH_RELAY_SNDBUF") {
		t.Errorf("sndbufLine(64KB pinned) = %q, want it to name the variable to unset", got)
	}
	if !strings.Contains(got, "64") {
		t.Errorf("sndbufLine(64KB pinned) = %q, want the size in it", got)
	}
}

// A size with no rate behind it must not be turned into a duration: dividing by
// a rate we do not have is how the Overview chart on this same project came to
// report several GB/s. (That state now also means "pinned" — see above — but the
// arithmetic rule is separate from the label and is what this pins.)
func TestSndbufLineWillNotInventADurationWithoutARate(t *testing.T) {
	got := sndbufLine(512<<10, 0)
	if strings.Contains(got, "of queue") {
		t.Errorf("sndbufLine(512KB, no rate) = %q, want no queue time claimed", got)
	}
	if strings.Contains(got, "Mbit/s") {
		t.Errorf("sndbufLine(512KB, no rate) = %q, want no rate claimed", got)
	}
}
