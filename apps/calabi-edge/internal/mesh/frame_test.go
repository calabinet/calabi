package mesh

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		hdr  ForwardHeader
		head []byte
		tail string // bytes that follow the frame (the live stream)
	}{
		{
			name: "http with head and tail",
			hdr: ForwardHeader{
				Kind:        KindHTTP,
				Host:        "u000123.cn-chengdu.example.com",
				Path:        "/api/x",
				VisitorIP:   "203.0.113.7",
				VisitorPort: 51514,
				OriginEdge:  987654321,
			},
			head: []byte("GET /api/x HTTP/1.1\r\nHost: u000123.cn-chengdu.example.com\r\n\r\n"),
			tail: "the rest of the visitor body bytes",
		},
		{
			name: "sni empty head still ok",
			hdr:  ForwardHeader{Kind: KindSNI, Host: "tls.example.com"},
			head: nil,
			tail: "\x16\x03\x01rest",
		},
		{
			name: "https binary head",
			hdr:  ForwardHeader{Kind: KindHTTPS, Host: "h.example.com"},
			head: []byte{0x00, 0x01, 0xff, 0xfe, 0x7f},
			tail: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tc.hdr, tc.head); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			// Append the would-be live-stream bytes.
			buf.WriteString(tc.tail)

			br := bufio.NewReader(&buf)
			gotHdr, gotHead, err := ReadFrame(br)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if gotHdr.Version != frameVersion {
				t.Errorf("version = %d, want %d", gotHdr.Version, frameVersion)
			}
			if gotHdr.Kind != tc.hdr.Kind || gotHdr.Host != tc.hdr.Host ||
				gotHdr.Path != tc.hdr.Path || gotHdr.VisitorIP != tc.hdr.VisitorIP ||
				gotHdr.VisitorPort != tc.hdr.VisitorPort || gotHdr.OriginEdge != tc.hdr.OriginEdge {
				t.Errorf("header mismatch:\n got %+v\nwant %+v", gotHdr, tc.hdr)
			}
			if !bytes.Equal(gotHead, tc.head) && !(len(gotHead) == 0 && len(tc.head) == 0) {
				t.Errorf("head = %q, want %q", gotHead, tc.head)
			}
			// The live-stream bytes must still be readable, intact, from br.
			rest, _ := io.ReadAll(br)
			if string(rest) != tc.tail {
				t.Errorf("tail = %q, want %q", rest, tc.tail)
			}
		})
	}
}

func TestReadFrameBadMagic(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("XXXXsome other protocol entirely"))
	if _, _, err := ReadFrame(br); err == nil {
		t.Fatal("expected error on bad magic, got nil")
	}
}

func TestReadFrameTruncatedHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, ForwardHeader{Kind: KindHTTP, Host: "h"}, nil); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// Chop the buffer mid-header.
	full := buf.Bytes()
	truncated := full[:8] // magic + headerLen, no header body
	br := bufio.NewReader(bytes.NewReader(truncated))
	if _, _, err := ReadFrame(br); err == nil {
		t.Fatal("expected error on truncated header, got nil")
	}
}

func TestWriteFrameRejectsInvalidKind(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, ForwardHeader{Kind: "tcp", Host: "h"}, nil); err == nil {
		t.Fatal("expected error for invalid kind tcp, got nil")
	}
}

func TestValidKind(t *testing.T) {
	for _, k := range []string{KindHTTP, KindHTTPS, KindSNI} {
		if !ValidKind(k) {
			t.Errorf("ValidKind(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"", "tcp", "udp", "HTTP", "http "} {
		if ValidKind(k) {
			t.Errorf("ValidKind(%q) = true, want false", k)
		}
	}
}
