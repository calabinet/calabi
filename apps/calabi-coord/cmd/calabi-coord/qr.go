package main

import (
	"io"
	"strings"

	"rsc.io/qr"
)

// writeQR draws text as a QR code on a terminal: two modules per character
// cell (the upper half block "▀", its top half coloured by the foreground and
// its bottom half by the background), with the four-module quiet zone a scanner
// needs. Colours are explicit ANSI black and white rather than "block" versus
// "space", so the code reads the same on a dark terminal and a light one.
func writeQR(w io.Writer, text string) error {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	const quiet = 4
	size := code.Size + 2*quiet
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Black(x, y)
	}
	var b strings.Builder
	for y := 0; y < size; y += 2 {
		for x := 0; x < size; x++ {
			fg, bg := "97", "107" // white over white
			if dark(x, y) {
				fg = "30"
			}
			if y+1 < size && dark(x, y+1) {
				bg = "40"
			}
			b.WriteString("\x1b[" + fg + ";" + bg + "m▀")
		}
		b.WriteString("\x1b[0m\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}
