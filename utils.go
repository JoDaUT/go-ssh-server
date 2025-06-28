// Package main
// utils functions in this file are based on https://github.com/gliderlabs/ssh/blob/master/util.go
package main

import "encoding/binary"

// parseString parses an ssh binary encrypted string
// See https://datatracker.ietf.org/doc/html/rfc4251#section-5
// Ssh strings are stored as a uint32 containing its length
// (number of bytes that follow) and zero (= empty string) or more
// bytes that are the value of the string.  Terminating null
// characters are not used.
func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length]) // Extract string
	rest = in[4+length:]           // Remaining bytes
	ok = true
	return
}

// parseUint32 parses the in[0:4] as uint32
func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}
