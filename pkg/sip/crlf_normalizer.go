package sip

import (
	"bytes"
	"net"
)

// findHeaderBodySplit returns the byte offset where the SIP body begins
// (immediately after the blank-line separator). Returns -1 if no separator
// is found, meaning the data is likely all headers.
//
// Handles all line-ending variants: \r\n\r\n, \n\n, \r\n\n, \n\r\n.
func findHeaderBodySplit(data []byte) int {
	for i := 0; i < len(data)-1; i++ {
		if data[i] != '\n' {
			continue
		}
		// We're at a \n. The next "line" starts at i+1.
		// A blank line means the next char is also a line ending.
		if data[i+1] == '\n' {
			return i + 2 // \n\n
		}
		if data[i+1] == '\r' && i+2 < len(data) && data[i+2] == '\n' {
			return i + 3 // \n\r\n
		}
	}
	return -1
}

// normalizeCRLFBytes replaces bare \n (not preceded by \r) with \r\n.
func normalizeCRLFBytes(data []byte) []byte {
	// Fast path: if no \n exists, return as-is
	if !bytes.Contains(data, []byte("\n")) {
		return data
	}

	// Check if all \n are already preceded by \r
	hasBareNewline := false
	for i, b := range data {
		if b == '\n' && (i == 0 || data[i-1] != '\r') {
			hasBareNewline = true
			break
		}
	}
	if !hasBareNewline {
		return data
	}

	// Replace bare \n with \r\n
	var buf bytes.Buffer
	buf.Grow(len(data) + 64)
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' && (i == 0 || data[i-1] != '\r') {
			buf.WriteByte('\r')
		}
		buf.WriteByte(data[i])
	}
	return buf.Bytes()
}

// normalizeCRLF replaces bare \n with \r\n only in the SIP header section,
// leaving the message body untouched. This prevents Content-Length / body-size
// mismatch when an SBC (e.g. AudioCodes) sends bare LFs in the body: expanding
// those LFs would make the body longer than Content-Length declares, causing
// sipgo to truncate the body and break multipart SIPREC parsing.
func normalizeCRLF(data []byte) []byte {
	split := findHeaderBodySplit(data)
	if split < 0 || split >= len(data) {
		// No separator or no body — normalize everything (all headers)
		return normalizeCRLFBytes(data)
	}

	headerSection := data[:split]
	normalized := normalizeCRLFBytes(headerSection)
	if len(normalized) == split {
		// Headers unchanged — return original slice as-is
		return data
	}

	// Headers expanded — rebuild: normalized headers + original body
	body := data[split:]
	result := make([]byte, len(normalized)+len(body))
	copy(result, normalized)
	copy(result[len(normalized):], body)
	return result
}

// crlfPacketConn wraps a net.PacketConn to normalize bare \n to \r\n
// in incoming UDP packets before sipgo's parser processes them.
type crlfPacketConn struct {
	net.PacketConn
}

func (c *crlfPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil || n == 0 {
		return n, addr, err
	}

	// normalizeCRLF only touches headers (before the blank-line separator),
	// leaving the body intact so Content-Length stays accurate.
	normalized := normalizeCRLF(p[:n])
	if len(normalized) == n {
		// No change — data is already in p (or same-length slice)
		return n, addr, nil
	}

	// Normalized data is longer (header expansion); copy back if it fits.
	// normalizeCRLF returns a fresh allocation when it changes data, so
	// copying into p is safe even though body bytes originally lived there.
	if len(normalized) <= len(p) {
		copy(p, normalized)
		return len(normalized), addr, nil
	}

	// Extremely unlikely: normalized data exceeds buffer.
	copy(p, normalized)
	return len(p), addr, nil
}

// crlfListener wraps a net.Listener so that accepted connections
// normalize bare \n to \r\n in incoming TCP data.
type crlfListener struct {
	net.Listener
}

func (l *crlfListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &crlfConn{Conn: conn}, nil
}

// crlfConn wraps a net.Conn to normalize bare \n to \r\n on Read.
type crlfConn struct {
	net.Conn
	pending []byte // leftover normalized bytes from a previous read
}

func (c *crlfConn) Read(p []byte) (int, error) {
	// Drain any pending bytes from a previous normalization that expanded the data
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}

	n, err := c.Conn.Read(p)
	if n == 0 {
		return n, err
	}

	// normalizeCRLF only touches headers, leaving the body intact.
	normalized := normalizeCRLF(p[:n])
	if len(normalized) == n {
		return n, err
	}

	// Normalized data is longer than what was read
	copied := copy(p, normalized)
	if copied < len(normalized) {
		// Store overflow for the next Read call
		c.pending = append(c.pending, normalized[copied:]...)
	}
	return copied, err
}
