package sip

import (
	"bytes"
	"fmt"
	"mime"
	"mime/multipart"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNormalizeCRLF(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already correct CRLF",
			input:    "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.example.com\r\n\r\n",
			expected: "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.example.com\r\n\r\n",
		},
		{
			name:     "bare LF only",
			input:    "INVITE sip:bob@example.com SIP/2.0\nVia: SIP/2.0/UDP pc33.example.com\n\n",
			expected: "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.example.com\r\n\r\n",
		},
		{
			name:     "mixed CRLF and bare LF",
			input:    "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.example.com\nContact: <sip:alice@host>\r\n\r\n",
			expected: "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.example.com\r\nContact: <sip:alice@host>\r\n\r\n",
		},
		{
			name:     "no newlines at all",
			input:    "some data without newlines",
			expected: "some data without newlines",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "bare LF at start",
			input:    "\nVia: SIP/2.0/UDP host\r\n\r\n",
			expected: "\r\nVia: SIP/2.0/UDP host\r\n\r\n",
		},
		{
			name:     "full SIP message with bare LF",
			input:    "INVITE sip:bob@biloxi.com SIP/2.0\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\nMax-Forwards: 70\nTo: Bob <sip:bob@biloxi.com>\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\nCall-ID: a84b4c76e66710@pc33.atlanta.com\nCSeq: 314159 INVITE\nContact: <sip:alice@pc33.atlanta.com>\nContent-Length: 0\n\n",
			expected: "INVITE sip:bob@biloxi.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\nMax-Forwards: 70\r\nTo: Bob <sip:bob@biloxi.com>\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nCall-ID: a84b4c76e66710@pc33.atlanta.com\r\nCSeq: 314159 INVITE\r\nContact: <sip:alice@pc33.atlanta.com>\r\nContent-Length: 0\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeCRLF([]byte(tt.input))
			if !bytes.Equal(result, []byte(tt.expected)) {
				t.Errorf("normalizeCRLF(%q) =\n  %q\nwant:\n  %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestFindHeaderBodySplit exercises every separator variant and edge case.
func TestFindHeaderBodySplit(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int // expected split index, -1 if none
	}{
		{"CRLF separator", "H1: v\r\nH2: v\r\n\r\nbody", 16},
		{"bare LF separator", "H1: v\nH2: v\n\nbody", 13},
		{"mixed CRLF header + LF separator", "H1: v\r\nH2: v\n\nbody", 14},
		{"LF header + CRLF separator", "H1: v\nH2: v\n\r\nbody", 14},
		{"no separator", "H1: v\r\nH2: v\r\n", -1},
		{"empty", "", -1},
		{"just separator LF", "\n\n", 2},
		{"just separator CRLF", "\r\n\r\n", 4},
		{"body contains newlines", "H: v\n\nbody\nwith\nnewlines", 6},
		{"single LF", "\n", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findHeaderBodySplit([]byte(tt.input))
			if got != tt.want {
				t.Errorf("findHeaderBodySplit(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// TestNormalizeCRLF_BodyPreserved is the key regression test for issue #44:
// bare LFs in headers must be normalized, but body bytes must be untouched
// so that Content-Length still matches.
func TestNormalizeCRLF_BodyPreserved(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "bare LF headers + bare LF body stays intact",
			input: "INVITE sip:x SIP/2.0\nContent-Length: 20\n\n" +
				"body\nwith\nbare\nLFs\n",
			expected: "INVITE sip:x SIP/2.0\r\nContent-Length: 20\r\n\r\n" +
				"body\nwith\nbare\nLFs\n",
		},
		{
			name: "CRLF headers + body with bare LFs untouched",
			input: "INVITE sip:x SIP/2.0\r\nContent-Length: 10\r\n\r\n" +
				"body\ndata\n",
			expected: "INVITE sip:x SIP/2.0\r\nContent-Length: 10\r\n\r\n" +
				"body\ndata\n",
		},
		{
			name:     "headers only (no body) still normalized",
			input:    "INVITE sip:x SIP/2.0\nContent-Length: 0\n\n",
			expected: "INVITE sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name:     "no separator — all gets normalized (header-only packet)",
			input:    "INVITE sip:x SIP/2.0\nVia: SIP/2.0/UDP host",
			expected: "INVITE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeCRLF([]byte(tt.input))
			if !bytes.Equal(result, []byte(tt.expected)) {
				t.Errorf("got:\n  %q\nwant:\n  %q", result, tt.expected)
			}
		})
	}
}

// TestNormalizeCRLF_AudioCodesMultipartBody reproduces issue #44 end-to-end:
// an AudioCodes SBC sends a SIPREC INVITE with bare LFs in both headers and
// the multipart body. Content-Length is computed on the raw (bare-LF) body.
// After normalization, Content-Length must still match the body size, and the
// multipart parser must find both the SDP and rs-metadata parts.
func TestNormalizeCRLF_AudioCodesMultipartBody(t *testing.T) {
	boundary := "boundary_ac14d5"

	// Build a multipart body with bare LFs (as AudioCodes might send)
	body := "--" + boundary + "\n" +
		"Content-Type: application/sdp\n" +
		"\n" +
		"v=0\n" +
		"o=AudiocodesGW 1644952274 165864691 IN IP4 192.168.100.21\n" +
		"s=SBC-Call\n" +
		"c=IN IP4 192.168.100.21\n" +
		"t=0 0\n" +
		"m=audio 7716 RTP/AVP 8 101\n" +
		"a=rtpmap:8 PCMA/8000\n" +
		"\n" +
		"--" + boundary + "\n" +
		"Content-Type: application/rs-metadata+xml\n" +
		"Content-Disposition: recording-session\n" +
		"\n" +
		`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<recording xmlns="urn:ietf:params:xml:ns:recording:1">` + "\n" +
		"  <datamode>complete</datamode>\n" +
		"  <session session_id=\"abc123\">\n" +
		"    <group-ref>group1</group-ref>\n" +
		"  </session>\n" +
		"</recording>\n" +
		"\n" +
		"--" + boundary + "--\n"

	contentLength := len(body) // calculated on bare-LF body, like the SBC does

	// Build the full SIP packet with bare-LF headers
	packet := fmt.Sprintf("INVITE sip:recorder@10.0.0.1 SIP/2.0\n"+
		"Via: SIP/2.0/UDP 192.168.100.21;branch=z9hG4bKac311994078\n"+
		"From: <sip:src@192.168.100.21>;tag=1c1818087822\n"+
		"To: <sip:recorder@10.0.0.1>\n"+
		"Call-ID: 1330070767992026211126@192.168.100.21\n"+
		"CSeq: 1 INVITE\n"+
		"Content-Type: multipart/mixed;boundary=%s\n"+
		"Content-Length: %d\n"+
		"\n"+
		"%s", boundary, contentLength, body)

	// Normalize (simulating what crlfPacketConn does)
	normalized := normalizeCRLF([]byte(packet))

	// Parse out the Content-Length and body from the normalized packet
	parts := bytes.SplitN(normalized, []byte("\r\n\r\n"), 2)
	if len(parts) != 2 {
		t.Fatal("normalized packet missing header/body separator")
	}
	headerSection := string(parts[0])
	bodySection := parts[1]

	// Extract Content-Length from normalized headers
	var clValue int
	for _, line := range strings.Split(headerSection, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			fmt.Sscanf(strings.TrimSpace(line[len("Content-Length:"):]), "%d", &clValue)
		}
	}

	// THE KEY ASSERTION: body length must equal Content-Length
	if len(bodySection) != clValue {
		t.Fatalf("Content-Length %d != actual body length %d (body truncation bug!)",
			clValue, len(bodySection))
	}

	// Verify the multipart body is still parseable
	ct := "multipart/mixed;boundary=" + boundary
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("parse media type: %v", err)
	}

	mr := multipart.NewReader(bytes.NewReader(bodySection), params["boundary"])
	var foundSDP, foundMetadata bool
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		ct := part.Header.Get("Content-Type")
		switch {
		case strings.Contains(ct, "sdp"):
			foundSDP = true
		case strings.Contains(ct, "rs-metadata"):
			foundMetadata = true
		}
	}

	if !foundSDP {
		t.Error("multipart parser did not find SDP part")
	}
	if !foundMetadata {
		t.Error("multipart parser did not find rs-metadata part — body was likely truncated")
	}
}

// TestNormalizeCRLF_BodyBinaryData ensures binary body content (e.g. RTP
// payload or base64 with 0x0a bytes) isn't corrupted by normalization.
func TestNormalizeCRLF_BodyBinaryData(t *testing.T) {
	// Body contains raw 0x0a (LF) bytes that are NOT line endings
	binaryBody := []byte{0x01, 0x0a, 0x0d, 0x0a, 0xff, 0x0a, 0x0a, 0x00}

	header := "INVITE sip:x SIP/2.0\nContent-Length: 8\n\n"
	packet := append([]byte(header), binaryBody...)

	normalized := normalizeCRLF(packet)

	// Find body in normalized output
	idx := bytes.Index(normalized, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatal("no header/body separator after normalization")
	}
	resultBody := normalized[idx+4:]

	if !bytes.Equal(resultBody, binaryBody) {
		t.Errorf("body corrupted:\n  got:  %x\n  want: %x", resultBody, binaryBody)
	}
}

// TestNormalizeCRLF_LargeMultipartBody ensures a large SIPREC body with many
// bare-LF lines doesn't get truncated (the original bug scenario: 60+ lines
// of XML metadata with bare LFs causing ~60 extra bytes of expansion).
func TestNormalizeCRLF_LargeMultipartBody(t *testing.T) {
	// Build a body with 100 lines of XML using bare LFs
	var bodyBuilder strings.Builder
	bodyBuilder.WriteString("--boundary123\n")
	bodyBuilder.WriteString("Content-Type: application/sdp\n\nv=0\n\n")
	bodyBuilder.WriteString("--boundary123\n")
	bodyBuilder.WriteString("Content-Type: application/rs-metadata+xml\n\n")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&bodyBuilder, "  <participant id=\"p%d\">data</participant>\n", i)
	}
	bodyBuilder.WriteString("--boundary123--\n")
	body := bodyBuilder.String()

	contentLength := len(body)

	packet := fmt.Sprintf("INVITE sip:x SIP/2.0\n"+
		"Content-Type: multipart/mixed;boundary=boundary123\n"+
		"Content-Length: %d\n\n%s", contentLength, body)

	normalized := normalizeCRLF([]byte(packet))

	// Extract body after the normalized separator
	idx := bytes.Index(normalized, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatal("missing separator")
	}
	resultBody := normalized[idx+4:]

	if len(resultBody) != contentLength {
		t.Fatalf("body length %d != Content-Length %d (truncated by %d bytes)",
			len(resultBody), contentLength, contentLength-len(resultBody))
	}

	// Body must be byte-identical to original (bare LFs preserved)
	if !bytes.Equal(resultBody, []byte(body)) {
		t.Error("body content was modified by normalization")
	}
}

// TestNormalizeCRLF_ProperCRLFPassthrough ensures that a fully compliant
// message (all CRLF) passes through unchanged with zero allocations.
func TestNormalizeCRLF_ProperCRLFPassthrough(t *testing.T) {
	msg := "INVITE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP host\r\n\r\nbody data\r\n"
	input := []byte(msg)
	result := normalizeCRLF(input)

	// Must return the exact same slice (no copy)
	if &result[0] != &input[0] {
		t.Error("proper CRLF message was copied instead of returned as-is")
	}
}

// TestNormalizeCRLF_SeparatorVariants exercises all four blank-line separator
// forms to ensure headers are normalized and body is preserved in each case.
// The separator string encodes "last header line ending + blank line ending":
//
//	\r\n\r\n = CRLF header + CRLF blank
//	\n\n     = LF header   + LF blank
//	\r\n\n   = CRLF header + LF blank
//	\n\r\n   = LF header   + CRLF blank
func TestNormalizeCRLF_SeparatorVariants(t *testing.T) {
	tests := []struct {
		name      string
		firstEnd  string // line ending for the first header line
		sep       string // last-header-ending + blank-line (the full separator)
	}{
		{"CRLF+CRLF", "\r\n", "\r\n\r\n"},
		{"LF+LF", "\n", "\n\n"},
		{"CRLF+LF", "\r\n", "\r\n\n"},
		{"LF+CRLF", "\n", "\n\r\n"},
	}

	bodyContent := "body\nwith\nbare\nLFs"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build: start-line + firstEnd + Via header + sep + body
			// The sep already includes the Via line's ending + the blank line.
			raw := "INVITE sip:x SIP/2.0" + tt.firstEnd +
				"Via: SIP/2.0/UDP host" + tt.sep +
				bodyContent

			result := normalizeCRLF([]byte(raw))

			// Headers must end with \r\n\r\n after normalization
			idx := bytes.Index(result, []byte("\r\n\r\n"))
			if idx < 0 {
				t.Fatalf("no CRLF separator in result: %q", result)
			}

			// No bare LFs in the header section
			headerBytes := result[:idx]
			for i, b := range headerBytes {
				if b == '\n' && (i == 0 || headerBytes[i-1] != '\r') {
					t.Errorf("bare LF at header byte %d: %q", i, headerBytes)
					break
				}
			}

			// Body must be untouched
			body := string(result[idx+4:])
			if body != bodyContent {
				t.Errorf("body was modified: got %q, want %q", body, bodyContent)
			}
		})
	}
}

func TestCRLFPacketConn(t *testing.T) {
	// Create a real UDP connection pair
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	clientConn, err := net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	// Wrap server conn with CRLF normalizer
	wrapped := &crlfPacketConn{PacketConn: serverConn}

	// Send a SIP message with bare \n
	msg := "INVITE sip:bob@example.com SIP/2.0\nVia: SIP/2.0/UDP host\nCall-ID: test123\n\n"
	_, err = clientConn.Write([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	// Read through the normalizer
	buf := make([]byte, 4096)
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := wrapped.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	expected := "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP host\r\nCall-ID: test123\r\n\r\n"
	if string(buf[:n]) != expected {
		t.Errorf("got:\n  %q\nwant:\n  %q", string(buf[:n]), expected)
	}
}

// TestCRLFPacketConn_BodyPreserved sends a SIP message with bare-LF headers
// and a bare-LF body through a real UDP crlfPacketConn and verifies the body
// is not modified while headers are normalized.
func TestCRLFPacketConn_BodyPreserved(t *testing.T) {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	clientConn, err := net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	wrapped := &crlfPacketConn{PacketConn: serverConn}

	body := "--boundary\nContent-Type: application/sdp\n\nv=0\n\n--boundary--\n"
	packet := fmt.Sprintf("INVITE sip:x SIP/2.0\nContent-Type: multipart/mixed;boundary=boundary\nContent-Length: %d\n\n%s",
		len(body), body)

	_, err = clientConn.Write([]byte(packet))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := wrapped.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	result := buf[:n]
	idx := bytes.Index(result, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatal("no CRLF separator in normalized packet")
	}
	resultBody := string(result[idx+4:])

	if resultBody != body {
		t.Errorf("body modified by normalizer:\n  got:  %q\n  want: %q", resultBody, body)
	}

	// Verify Content-Length matches
	headers := string(result[:idx])
	var cl int
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			fmt.Sscanf(strings.TrimSpace(line[len("Content-Length:"):]), "%d", &cl)
		}
	}
	if cl != len(body) {
		t.Errorf("Content-Length %d != body length %d", cl, len(body))
	}
}

func TestCRLFConn(t *testing.T) {
	// Create a TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Wrap with CRLF normalizer
	wrapped := &crlfListener{Listener: listener}

	// Send data with bare \n from a client
	msg := "INVITE sip:bob@example.com SIP/2.0\nVia: SIP/2.0/TCP host\n\n"
	expected := "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP host\r\n\r\n"

	go func() {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte(msg))
	}()

	conn, err := wrapped.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	if string(buf[:n]) != expected {
		t.Errorf("got:\n  %q\nwant:\n  %q", string(buf[:n]), expected)
	}
}

func BenchmarkNormalizeCRLF_AlreadyCorrect(b *testing.B) {
	data := []byte("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP host\r\nCall-ID: test\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeCRLF(data)
	}
}

func BenchmarkNormalizeCRLF_NeedsFixing(b *testing.B) {
	data := []byte("INVITE sip:bob@example.com SIP/2.0\nVia: SIP/2.0/UDP host\nCall-ID: test\n\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeCRLF(data)
	}
}

func BenchmarkNormalizeCRLF_WithBody(b *testing.B) {
	body := strings.Repeat("line of body content\n", 50)
	data := []byte(fmt.Sprintf("INVITE sip:x SIP/2.0\nVia: SIP/2.0/UDP host\nContent-Length: %d\n\n%s",
		len(body), body))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeCRLF(data)
	}
}
