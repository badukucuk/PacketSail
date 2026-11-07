package tlsfrag

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestForwardClientHello(t *testing.T) {
	original := makeTestClientHello("example.com")
	additional := []byte("following data")

	input := append(bytes.Clone(original), additional...)

	var output bytes.Buffer

	if err := ForwardClientHello(&output, bytes.NewReader(input)); err != nil {
		t.Fatalf("forward ClientHello: %v", err)
	}

	result := output.Bytes()

	firstLength := int(binary.BigEndian.Uint16(result[3:5]))
	secondStart := recordHeaderSize + firstLength
	secondLength := int(binary.BigEndian.Uint16(
		result[secondStart+3 : secondStart+5],
	))

	endOfSecond := secondStart + recordHeaderSize + secondLength

	reconstructed := append([]byte{}, result[5:secondStart]...)
	reconstructed = append(reconstructed, result[secondStart+5:endOfSecond]...)

	if !bytes.Equal(reconstructed, original[5:]) {
		t.Fatal("forwarding changed the ClientHello payload")
	}

	if !bytes.Equal(result[endOfSecond:], additional) {
		t.Fatal("following data was changed")
	}
}

func TestForwardNonTLSTraffic(t *testing.T) {
	original := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	var output bytes.Buffer

	if err := ForwardClientHello(&output, bytes.NewReader(original)); err != nil {
		t.Fatalf("forward non-TLS traffic: %v", err)
	}

	if !bytes.Equal(output.Bytes(), original) {
		t.Fatal("non-TLS traffic was modified")
	}
}

func TestForwardClientHelloWithSmallReads(t *testing.T) {
	original := makeTestClientHello("example.com")

	reader := &oneByteReader{
		reader: bytes.NewReader(original),
	}

	var output bytes.Buffer

	if err := ForwardClientHello(&output, reader); err != nil {
		t.Fatalf("forward fragmented input: %v", err)
	}

	if output.Len() != len(original)+recordHeaderSize {
		t.Fatalf("unexpected output length: %d", output.Len())
	}
}

type oneByteReader struct {
	reader io.Reader
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}

	return r.reader.Read(p)
}

func TestForwardInitialRecordLeavesRemainingData(t *testing.T) {
	original := makeTestClientHello("example.com")
	remaining := []byte("additional application data")

	input := append(bytes.Clone(original), remaining...)
	reader := bytes.NewReader(input)

	var output bytes.Buffer

	if err := ForwardInitialRecord(&output, reader); err != nil {
		t.Fatalf("forward initial TLS record: %v", err)
	}

	fragmented := output.Bytes()

	if len(fragmented) != len(original)+recordHeaderSize {
		t.Fatalf(
			"unexpected fragmented length: got %d, want %d",
			len(fragmented),
			len(original)+recordHeaderSize,
		)
	}

	// The initial record was consumed, but subsequent bytes must remain unread.
	unread, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read remaining data: %v", err)
	}

	if !bytes.Equal(unread, remaining) {
		t.Fatalf("unexpected remaining data: %q", unread)
	}

	firstLength := int(binary.BigEndian.Uint16(fragmented[3:5]))
	secondStart := recordHeaderSize + firstLength
	secondLength := int(binary.BigEndian.Uint16(
		fragmented[secondStart+3 : secondStart+5],
	))

	secondEnd := secondStart + recordHeaderSize + secondLength

	reconstructed := append([]byte{}, fragmented[5:secondStart]...)
	reconstructed = append(reconstructed, fragmented[secondStart+5:secondEnd]...)

	if !bytes.Equal(reconstructed, original[5:]) {
		t.Fatal("fragmentation changed the original ClientHello payload")
	}
}

func TestForwardInitialNonTLSTraffic(t *testing.T) {
	original := []byte("GET / HTTP/1.1\r\n\r\n")
	reader := bytes.NewReader(original)

	var output bytes.Buffer

	if err := ForwardInitialRecord(&output, reader); err != nil {
		t.Fatalf("forward initial non-TLS data: %v", err)
	}

	if !bytes.Equal(output.Bytes(), original[:1]) {
		t.Fatalf("unexpected initial output: %q", output.Bytes())
	}

	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read remaining data: %v", err)
	}

	if !bytes.Equal(remaining, original[1:]) {
		t.Fatalf("unexpected remaining data: %q", remaining)
	}
}
