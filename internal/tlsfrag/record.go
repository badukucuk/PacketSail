package tlsfrag

import (
	"encoding/binary"
	"fmt"
)

const (
	recordHeaderSize = 5
	maxPlaintextSize = 1 << 14
)

// SplitClientHelloRecord splits a single plaintext ClientHello
// handshake record into two TLS records without changing its payload.
func SplitClientHelloRecord(record []byte, splitAt int) ([]byte, error) {
	if len(record) < recordHeaderSize {
		return nil, fmt.Errorf("TLS record header is incomplete")
	}

	if record[0] != 0x16 {
		return nil, fmt.Errorf("expected a TLS handshake record")
	}

	if record[1] != 0x03 || (record[2] != 0x01 && record[2] != 0x03) {
		return nil, fmt.Errorf("unsupported TLS record version")
	}

	length := int(binary.BigEndian.Uint16(record[3:5]))
	if length > maxPlaintextSize {
		return nil, fmt.Errorf("TLS plaintext record exceeds maximum size")
	}

	if len(record) != recordHeaderSize+length {
		return nil, fmt.Errorf("TLS record length does not match payload")
	}

	payload := record[recordHeaderSize:]

	if len(payload) < 4 || payload[0] != 0x01 {
		return nil, fmt.Errorf("expected a ClientHello handshake message")
	}

	handshakeLength := int(payload[1])<<16 |
		int(payload[2])<<8 |
		int(payload[3])

	if handshakeLength != len(payload)-4 {
		return nil, fmt.Errorf("ClientHello length does not match record payload")
	}

	if splitAt <= 0 || splitAt >= len(payload) {
		return nil, fmt.Errorf("split position must be inside the payload")
	}

	result := make([]byte, len(record)+recordHeaderSize)

	// First record: original header with a shorter payload length.
	copy(result[:recordHeaderSize], record[:recordHeaderSize])
	binary.BigEndian.PutUint16(result[3:5], uint16(splitAt))
	copy(result[5:5+splitAt], payload[:splitAt])

	// Second record: another header followed by the remaining payload.
	secondStart := recordHeaderSize + splitAt
	copy(result[secondStart:secondStart+recordHeaderSize], record[:recordHeaderSize])

	remaining := len(payload) - splitAt
	binary.BigEndian.PutUint16(
		result[secondStart+3:secondStart+5],
		uint16(remaining),
	)

	copy(result[secondStart+5:], payload[splitAt:])

	return result, nil
}

type wireReader struct {
	data   []byte
	offset int
}

func (r *wireReader) read(size int) ([]byte, error) {
	if size < 0 || size > len(r.data)-r.offset {
		return nil, fmt.Errorf("incomplete TLS field")
	}

	value := r.data[r.offset : r.offset+size]
	r.offset += size

	return value, nil
}

func (r *wireReader) vector(lengthBytes int) ([]byte, int, error) {
	prefix, err := r.read(lengthBytes)
	if err != nil {
		return nil, 0, err
	}

	var length int

	switch lengthBytes {
	case 1:
		length = int(prefix[0])
	case 2:
		length = int(binary.BigEndian.Uint16(prefix))
	default:
		return nil, 0, fmt.Errorf("unsupported TLS length field size")
	}

	start := r.offset

	value, err := r.read(length)
	if err != nil {
		return nil, 0, err
	}

	return value, start, nil
}

// FindServerName returns the hostname and its byte offset inside
// a single plaintext TLS ClientHello record.
func FindServerName(record []byte) (string, int, error) {
	if len(record) < 9 {
		return "", 0, fmt.Errorf("incomplete ClientHello record")
	}

	if record[0] != 0x16 {
		return "", 0, fmt.Errorf("expected a TLS handshake record")
	}

	if record[1] != 0x03 || (record[2] != 0x01 && record[2] != 0x03) {
		return "", 0, fmt.Errorf("unsupported TLS record version")
	}

	recordLength := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLength > maxPlaintextSize || recordLength != len(record)-5 {
		return "", 0, fmt.Errorf("invalid TLS record length")
	}

	payload := record[5:]
	if payload[0] != 0x01 {
		return "", 0, fmt.Errorf("expected ClientHello")
	}

	handshakeLength := int(payload[1])<<16 |
		int(payload[2])<<8 |
		int(payload[3])

	if handshakeLength != len(payload)-4 {
		return "", 0, fmt.Errorf("invalid ClientHello length")
	}

	// Skip the handshake header, legacy version, and random bytes.
	reader := wireReader{data: record[9:]}

	if _, err := reader.read(34); err != nil {
		return "", 0, err
	}

	if _, _, err := reader.vector(1); err != nil {
		return "", 0, err
	}

	cipherSuites, _, err := reader.vector(2)
	if err != nil {
		return "", 0, err
	}
	if len(cipherSuites) < 2 || len(cipherSuites)%2 != 0 {
		return "", 0, fmt.Errorf("invalid cipher suites length")
	}

	compression, _, err := reader.vector(1)
	if err != nil {
		return "", 0, err
	}
	if len(compression) == 0 {
		return "", 0, fmt.Errorf("empty compression methods")
	}

	extensions, extensionsStart, err := reader.vector(2)
	if err != nil {
		return "", 0, err
	}
	if reader.offset != len(reader.data) {
		return "", 0, fmt.Errorf("trailing ClientHello data")
	}

	extReader := wireReader{data: extensions}

	for extReader.offset < len(extensions) {
		kindBytes, err := extReader.read(2)
		if err != nil {
			return "", 0, err
		}

		kind := binary.BigEndian.Uint16(kindBytes)

		extension, extensionStart, err := extReader.vector(2)
		if err != nil {
			return "", 0, err
		}

		if kind != 0 {
			continue
		}

		sniReader := wireReader{data: extension}
		names, namesStart, err := sniReader.vector(2)
		if err != nil {
			return "", 0, err
		}
		if sniReader.offset != len(extension) {
			return "", 0, fmt.Errorf("invalid server_name extension")
		}

		nameReader := wireReader{data: names}

		nameType, err := nameReader.read(1)
		if err != nil {
			return "", 0, err
		}
		if nameType[0] != 0 {
			return "", 0, fmt.Errorf("unsupported server name type")
		}

		hostname, hostnameStart, err := nameReader.vector(2)
		if err != nil {
			return "", 0, err
		}
		if len(hostname) == 0 || nameReader.offset != len(names) {
			return "", 0, fmt.Errorf("invalid server name")
		}

		offset := 9 + extensionsStart + extensionStart +
			namesStart + hostnameStart

		return string(hostname), offset, nil
	}

	return "", 0, fmt.Errorf("ClientHello has no server_name extension")
}
