package tlsfrag

import (
	"bytes"
	"encoding/binary"
	"io"
)

// ForwardInitialRecord processes and forwards the first TLS record.
// Non-TLS traffic is passed through without modification.
func ForwardInitialRecord(dst io.Writer, src io.Reader) error {
	var first [1]byte

	if _, err := io.ReadFull(src, first[:]); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}

	if first[0] != 0x16 {
		_, err := io.Copy(dst, bytes.NewReader(first[:]))
		return err
	}

	header := make([]byte, recordHeaderSize)
	header[0] = first[0]

	if _, err := io.ReadFull(src, header[1:]); err != nil {
		return err
	}

	length := int(binary.BigEndian.Uint16(header[3:5]))

	if header[1] != 0x03 ||
		(header[2] != 0x01 && header[2] != 0x03) ||
		length < 4 ||
		length > maxPlaintextSize {
		_, err := io.Copy(dst, bytes.NewReader(header))
		return err
	}

	record := make([]byte, recordHeaderSize+length)
	copy(record, header)

	if _, err := io.ReadFull(src, record[recordHeaderSize:]); err != nil {
		return err
	}

	output := record

	hostname, offset, err := FindServerName(record)
	if err == nil {
		splitAt := offset - recordHeaderSize + len(hostname)/2

		fragmented, splitErr := SplitClientHelloRecord(record, splitAt)
		if splitErr == nil {
			output = fragmented
		}
	}

	_, err = io.Copy(dst, bytes.NewReader(output))
	return err
}

// ForwardClientHello processes the first record and then forwards
// all remaining data unchanged.
func ForwardClientHello(dst io.Writer, src io.Reader) error {
	if err := ForwardInitialRecord(dst, src); err != nil {
		return err
	}

	_, err := io.Copy(dst, src)
	return err
}
