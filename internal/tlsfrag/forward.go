package tlsfrag

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Strategy identifies where the initial ClientHello is split.
type Strategy string

const (
	StrategySNIMidpoint Strategy = "sni-midpoint"
	StrategyBeforeSNI   Strategy = "before-sni"
	StrategyDualSplit   Strategy = "dual-split"
)

// ForwardInitialRecord preserves the existing default behavior.
func ForwardInitialRecord(dst io.Writer, src io.Reader) error {
	return ForwardInitialRecordWithStrategy(
		dst,
		src,
		StrategySNIMidpoint,
	)
}

// ForwardInitialRecordWithStrategy processes the first TLS record using the selected fragmentation strategy.
func ForwardInitialRecordWithStrategy(
	dst io.Writer,
	src io.Reader,
	strategy Strategy,
) error {
	switch strategy {
	case StrategySNIMidpoint, StrategyBeforeSNI, StrategyDualSplit:
	default:
		return fmt.Errorf("unsupported TLS fragmentation strategy: %q", strategy)
	}

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
		// FindServerName returns an offset relative to the complete
		// TLS record. SplitClientHelloRecord expects a payload offset.
		sniStart := offset - recordHeaderSize

		var splitAt int

		switch strategy {
		case StrategySNIMidpoint:
			splitAt = sniStart + len(hostname)/2

		case StrategyBeforeSNI:
			splitAt = sniStart

		case StrategyDualSplit:
			splitAt = sniStart + 1
		}

		fragmented, splitErr := SplitClientHelloRecord(record, splitAt)
		if splitErr == nil {
			output = fragmented

			if strategy == StrategyDualSplit {
				// Send the first two bytes separately to reproduce
				// the selected TCP write pattern.
				if _, err := io.Copy(dst, bytes.NewReader(output[:2])); err != nil {
					return err
				}

				_, err := io.Copy(dst, bytes.NewReader(output[2:]))
				return err
			}
		}
	}

	_, err = io.Copy(dst, bytes.NewReader(output))
	return err
}

// ForwardClientHello processes the first record and then forwards all remaining data unchanged.
func ForwardClientHello(dst io.Writer, src io.Reader) error {
	if err := ForwardInitialRecord(dst, src); err != nil {
		return err
	}

	_, err := io.Copy(dst, src)
	return err
}
