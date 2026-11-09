package tlsfrag

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSplitClientHelloRecord(t *testing.T) {
	original := []byte{
		0x16, 0x03, 0x03, 0x00, 0x08,
		0x01, 0x00, 0x00, 0x04,
		0xAA, 0xBB, 0xCC, 0xDD,
	}

	result, err := SplitClientHelloRecord(original, 5)
	if err != nil {
		t.Fatalf("split ClientHello record: %v", err)
	}

	expected := []byte{
		0x16, 0x03, 0x03, 0x00, 0x05,
		0x01, 0x00, 0x00, 0x04, 0xAA,

		0x16, 0x03, 0x03, 0x00, 0x03,
		0xBB, 0xCC, 0xDD,
	}

	if !bytes.Equal(result, expected) {
		t.Fatalf("unexpected fragmented record:\ngot  %x\nwant %x", result, expected)
	}

	firstLength := int(binary.BigEndian.Uint16(result[3:5]))
	secondStart := 5 + firstLength
	secondLength := int(binary.BigEndian.Uint16(result[secondStart+3 : secondStart+5]))

	reconstructed := append([]byte{}, result[5:5+firstLength]...)
	reconstructed = append(reconstructed, result[secondStart+5:]...)

	if secondLength != 3 {
		t.Fatalf("unexpected second record length: %d", secondLength)
	}

	if !bytes.Equal(reconstructed, original[5:]) {
		t.Fatal("fragmentation changed the original handshake payload")
	}
}

func TestSplitClientHelloRecordRejectsInvalidInput(t *testing.T) {
	valid := []byte{
		0x16, 0x03, 0x03, 0x00, 0x08,
		0x01, 0x00, 0x00, 0x04,
		0xAA, 0xBB, 0xCC, 0xDD,
	}

	tests := []struct {
		name    string
		record  []byte
		splitAt int
		wantErr string
	}{
		{"short header", []byte{0x16, 0x03}, 1, "header is incomplete"},
		{"wrong type", append([]byte{0x17}, valid[1:]...), 5, "handshake record"},
		{"length mismatch", valid[:len(valid)-1], 5, "length does not match"},
		{"invalid split zero", valid, 0, "split position"},
		{"invalid split end", valid, 8, "split position"},
		{"wrong handshake type", []byte{
			0x16, 0x03, 0x03, 0x00, 0x08,
			0x02, 0x00, 0x00, 0x04,
			0xAA, 0xBB, 0xCC, 0xDD,
		}, 5, "ClientHello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SplitClientHelloRecord(tt.record, tt.splitAt)
			if err == nil {
				t.Fatal("expected an error")
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// makeTestClientHello creates a minimal ClientHello record for parser tests.
func makeTestClientHello(hostname string) []byte {
	name := []byte(hostname)

	// ServerName: name type, name length, hostname.
	serverName := []byte{0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(serverName[1:3], uint16(len(name)))
	serverName = append(serverName, name...)

	// ServerNameList: two-byte length followed by the name entry.
	nameList := make([]byte, 2)
	binary.BigEndian.PutUint16(nameList, uint16(len(serverName)))
	nameList = append(nameList, serverName...)

	// server_name extension: type 0 and its data length.
	extension := []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(extension[2:4], uint16(len(nameList)))
	extension = append(extension, nameList...)

	// ClientHello fixed fields: legacy version and 32 random bytes.
	body := make([]byte, 34)
	body[0], body[1] = 0x03, 0x03

	// Empty session ID, one cipher suite, one compression method.
	body = append(body,
		0x00,
		0x00, 0x02, 0x13, 0x01,
		0x01, 0x00,
	)

	// Extensions vector.
	extensionsLength := make([]byte, 2)
	binary.BigEndian.PutUint16(extensionsLength, uint16(len(extension)))
	body = append(body, extensionsLength...)
	body = append(body, extension...)

	// Handshake header: ClientHello type and three-byte length.
	handshake := []byte{
		0x01,
		byte(len(body) >> 16),
		byte(len(body) >> 8),
		byte(len(body)),
	}
	handshake = append(handshake, body...)

	// TLS record header.
	record := []byte{0x16, 0x03, 0x03, 0x00, 0x00}
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))

	return append(record, handshake...)
}

func TestFindServerName(t *testing.T) {
	record := makeTestClientHello("discord.com")

	hostname, offset, err := FindServerName(record)
	if err != nil {
		t.Fatalf("find server name: %v", err)
	}

	if hostname != "discord.com" {
		t.Fatalf("unexpected hostname: got %q", hostname)
	}

	if offset < 0 || offset+len(hostname) > len(record) {
		t.Fatalf("invalid hostname offset: %d", offset)
	}

	if !bytes.Equal(record[offset:offset+len(hostname)], []byte(hostname)) {
		t.Fatal("hostname offset does not point to the SNI hostname")
	}
}

func TestFindServerNameRejectsInvalidInput(t *testing.T) {
	valid := makeTestClientHello("discord.com")

	invalidLength := bytes.Clone(valid)
	invalidLength[4]++

	invalidHandshake := bytes.Clone(valid)
	invalidHandshake[5] = 0x02

	tests := []struct {
		name   string
		record []byte
	}{
		{
			name:   "incomplete record",
			record: []byte{0x16, 0x03},
		},
		{
			name:   "incorrect record length",
			record: invalidLength,
		},
		{
			name:   "wrong handshake type",
			record: invalidHandshake,
		},
		{
			name:   "truncated ClientHello",
			record: valid[:len(valid)-1],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := FindServerName(tt.record)
			if err == nil {
				t.Fatal("expected invalid ClientHello to be rejected")
			}
		})
	}
}

func captureClientHelloRecord(t *testing.T) []byte {
	t.Helper()

	clientConn, serverConn := net.Pipe()

	tlsClient := tls.Client(clientConn, &tls.Config{
		ServerName: "example.com",
		MinVersion: tls.VersionTLS12,
	})

	handshakeDone := make(chan error, 1)

	go func() {
		handshakeDone <- tlsClient.Handshake()
	}()

	defer func() {
		serverConn.Close()
		tlsClient.Close()
		<-handshakeDone
	}()

	if err := serverConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	var header [5]byte
	if _, err := io.ReadFull(serverConn, header[:]); err != nil {
		t.Fatalf("read TLS record header: %v", err)
	}

	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length == 0 || length > maxPlaintextSize {
		t.Fatalf("invalid TLS record length: %d", length)
	}

	record := make([]byte, 5+length)
	copy(record[:5], header[:])

	if _, err := io.ReadFull(serverConn, record[5:]); err != nil {
		t.Fatalf("read TLS record payload: %v", err)
	}

	return record
}

func TestFindServerNameFromRealClientHello(t *testing.T) {
	record := captureClientHelloRecord(t)

	hostname, offset, err := FindServerName(record)
	if err != nil {
		t.Fatalf("parse real ClientHello: %v", err)
	}

	if hostname != "example.com" {
		t.Fatalf("unexpected SNI: got %q, want %q", hostname, "example.com")
	}

	if offset < 5 || offset+len(hostname) > len(record) {
		t.Fatalf("invalid SNI offset: %d", offset)
	}

	actual := record[offset : offset+len(hostname)]

	if !bytes.Equal(actual, []byte(hostname)) {
		t.Fatalf("SNI offset points to %q instead of %q", actual, hostname)
	}

	t.Logf("ClientHello size: %d bytes", len(record))
	t.Logf("SNI hostname: %s", hostname)
	t.Logf("SNI offset: %d", offset)
}

func TestSplitRealClientHelloAtSNI(t *testing.T) {
	original := captureClientHelloRecord(t)

	hostname, offset, err := FindServerName(original)
	if err != nil {
		t.Fatalf("find SNI: %v", err)
	}

	splitAt := offset - 5 + len(hostname)/2

	fragmented, err := SplitClientHelloRecord(original, splitAt)
	if err != nil {
		t.Fatalf("split real ClientHello: %v", err)
	}

	firstLength := int(binary.BigEndian.Uint16(fragmented[3:5]))
	secondStart := 5 + firstLength

	if secondStart+5 > len(fragmented) {
		t.Fatal("second TLS record header is missing")
	}

	secondLength := int(binary.BigEndian.Uint16(
		fragmented[secondStart+3 : secondStart+5],
	))

	if firstLength != splitAt {
		t.Fatalf("first record length: got %d, want %d", firstLength, splitAt)
	}

	if secondStart+5+secondLength != len(fragmented) {
		t.Fatal("second TLS record length is incorrect")
	}

	if fragmented[0] != 0x16 || fragmented[secondStart] != 0x16 {
		t.Fatal("expected two TLS handshake records")
	}

	reconstructed := make([]byte, 0, len(original)-5)
	reconstructed = append(reconstructed, fragmented[5:secondStart]...)
	reconstructed = append(reconstructed, fragmented[secondStart+5:]...)

	if !bytes.Equal(reconstructed, original[5:]) {
		t.Fatal("fragmentation modified the ClientHello payload")
	}

	t.Logf("SNI hostname: %s", hostname)
	t.Logf("Split position: %d", splitAt)
	t.Logf("First payload: %d bytes", firstLength)
	t.Logf("Second payload: %d bytes", secondLength)
}

func TestFragmentedClientHelloHandshake(t *testing.T) {
	versions := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13},
	}

	for _, version := range versions {
		t.Run(version.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			)

			server.TLS = &tls.Config{
				MinVersion: version.version,
				MaxVersion: version.version,
			}
			server.StartTLS()
			defer server.Close()

			certificate := server.Certificate()
			if len(certificate.DNSNames) == 0 {
				t.Fatal("test certificate has no DNS names")
			}

			hostname := certificate.DNSNames[0]

			roots := x509.NewCertPool()
			roots.AddCert(certificate)

			positions := []struct {
				name    string
				splitAt func(offset, hostnameLength int) int
			}{
				{
					name: "after handshake header",
					splitAt: func(offset, hostnameLength int) int {
						return 4
					},
				},
				{
					name: "before SNI",
					splitAt: func(offset, hostnameLength int) int {
						return offset - recordHeaderSize
					},
				},
				{
					name: "middle of SNI",
					splitAt: func(offset, hostnameLength int) int {
						return offset - recordHeaderSize + hostnameLength/2
					},
				},
			}

			for _, position := range positions {
				t.Run(position.name, func(t *testing.T) {
					upstream, err := net.Dial(
						"tcp",
						server.Listener.Addr().String(),
					)
					if err != nil {
						t.Fatalf("connect to TLS server: %v", err)
					}
					defer upstream.Close()

					clientSide, proxySide := net.Pipe()
					defer proxySide.Close()

					client := tls.Client(clientSide, &tls.Config{
						ServerName: hostname,
						RootCAs:    roots,
						MinVersion: version.version,
						MaxVersion: version.version,
					})
					defer client.Close()

					deadline := time.Now().Add(5 * time.Second)

					if err := client.SetDeadline(deadline); err != nil {
						t.Fatalf("set client deadline: %v", err)
					}

					if err := upstream.SetDeadline(deadline); err != nil {
						t.Fatalf("set upstream deadline: %v", err)
					}

					forwarded := make(chan error, 1)

					go func() {
						var header [recordHeaderSize]byte

						if _, err := io.ReadFull(proxySide, header[:]); err != nil {
							forwarded <- err
							return
						}

						length := int(binary.BigEndian.Uint16(header[3:5]))
						if length == 0 || length > maxPlaintextSize {
							forwarded <- fmt.Errorf(
								"invalid TLS record length: %d",
								length,
							)
							return
						}

						record := make([]byte, recordHeaderSize+length)
						copy(record, header[:])

						if _, err := io.ReadFull(
							proxySide,
							record[recordHeaderSize:],
						); err != nil {
							forwarded <- err
							return
						}

						name, offset, err := FindServerName(record)
						if err != nil {
							forwarded <- err
							return
						}

						splitAt := position.splitAt(offset, len(name))

						fragmented, err := SplitClientHelloRecord(
							record,
							splitAt,
						)
						if err != nil {
							forwarded <- err
							return
						}

						if _, err := io.Copy(
							upstream,
							bytes.NewReader(fragmented),
						); err != nil {
							forwarded <- err
							return
						}

						forwarded <- nil

						// Continue the remaining handshake in both directions.
						go io.Copy(proxySide, upstream)
						io.Copy(upstream, proxySide)
					}()

					handshakeErr := client.Handshake()
					forwardErr := <-forwarded

					if forwardErr != nil {
						t.Fatalf(
							"forward fragmented ClientHello: %v",
							forwardErr,
						)
					}

					if handshakeErr != nil {
						t.Fatalf(
							"TLS handshake failed: %v",
							handshakeErr,
						)
					}

					state := client.ConnectionState()

					if state.Version != version.version {
						t.Fatalf(
							"negotiated version: got 0x%04x, want 0x%04x",
							state.Version,
							version.version,
						)
					}

					if len(state.VerifiedChains) == 0 {
						t.Fatal("TLS certificate was not verified")
					}

					t.Logf(
						"handshake completed with TLS version 0x%04x",
						state.Version,
					)
				})
			}
		})
	}
}

func TestSplitUpdaterShapedClientHello(t *testing.T) {
	const (
		hostname   = "updates.discord.com"
		recordSize = 179
	)

	// Start with a valid ClientHello containing an SNI extension.
	original := makeTestClientHello(hostname)

	// Add a padding extension to construct a 179-byte record.
	paddingLength := recordSize - len(original) - 4
	if paddingLength < 0 {
		t.Fatal("base ClientHello exceeds target record size")
	}

	paddingExtension := make([]byte, 4+paddingLength)
	binary.BigEndian.PutUint16(paddingExtension[0:2], 0x0015)
	binary.BigEndian.PutUint16(
		paddingExtension[2:4],
		uint16(paddingLength),
	)

	// Locate the extensions length field in our test fixture.
	// The fixture contains a fixed-size session ID, cipher suite
	// and compression methods section before its extensions.
	const extensionsLengthOffset = 50

	oldExtensionsLength := int(binary.BigEndian.Uint16(
		original[extensionsLengthOffset : extensionsLengthOffset+2],
	))

	original = append(original, paddingExtension...)

	binary.BigEndian.PutUint16(
		original[extensionsLengthOffset:extensionsLengthOffset+2],
		uint16(oldExtensionsLength+len(paddingExtension)),
	)

	// Update the TLS record and handshake lengths.
	binary.BigEndian.PutUint16(
		original[3:5],
		uint16(len(original)-5),
	)

	handshakeLength := len(original) - 9
	original[6] = byte(handshakeLength >> 16)
	original[7] = byte(handshakeLength >> 8)
	original[8] = byte(handshakeLength)

	// Match the record-layer version observed in the updater.
	original[2] = 0x01

	if len(original) != recordSize {
		t.Fatalf(
			"unexpected ClientHello size: got %d, want %d",
			len(original),
			recordSize,
		)
	}

	name, offset, err := FindServerName(original)
	if err != nil {
		t.Fatalf("find updater-shaped ClientHello SNI: %v", err)
	}

	if name != hostname {
		t.Fatalf("unexpected SNI: got %q, want %q", name, hostname)
	}

	splitAt := offset - 5 + len(name)/2

	fragmented, err := SplitClientHelloRecord(original, splitAt)
	if err != nil {
		t.Fatalf("split updater-shaped ClientHello: %v", err)
	}

	firstLength := int(binary.BigEndian.Uint16(fragmented[3:5]))
	secondStart := 5 + firstLength

	if secondStart+5 > len(fragmented) {
		t.Fatal("second TLS record header is missing")
	}

	secondLength := int(binary.BigEndian.Uint16(
		fragmented[secondStart+3 : secondStart+5],
	))

	if secondStart+5+secondLength != len(fragmented) {
		t.Fatal("invalid second TLS record length")
	}

	if fragmented[0] != 0x16 || fragmented[secondStart] != 0x16 {
		t.Fatal("expected two TLS handshake records")
	}

	if fragmented[2] != 0x01 || fragmented[secondStart+2] != 0x01 {
		t.Fatal("TLS record version was not preserved")
	}

	reconstructed := append(
		[]byte{},
		fragmented[5:secondStart]...,
	)
	reconstructed = append(
		reconstructed,
		fragmented[secondStart+5:]...,
	)

	if !bytes.Equal(reconstructed, original[5:]) {
		t.Fatal("fragmentation modified the ClientHello payload")
	}

	t.Logf("ClientHello size: %d bytes", len(original))
	t.Logf("SNI: %s", name)
	t.Logf("Split position: %d", splitAt)
	t.Logf("First record payload: %d bytes", firstLength)
	t.Logf("Second record payload: %d bytes", secondLength)
}

func TestSplitClientHelloRecordAtDifferentPositions(t *testing.T) {
	original := makeTestClientHello("updates.discord.com")

	// Add an empty padding extension so the SNI is no longer the final field in the ClientHello.
	paddingExtension := []byte{
		0x00, 0x15, // Extension type: padding (21).
		0x00, 0x00, // Extension length: 0.
	}

	original = append(original, paddingExtension...)

	// The existing synthetic ClientHello contains one extensions vector.
	// Its two-byte length is immediately before the server_name extension.
	extensionsLengthOffset := len(original) - len(paddingExtension) - (4 + 2 + 3 + len("updates.discord.com")) - 2

	extensionsLength := binary.BigEndian.Uint16(
		original[extensionsLengthOffset : extensionsLengthOffset+2],
	)

	binary.BigEndian.PutUint16(
		original[extensionsLengthOffset:extensionsLengthOffset+2],
		extensionsLength+uint16(len(paddingExtension)),
	)

	// Update the outer TLS record length.
	binary.BigEndian.PutUint16(
		original[3:5],
		uint16(len(original)-recordHeaderSize),
	)

	// Update the three-byte handshake length.
	handshakeLength := len(original) - recordHeaderSize - 4

	original[6] = byte(handshakeLength >> 16)
	original[7] = byte(handshakeLength >> 8)
	original[8] = byte(handshakeLength)

	hostname, offset, err := FindServerName(original)
	if err != nil {
		t.Fatalf("find server name: %v", err)
	}

	sniStart := offset - recordHeaderSize
	sniEnd := sniStart + len(hostname)
	payloadLength := len(original) - recordHeaderSize

	tests := []struct {
		name    string
		splitAt int
	}{
		{
			name:    "after handshake header",
			splitAt: 4,
		},
		{
			name:    "before SNI",
			splitAt: sniStart,
		},
		{
			name:    "middle of SNI",
			splitAt: sniStart + len(hostname)/2,
		},
		{
			name:    "after SNI",
			splitAt: sniEnd,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fragmented, err := SplitClientHelloRecord(original, tt.splitAt)
			if err != nil {
				t.Fatalf("split ClientHello: %v", err)
			}

			if len(fragmented) != len(original)+recordHeaderSize {
				t.Fatalf("unexpected fragmented size: %d", len(fragmented))
			}

			firstLength := int(binary.BigEndian.Uint16(fragmented[3:5]))
			secondStart := recordHeaderSize + firstLength

			if firstLength != tt.splitAt {
				t.Fatalf("first record length: got %d, want %d",
					firstLength, tt.splitAt)
			}

			if secondStart+recordHeaderSize > len(fragmented) {
				t.Fatal("second TLS record header is missing")
			}

			secondLength := int(binary.BigEndian.Uint16(
				fragmented[secondStart+3 : secondStart+5],
			))

			if secondLength != payloadLength-tt.splitAt {
				t.Fatalf("unexpected second record length: %d",
					secondLength)
			}

			if fragmented[0] != 0x16 || fragmented[secondStart] != 0x16 {
				t.Fatal("expected two TLS handshake records")
			}

			if !bytes.Equal(fragmented[:3], original[:3]) ||
				!bytes.Equal(fragmented[secondStart:secondStart+3], original[:3]) {
				t.Fatal("TLS record type or version was modified")
			}

			reconstructed := make([]byte, 0, payloadLength)
			reconstructed = append(
				reconstructed,
				fragmented[recordHeaderSize:secondStart]...,
			)
			reconstructed = append(
				reconstructed,
				fragmented[secondStart+recordHeaderSize:]...,
			)

			if !bytes.Equal(reconstructed, original[recordHeaderSize:]) {
				t.Fatal("fragmentation modified the ClientHello payload")
			}
		})
	}
}

func TestForwardInitialRecordWithStrategy(t *testing.T) {
	original := makeTestClientHello("updates.discord.com")

	hostname, offset, err := FindServerName(original)
	if err != nil {
		t.Fatalf("find server name: %v", err)
	}

	sniStart := offset - recordHeaderSize

	tests := []struct {
		name     string
		strategy Strategy
		splitAt  int
	}{
		{
			name:     "SNI midpoint",
			strategy: StrategySNIMidpoint,
			splitAt:  sniStart + len(hostname)/2,
		},
		{
			name:     "before SNI",
			strategy: StrategyBeforeSNI,
			splitAt:  sniStart,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer

			err := ForwardInitialRecordWithStrategy(
				&output,
				bytes.NewReader(original),
				tt.strategy,
			)
			if err != nil {
				t.Fatalf("forward initial TLS record: %v", err)
			}

			fragmented := output.Bytes()

			if len(fragmented) != len(original)+recordHeaderSize {
				t.Fatalf(
					"unexpected output length: got %d, want %d",
					len(fragmented),
					len(original)+recordHeaderSize,
				)
			}

			firstLength := int(binary.BigEndian.Uint16(
				fragmented[3:5],
			))

			if firstLength != tt.splitAt {
				t.Fatalf(
					"unexpected split position: got %d, want %d",
					firstLength,
					tt.splitAt,
				)
			}

			secondStart := recordHeaderSize + firstLength

			if secondStart+recordHeaderSize > len(fragmented) {
				t.Fatal("second TLS record header is missing")
			}

			secondLength := int(binary.BigEndian.Uint16(
				fragmented[secondStart+3 : secondStart+5],
			))

			if secondStart+recordHeaderSize+secondLength != len(fragmented) {
				t.Fatal("invalid second TLS record length")
			}

			if fragmented[0] != 0x16 || fragmented[secondStart] != 0x16 {
				t.Fatal("expected two TLS handshake records")
			}

			reconstructed := make([]byte, 0, len(original)-recordHeaderSize)
			reconstructed = append(
				reconstructed,
				fragmented[recordHeaderSize:secondStart]...,
			)
			reconstructed = append(
				reconstructed,
				fragmented[secondStart+recordHeaderSize:]...,
			)

			if !bytes.Equal(reconstructed, original[recordHeaderSize:]) {
				t.Fatal("fragmentation changed the ClientHello payload")
			}
		})
	}
}

func TestForwardInitialRecordRejectsUnknownStrategy(t *testing.T) {
	var output bytes.Buffer

	err := ForwardInitialRecordWithStrategy(
		&output,
		bytes.NewReader(makeTestClientHello("example.com")),
		Strategy("unknown"),
	)

	if err == nil {
		t.Fatal("expected unsupported strategy error")
	}

	if !strings.Contains(err.Error(), "unsupported TLS fragmentation strategy") {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.Len() != 0 {
		t.Fatal("unexpected output for unsupported strategy")
	}
}

func TestForwardInitialRecordPreservesDefaultStrategy(t *testing.T) {
	original := makeTestClientHello("updates.discord.com")

	var defaultOutput bytes.Buffer
	var explicitOutput bytes.Buffer

	if err := ForwardInitialRecord(
		&defaultOutput,
		bytes.NewReader(original),
	); err != nil {
		t.Fatalf("forward with default strategy: %v", err)
	}

	if err := ForwardInitialRecordWithStrategy(
		&explicitOutput,
		bytes.NewReader(original),
		StrategySNIMidpoint,
	); err != nil {
		t.Fatalf("forward with explicit default strategy: %v", err)
	}

	if !bytes.Equal(defaultOutput.Bytes(), explicitOutput.Bytes()) {
		t.Fatal("default fragmentation behavior changed")
	}
}
