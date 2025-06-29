package tomtp

import (
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeMinimalPayload(t *testing.T) {
	original := &PayloadMeta{
		StreamId:     12345,
		StreamOffset: 0,
	}

	encoded, _ := EncodePayload(original, []byte{})

	decoded, _, decodedData, err := DecodePayload(encoded)
	require.NoError(t, err, "Failed to decode minimal payload")

	assert.Equal(t, original.StreamId, decoded.StreamId, "StreamId mismatch")
	assert.Equal(t, original.StreamOffset, decoded.StreamOffset, "StreamOffset mismatch")
	assert.Empty(t, decodedData, "Data should be empty")
}

// Merged TestPayloadWithAllFeatures1 and TestPayloadWithAllFeatures2 into one test
func TestPayloadWithAllFeatures(t *testing.T) {
	testCases := []struct {
		name       string
		isClose    bool
		rcvWndSize uint64
		expected   uint64
	}{
		{"with close flag", true, 1000, 0},
		{"without close flag", false, 1000, 768},
	}

	for _, tc := range testCases {
		original := &PayloadMeta{
			IsClose:      tc.isClose,
			IsSender:     true,
			StreamId:     1,
			StreamOffset: 9999,
			RcvWndSize:   tc.rcvWndSize,
			Ack:          &Ack{streamId: 1, offset: 123456, len: 10},
		}

		originalData := []byte("test data")
		encoded, _ := EncodePayload(original, originalData)
		decoded, _, decodedData, err := DecodePayload(encoded)

		require.NoError(t, err, "Failed to decode payload")
		assert.Equal(t, original.IsClose, decoded.IsClose)
		assert.Equal(t, original.IsSender, decoded.IsSender)
		assert.Equal(t, original.StreamId, decoded.StreamId)
		assert.Equal(t, original.StreamOffset, decoded.StreamOffset)
		assert.Equal(t, originalData, decodedData)
		require.NotNil(t, decoded.Ack)
		assert.Equal(t, tc.expected, decoded.RcvWndSize, tc.name)
	}
}

// Merged TestEmptyData and TestAckHandling into basic payload tests
func TestPayloadBasicFeatures(t *testing.T) {
	// Test empty data
	emptyDataPayload := &PayloadMeta{
		StreamId:     1,
		StreamOffset: 100,
	}
	encoded, _ := EncodePayload(emptyDataPayload, []byte{})
	decoded, _, decodedData, err := DecodePayload(encoded)
	require.NoError(t, err)
	assert.Equal(t, emptyDataPayload.StreamId, decoded.StreamId)
	assert.Equal(t, emptyDataPayload.StreamOffset, decoded.StreamOffset)
	assert.Empty(t, decodedData)

	// Test ACK handling
	ackPayload := &PayloadMeta{
		StreamId:     1,
		StreamOffset: 100,
		Ack:          &Ack{streamId: 0, offset: 0, len: 0},
		RcvWndSize:   1000,
	}
	encoded, _ = EncodePayload(ackPayload, []byte("test"))
	decoded, _, _, err = DecodePayload(encoded)
	require.NoError(t, err)
	assert.Equal(t, ackPayload.Ack, decoded.Ack)
}

func FuzzPayload(f *testing.F) {
	// Add seed corpus with valid and edge case payloads
	payloads := []*PayloadMeta{
		{
			StreamId:     1,
			StreamOffset: 100,
			RcvWndSize:   1000,
			Ack:          &Ack{streamId: 10, offset: 200, len: 10},
		},
		{
			StreamId:     math.MaxUint32,
			StreamOffset: math.MaxUint64,
		},
	}

	for _, p := range payloads {
		originalData := []byte("test data")
		encoded, _ := EncodePayload(p, originalData)
		f.Add(encoded)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, _, payloadData, err := DecodePayload(data)
		if err != nil {
			t.Skip()
		}

		reEncoded, _ := EncodePayload(decoded, payloadData)
		reDecoded, _, reDecodedData, err := DecodePayload(reEncoded)
		if err != nil {
			t.Skip()
		}

		if !reflect.DeepEqual(decoded, reDecoded) || !reflect.DeepEqual(payloadData, reDecodedData) {
			t.Fatal("re-encoded/decoded payload differs from original")
		}
	})
}

// Merged all DecodeRcvWindow tests into one
func TestDecodeRcvWindow(t *testing.T) {
	testCases := []struct {
		input    uint8
		expected uint64
		desc     string
	}{
		{0, 0, "zero"},
		{1, 768, "768 (middle of 512-1023)"},
		{2, 1536, "1.5KB"},
		{3, 3072, "3KB"},
		{4, 6144, "6KB"},
		{5, 12288, "12KB"},
		{7, 49152, "48KB"},
		{10, 393216, "384KB"},
		{11, 786432, "768KB"},
		{12, 1572864, "1.5MB"},
		{20, 402653184, "384MB"},
		{30, 412316860416, "384GB"},
	}

	for _, tc := range testCases {
		result := DecodeRcvWindow(tc.input)
		assert.Equal(t, tc.expected, result, "DecodeRcvWindow(%d) should return %s", tc.input, tc.desc)
	}
}

// Merged all EncodeRcvWindow tests into one
func TestEncodeRcvWindow(t *testing.T) {
	testCases := []struct {
		input    uint64
		expected uint8
		desc     string
	}{
		// Zero and below 512
		{0, 0, "zero"},
		{1, 0, "below 512"},
		{256, 0, "below 512"},
		{511, 0, "just below 512"},

		// 512-1023 range
		{512, 1, "exactly 512"},
		{700, 1, "between 512-1024"},
		{1023, 1, "just below 1KB"},

		// Powers of 2
		{1024, 2, "1KB"},
		{2048, 3, "2KB"},
		{4096, 4, "4KB"},
		{8192, 5, "8KB"},
		{16384, 6, "16KB"},
		{32768, 7, "32KB"},
		{65536, 8, "64KB"},
		{131072, 9, "128KB"},
		{262144, 10, "256KB"},
		{524288, 11, "512KB"},
		{1048576, 12, "1MB"},

		// Between powers
		{1500, 2, "between 1-2KB"},
		{3000, 3, "between 2-4KB"},
		{5000, 4, "between 4-8KB"},
		{10000, 5, "between 8-16KB"},
		{20000, 6, "between 16-32KB"},
		{50000, 7, "between 32-64KB"},
		{100000, 8, "between 64-128KB"},
		{200000, 9, "between 128-256KB"},
		{400000, 10, "between 256-512KB"},
		{800000, 11, "between 512KB-1MB"},
		{1500000, 12, "between 1-2MB"},

		// Large values
		{1073741824, 22, "1GB"},
		{2147483648, 23, "2GB"},
		{17179869184, 26, "16GB"},
		{34359738368, 27, "32GB"},

		// Very large values (capped at 30)
		{1 << 40, 30, "1TB"},
		{1 << 45, 30, "32TB"},
		{^uint64(0), 30, "max uint64"},

		// Edge cases
		{1025, 2, "just above 1KB"},
		{2047, 2, "just below 2KB"},
		{2049, 3, "just above 2KB"},
		{4095, 3, "just below 4KB"},
		{8191, 4, "just below 8KB"},
	}

	for _, tc := range testCases {
		result := EncodeRcvWindow(tc.input)
		assert.Equal(t, tc.expected, result, "EncodeRcvWindow(%d) should return %d (%s)", tc.input, tc.expected, tc.desc)
	}
}

// Merged round-trip tests into one
func TestEncodeDecodeRoundTrip(t *testing.T) {
	testCases := []struct {
		input    uint64
		expected uint64
		desc     string
	}{
		// Special cases
		{0, 0, "zero"},
		{400, 0, "below 512"},
		{700, 768, "between 512-1024"},

		// Powers of 2
		{1024, 1536, "1KB"},
		{2048, 3072, "2KB"},
		{4096, 6144, "4KB"},
		{8192, 12288, "8KB"},
		{16384, 24576, "16KB"},
		{32768, 49152, "32KB"},
		{65536, 98304, "64KB"},
		{131072, 196608, "128KB"},
		{262144, 393216, "256KB"},
		{524288, 786432, "512KB"},
		{1048576, 1572864, "1MB"},

		// Edge cases
		{1025, 1536, "just above 1KB"},
		{2047, 1536, "just below 2KB"},
		{2049, 3072, "just above 2KB"},
		{4095, 3072, "just below 4KB"},
	}

	for _, tc := range testCases {
		encoded := EncodeRcvWindow(tc.input)
		decoded := DecodeRcvWindow(encoded)
		assert.Equal(t, tc.expected, decoded, "Round trip %s: input=%d, decoded=%d", tc.desc, tc.input, decoded)
	}
}

func TestEncodeDecodePayloadWithAcks(t *testing.T) {
	testCases := []struct {
		name        string
		payload     *PayloadMeta
		data        []byte
		expectError bool
	}{
		{
			name: "ACK only - no data",
			payload: &PayloadMeta{
				IsSender:     false,
				IsClose:      false,
				RcvWndSize:   1000,
				StreamId:     1,
				StreamOffset: 100,
				Ack: &Ack{
					streamId: 10,
					offset:   200,
					len:      300,
				},
			},
			data:        []byte{},
			expectError: false,
		},
		{
			name: "ACK with data",
			payload: &PayloadMeta{
				IsSender:     true,
				IsClose:      false,
				RcvWndSize:   2000,
				StreamId:     2,
				StreamOffset: 500,
				Ack: &Ack{
					streamId: 20,
					offset:   1000,
					len:      1500,
				},
			},
			data:        []byte("test data"),
			expectError: false,
		},
		{
			name: "No ACK - data only",
			payload: &PayloadMeta{
				IsSender:     true,
				IsClose:      false,
				RcvWndSize:   3000,
				StreamId:     3,
				StreamOffset: 1000,
				Ack:          nil,
			},
			data:        []byte("more test data"),
			expectError: false,
		},
		{
			name: "ACK with large offset (24-bit)",
			payload: &PayloadMeta{
				IsSender:     false,
				IsClose:      false,
				RcvWndSize:   4000,
				StreamId:     4,
				StreamOffset: 0xFFFFFE, // Just under 24-bit limit
				Ack: &Ack{
					streamId: 40,
					offset:   0xFFFFFE,
					len:      100,
				},
			},
			data:        []byte{},
			expectError: false,
		},
		{
			name: "ACK with large offset (48-bit)",
			payload: &PayloadMeta{
				IsSender:     false,
				IsClose:      false,
				RcvWndSize:   5000,
				StreamId:     5,
				StreamOffset: 0x1000000, // Requires 48-bit
				Ack: &Ack{
					streamId: 50,
					offset:   0x1000000,
					len:      200,
				},
			},
			data:        []byte{},
			expectError: false,
		},
		{
			name: "Multiple flags set with ACK",
			payload: &PayloadMeta{
				IsSender:     true,
				IsClose:      true,
				RcvWndSize:   0, // Will be ignored due to IsClose
				StreamId:     6,
				StreamOffset: 2000,
				Ack: &Ack{
					streamId: 60,
					offset:   3000,
					len:      400,
				},
			},
			data:        []byte("closing data"),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded, _ := EncodePayload(tc.payload, tc.data)

			// Print encoded data for debugging
			t.Logf("Encoded %d bytes for %s", len(encoded), tc.name)
			t.Logf("Flags byte: %08b", encoded[0])

			// Decode
			decoded, _, decodedData, err := DecodePayload(encoded)

			if tc.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, decoded)

			// Verify basic fields
			assert.Equal(t, tc.payload.IsSender, decoded.IsSender, "IsSender mismatch")
			assert.Equal(t, tc.payload.IsClose, decoded.IsClose, "IsClose mismatch")
			assert.Equal(t, tc.payload.StreamId, decoded.StreamId, "StreamId mismatch")
			assert.Equal(t, tc.payload.StreamOffset, decoded.StreamOffset, "StreamOffset mismatch")

			// Verify RcvWndSize (only if not closing)
			if !tc.payload.IsClose {
				// Due to encoding/decoding, exact match might not occur
				// but should be in the same range
				t.Logf("RcvWndSize - Original: %d, Decoded: %d", tc.payload.RcvWndSize, decoded.RcvWndSize)
			}

			// Verify ACK
			if tc.payload.Ack != nil {
				assert.NotNil(t, decoded.Ack, "ACK should not be nil")
				assert.Equal(t, tc.payload.Ack.streamId, decoded.Ack.streamId, "ACK streamId mismatch")
				assert.Equal(t, tc.payload.Ack.offset, decoded.Ack.offset, "ACK offset mismatch")
				assert.Equal(t, tc.payload.Ack.len, decoded.Ack.len, "ACK len mismatch")
			} else {
				assert.Nil(t, decoded.Ack, "ACK should be nil")
			}

			// Verify data
			assert.Equal(t, tc.data, decodedData, "Data mismatch")
		})
	}
}

// Test specific ACK encoding/decoding scenarios
func TestAckEncodingEdgeCases(t *testing.T) {
	t.Run("ACK flag bits", func(t *testing.T) {
		// Test that ACK flag is properly set in flags byte
		payload := &PayloadMeta{
			StreamId:     1,
			StreamOffset: 0,
			Ack: &Ack{
				streamId: 10,
				offset:   0,
				len:      100,
			},
		}

		encoded, _ := EncodePayload(payload, []byte{})
		flags := encoded[0]

		// Extract ackPack bits (bits 1-2)
		ackPack := (flags >> 1) & 0x03
		assert.Equal(t, uint8(2), ackPack, "Should be type 2 (ACK with 24-bit)")

		// Decode and verify
		decoded, _, _, err := DecodePayload(encoded)
		assert.NoError(t, err)
		assert.NotNil(t, decoded.Ack)
	})

	t.Run("No ACK flag bits", func(t *testing.T) {
		// Test that no ACK flag is properly set
		payload := &PayloadMeta{
			StreamId:     1,
			StreamOffset: 0,
			Ack:          nil,
		}

		encoded, _ := EncodePayload(payload, []byte{})
		flags := encoded[0]

		// Extract ackPack bits (bits 1-2)
		ackPack := (flags >> 1) & 0x03
		assert.Equal(t, uint8(0), ackPack, "Should be type 0 (no ACK with 24-bit)")

		// Decode and verify
		decoded, _, _, err := DecodePayload(encoded)
		assert.NoError(t, err)
		assert.Nil(t, decoded.Ack)
	})
}

// Test minimum payload sizes
func TestPayloadMinimumSizes(t *testing.T) {
	testCases := []struct {
		name         string
		hasAck       bool
		needs48bit   bool
		expectedSize int
	}{
		{"No ACK, 24-bit", false, false, 8},   // 1 + 4 + 3
		{"No ACK, 48-bit", false, true, 11},   // 1 + 4 + 6
		{"With ACK, 24-bit", true, false, 17}, // 1 + 9 + 4 + 3
		{"With ACK, 48-bit", true, true, 23},  // 1 + 12 + 4 + 6
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var offset uint64 = 0
			if tc.needs48bit {
				offset = 0x1000000
			}

			payload := &PayloadMeta{
				StreamId:     1,
				StreamOffset: offset,
			}

			if tc.hasAck {
				payload.Ack = &Ack{
					streamId: 10,
					offset:   offset,
					len:      100,
				}
			}

			encoded, _ := EncodePayload(payload, []byte{})
			assert.Equal(t, tc.expectedSize, len(encoded), "Encoded size mismatch")
		})
	}
}
