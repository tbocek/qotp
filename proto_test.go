package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to encode payload and assert no error
func encodePayload(payload *PayloadHeader, data []byte) []byte {
	encoded, _ := EncodePayload(payload, data)
	return encoded
}

func mustDecodePayload(t *testing.T, encoded []byte) (*PayloadHeader, []byte) {
	decoded, data, err := DecodePayload(encoded)
	require.NoError(t, err)
	return decoded, data
}

func roundTripPayload(t *testing.T, payload *PayloadHeader, data []byte) (*PayloadHeader, []byte) {
	encoded := encodePayload(payload, data)
	return mustDecodePayload(t, encoded)
}

func assertPayloadMatches(t *testing.T, expected, actual *PayloadHeader) {
	assert.Equal(t, expected.StreamID, actual.StreamID)
	assert.Equal(t, expected.StreamOffset, actual.StreamOffset)
	assert.Equal(t, expected.IsClose, actual.IsClose)
	assert.Equal(t, expected.IsNoRetry, actual.IsNoRetry)

	// Don't compare RcvWndSize directly - it gets encoded/decoded with precision loss
	// Instead, compare the expected behavior:
	if expected.IsClose {
		assert.Equal(t, uint64(0), actual.RcvWndSize, "Close flag should set RcvWndSize to 0")
	} else {
		assertRcvWindowInRange(t, expected.RcvWndSize, actual.RcvWndSize)
	}

	if expected.Ack == nil {
		assert.Nil(t, actual.Ack)
	} else {
		require.NotNil(t, actual.Ack)
		assert.Equal(t, expected.Ack.streamID, actual.Ack.streamID)
		assert.Equal(t, expected.Ack.offset, actual.Ack.offset)
		assert.Equal(t, expected.Ack.len, actual.Ack.len)
	}
}

func assertRcvWindowInRange(t *testing.T, original, decoded uint64) {
	encoded := EncodeRcvWindow(original)
	expectedDecoded := DecodeRcvWindow(encoded)
	assert.Equal(t, expectedDecoded, decoded,
		"RcvWndSize should match encode/decode result: %d -> encode(%d) -> decode(%d)",
		original, encoded, expectedDecoded)
}

// =============================================================================
// Basic Payload Tests - Simple cases with minimal features
// =============================================================================

func TestPayloadMinimal(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     12345,
		StreamOffset: 0,
	}

	decoded, decodedData := roundTripPayload(t, original, []byte{})

	assertPayloadMatches(t, original, decoded)
	assert.Empty(t, decodedData)
}

func TestPayloadEmptyData(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 100,
	}

	decoded, decodedData := roundTripPayload(t, original, []byte{})

	assertPayloadMatches(t, original, decoded)
	assert.Empty(t, decodedData)
}

// =============================================================================
// Feature Combination Tests - Testing different flag combinations
// =============================================================================

func TestPayloadWithAllFeaturesCloseFlag(t *testing.T) {
	original := &PayloadHeader{
		IsClose:      true,
		IsNoRetry:    true,
		StreamID:     1,
		StreamOffset: 9999,
		RcvWndSize:   1000,
		Ack:          &Ack{streamID: 1, offset: 123456, len: 10},
	}

	originalData := []byte("test data")
	decoded, decodedData := roundTripPayload(t, original, originalData)

	assertPayloadMatches(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
	assert.Equal(t, uint64(0), decoded.RcvWndSize) // Close flag sets RcvWndSize to 0
}

func TestPayloadWithAllFeaturesNoCloseFlag(t *testing.T) {
	original := &PayloadHeader{
		IsClose:      false,
		IsNoRetry:    true,
		StreamID:     1,
		StreamOffset: 9999,
		RcvWndSize:   1000,
		Ack:          &Ack{streamID: 1, offset: 123456, len: 10},
	}

	originalData := []byte("test data")
	decoded, decodedData := roundTripPayload(t, original, originalData)

	assertPayloadMatches(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
	assert.Equal(t, uint64(1024), decoded.RcvWndSize) // Without close flag, gets encoded value
}

func TestPayloadMultipleFlagsWithAck(t *testing.T) {
	original := &PayloadHeader{
		IsNoRetry:    true,
		IsClose:      true,
		RcvWndSize:   0, // Will be ignored due to IsClose
		StreamID:     6,
		StreamOffset: 2000,
		Ack:          &Ack{streamID: 60, offset: 3000, len: 400},
	}
	originalData := []byte("closing data")

	decoded, decodedData := roundTripPayload(t, original, originalData)

	assertPayloadMatches(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

// =============================================================================
// ACK Tests - Testing ACK functionality in various scenarios
// =============================================================================

func TestPayloadAckHandling(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 100,
		Ack:          &Ack{streamID: 0, offset: 0, len: 0},
		RcvWndSize:   1000,
	}

	decoded, _ := roundTripPayload(t, original, []byte("test"))

	assertPayloadMatches(t, original, decoded)
}

func TestPayloadAckOnlyNoData(t *testing.T) {
	original := &PayloadHeader{
		IsNoRetry:    false,
		IsClose:      false,
		RcvWndSize:   1000,
		StreamID:     1,
		StreamOffset: 100,
		Ack:          &Ack{streamID: 10, offset: 200, len: 300},
	}

	decoded, decodedData := roundTripPayload(t, original, []byte{})

	assertPayloadMatches(t, original, decoded)
	assert.Empty(t, decodedData)
}

func TestPayloadAckWithData(t *testing.T) {
	original := &PayloadHeader{
		IsNoRetry:    true,
		IsClose:      false,
		RcvWndSize:   2000,
		StreamID:     2,
		StreamOffset: 500,
		Ack:          &Ack{streamID: 20, offset: 1000, len: 1500},
	}
	originalData := []byte("test data")

	decoded, decodedData := roundTripPayload(t, original, originalData)

	assertPayloadMatches(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

func TestPayloadNoAckDataOnly(t *testing.T) {
	original := &PayloadHeader{
		IsNoRetry:    true,
		IsClose:      false,
		RcvWndSize:   3000,
		StreamID:     3,
		StreamOffset: 1000,
		Ack:          nil,
	}
	originalData := []byte("more test data")

	decoded, decodedData := roundTripPayload(t, original, originalData)

	assertPayloadMatches(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

func TestPayloadAckLargeOffset24Bit(t *testing.T) {
	original := &PayloadHeader{
		IsNoRetry:    false,
		IsClose:      false,
		RcvWndSize:   4000,
		StreamID:     4,
		StreamOffset: 0xFFFFFE, // Just under 24-bit limit
		Ack:          &Ack{streamID: 40, offset: 0xFFFFFE, len: 100},
	}

	decoded, decodedData := roundTripPayload(t, original, []byte{})

	assertPayloadMatches(t, original, decoded)
	assert.Empty(t, decodedData)
}

func TestPayloadAckLargeOffset48Bit(t *testing.T) {
	original := &PayloadHeader{
		IsNoRetry:    false,
		IsClose:      false,
		RcvWndSize:   5000,
		StreamID:     5,
		StreamOffset: 0x1000000, // Requires 48-bit
		Ack:          &Ack{streamID: 50, offset: 0x1000000, len: 200},
	}

	decoded, decodedData := roundTripPayload(t, original, []byte{})

	assertPayloadMatches(t, original, decoded)
	assert.Empty(t, decodedData)
}

// =============================================================================
// ACK Flag Bit Tests - Testing internal flag encoding
// =============================================================================

func TestPayloadAckFlagBitsWithAck(t *testing.T) {
	payload := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 0,
		Ack:          &Ack{streamID: 10, offset: 0, len: 100},
	}

	encoded := encodePayload(payload, []byte{})
	flags := encoded[0]
	ackPack := (flags >> 1) & 0x03

	assert.Equal(t, uint8(2), ackPack, "Should be type 2 (ACK with 24-bit)")

	decoded, _ := mustDecodePayload(t, encoded)
	assert.NotNil(t, decoded.Ack)
}

func TestPayloadAckFlagBitsNoAck(t *testing.T) {
	payload := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 0,
		Ack:          nil,
	}

	encoded := encodePayload(payload, []byte{})
	flags := encoded[0]
	ackPack := (flags >> 1) & 0x03

	assert.Equal(t, uint8(0), ackPack, "Should be type 0 (no ACK with 24-bit)")

	decoded, _ := mustDecodePayload(t, encoded)
	assert.Nil(t, decoded.Ack)
}

// =============================================================================
// Receive Window Tests - Testing window size encoding/decoding
// =============================================================================

func TestPayloadDecodeRcvWindow(t *testing.T) {
	testCases := []struct {
		input    uint8
		expected uint64
		desc     string
	}{
		{0, 0, "zero"},
		{1, 512, "512B"},
		{2, 1024, "1KB"},
		{3, 2048, "2KB"},
		{4, 4096, "4KB"},
		{5, 8192, "8KB"},
		{7, 32768, "32KB"},
		{10, 262144, "256KB"},
		{11, 524288, "512KB"},
		{12, 1048576, "1MB"},
		{20, 268435456, "256MB"},
		{22, 1073741824, "1GB"},
		{29, 137438953472, "128GB"},
	}
	for _, tc := range testCases {
		result := DecodeRcvWindow(tc.input)
		assert.Equal(t, tc.expected, result, "DecodeRcvWindow(%d) should return %s", tc.input, tc.desc)
	}
}

func TestPayloadEncodeRcvWindow(t *testing.T) {
	testCases := []struct {
		input    uint64
		expected uint8
		desc     string
	}{
		// Zero and below/at 512
		{0, 0, "zero"},
		{1, 1, "1 byte"},
		{256, 1, "256 bytes"},
		{512, 1, "exactly 512"},
		// 513-1024 range
		{513, 2, "just above 512"},
		{700, 2, "between 512-1024"},
		{1024, 2, "exactly 1KB"},
		// Higher ranges
		{1025, 3, "just above 1KB"},
		{2048, 3, "exactly 2KB"},
		{2049, 4, "just above 2KB"},
		{4096, 4, "exactly 4KB"},
		{4097, 5, "just above 4KB"},
		{8192, 5, "exactly 8KB"},
		{8193, 6, "just above 8KB"},
		{16384, 6, "exactly 16KB"},
		{16385, 7, "just above 16KB"},
		{32768, 7, "exactly 32KB"},
		{32769, 8, "just above 32KB"},
		{65536, 8, "exactly 64KB"},
		{65537, 9, "just above 64KB"},
		{131072, 9, "exactly 128KB"},
		{131073, 10, "just above 128KB"},
		{262144, 10, "exactly 256KB"},
		{262145, 11, "just above 256KB"},
		{524288, 11, "exactly 512KB"},
		{524289, 12, "just above 512KB"},
		{1048576, 12, "exactly 1MB"},
		{1048577, 13, "just above 1MB"},
		// Between powers
		{1500, 3, "between 1-2KB"},
		{3000, 4, "between 2-4KB"},
		{5000, 5, "between 4-8KB"},
		{10000, 6, "between 8-16KB"},
		{20000, 7, "between 16-32KB"},
		{50000, 8, "between 32-64KB"},
		{100000, 9, "between 64-128KB"},
		{200000, 10, "between 128-256KB"},
		{400000, 11, "between 256-512KB"},
		{800000, 12, "between 512KB-1MB"},
		{1500000, 13, "between 1-2MB"},
		// Large values
		{1073741824, 22, "1GB"},
		{2147483648, 23, "2GB"},
		{17179869184, 26, "16GB"},
		{34359738368, 27, "32GB"},
		{68719476736, 28, "64GB"},
		{137438953472, 29, "128GB"},
		// Very large values (capped at 29)
		{1 << 40, 29, "1TB"},
		{1 << 45, 29, "32TB"},
		{^uint64(0), 29, "max uint64"},
	}
	for _, tc := range testCases {
		result := EncodeRcvWindow(tc.input)
		assert.Equal(t, tc.expected, result, "EncodeRcvWindow(%d) should return %d (%s)", tc.input, tc.expected, tc.desc)
	}
}

func TestPayloadEncodeDecodeRoundTrip(t *testing.T) {
	testCases := []struct {
		input    uint64
		expected uint64
		desc     string
	}{
		// Special cases
		{0, 0, "zero"},
		{400, 512, "below 512 -> 512"},
		{700, 1024, "between 512-1024 -> 1024"},
		// Powers of 2 decode to themselves
		{512, 512, "512B"},
		{1024, 1024, "1KB"},
		{2048, 2048, "2KB"},
		{4096, 4096, "4KB"},
		{8192, 8192, "8KB"},
		{16384, 16384, "16KB"},
		{32768, 32768, "32KB"},
		{65536, 65536, "64KB"},
		{131072, 131072, "128KB"},
		{262144, 262144, "256KB"},
		{524288, 524288, "512KB"},
		{1048576, 1048576, "1MB"},
		// Edge cases - values get rounded up to next power
		{1025, 2048, "just above 1KB -> 2KB"},
		{2047, 2048, "just below 2KB -> 2KB"},
		{2049, 4096, "just above 2KB -> 4KB"},
		{4095, 4096, "just below 4KB -> 4KB"},
	}
	for _, tc := range testCases {
		encoded := EncodeRcvWindow(tc.input)
		decoded := DecodeRcvWindow(encoded)
		assert.Equal(t, tc.expected, decoded, "Round trip %s: input=%d, encoded=%d, decoded=%d", tc.desc, tc.input, encoded, decoded)
	}
}

// =============================================================================
// Size Validation Tests - Testing correct minimum sizes
// =============================================================================

func TestPayloadMinimumSizeNoAck24Bit(t *testing.T) {
	payload := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 0,
	}

	encoded := encodePayload(payload, []byte{})
	assert.Equal(t, 8, len(encoded), "No ACK, 24-bit should be 8 bytes")
}

func TestPayloadMinimumSizeNoAck48Bit(t *testing.T) {
	payload := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 0x1000000,
	}

	encoded := encodePayload(payload, []byte{})
	assert.Equal(t, 11, len(encoded), "No ACK, 48-bit should be 11 bytes")
}

func TestPayloadMinimumSizeWithAck24Bit(t *testing.T) {
	payload := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 0,
		Ack:          &Ack{streamID: 10, offset: 0, len: 100},
	}

	encoded := encodePayload(payload, []byte{})
	assert.Equal(t, 17, len(encoded), "With ACK, 24-bit should be 17 bytes")
}

func TestPayloadMinimumSizeWithAck48Bit(t *testing.T) {
	payload := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 0x1000000,
		Ack:          &Ack{streamID: 10, offset: 0x1000000, len: 100},
	}

	encoded := encodePayload(payload, []byte{})
	assert.Equal(t, 23, len(encoded), "With ACK, 48-bit should be 23 bytes")
}

// =============================================================================
// Exact Size Boundary Tests - Testing exact minimum size requirements
// =============================================================================

func TestPayloadExactMinimumSize(t *testing.T) {
	// Create valid 8-byte payload (no ACK, 24-bit, no data)
	data := []byte{
		0x00,                   // flags: no ping, no ACK, no close
		0x01, 0x00, 0x00, 0x00, // streamID = 1
		0x64, 0x00, 0x00, // streamOffset = 100 (24-bit)
	}

	decoded, userData, err := DecodePayload(data)
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), decoded.StreamID)
	assert.Equal(t, uint64(100), decoded.StreamOffset)
	assert.Empty(t, userData)
}

func TestPayloadExactRequiredSizeNoACK24bit(t *testing.T) {
	data := make([]byte, 8) // Exact size needed
	data[0] = 0x00          // flags: no ACK, 24-bit
	// streamID=1, streamOffset=100
	copy(data[1:], []byte{0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00})

	// Should succeed with exact size
	_, _, err := DecodePayload(data)
	assert.NoError(t, err)
}

func TestPayloadExactRequiredSizeNoACK48bit(t *testing.T) {
	data := make([]byte, 11) // Exact size needed
	data[0] = 0x02           // flags: no ACK, 48-bit
	// streamID=1, streamOffset=0x1000000 (48-bit)
	copy(data[1:], []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00})

	// Should succeed with exact size
	_, _, err := DecodePayload(data)
	assert.NoError(t, err)
}

func TestPayloadExactRequiredSizeWithACK24bit(t *testing.T) {
	data := make([]byte, 17) // Exact size needed
	data[0] = 0x04           // flags: ACK present, 24-bit
	// ACK: streamID=10, offset=200, len=50
	// Data: streamID=1, streamOffset=100
	copy(data[1:], []byte{
		0x0A, 0x00, 0x00, 0x00, // ACK streamID
		0xC8, 0x00, 0x00, // ACK offset (200)
		0x32, 0x00, // ACK len (50)
		0x01, 0x00, 0x00, 0x00, // Data streamID
		0x64, 0x00, 0x00, // Data streamOffset (100)
	})

	// Should succeed with exact size
	_, _, err := DecodePayload(data)
	assert.NoError(t, err)
}

func TestPayloadExactRequiredSizeWithACK48bit(t *testing.T) {
	data := make([]byte, 23) // Exact size needed
	data[0] = 0x06           // flags: ACK present, 48-bit
	// ACK: streamID=10, offset=0x1000000, len=50
	// Data: streamID=1, streamOffset=0x1000000
	copy(data[1:], []byte{
		0x0A, 0x00, 0x00, 0x00, // ACK streamID
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // ACK offset (48-bit)
		0x32, 0x00, // ACK len (50)
		0x01, 0x00, 0x00, 0x00, // Data streamID
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // Data streamOffset (48-bit)
	})

	// Should succeed with exact size
	_, _, err := DecodePayload(data)
	assert.NoError(t, err)
}

// =============================================================================
// Error Condition Tests - Testing invalid inputs and buffer overruns
// =============================================================================

func TestPayloadBelowMinimumSizeEmpty(t *testing.T) {
	data := []byte{}
	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "minimum")
}

func TestPayloadBelowMinimumSize1Byte(t *testing.T) {
	data := make([]byte, 1)
	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "minimum")
}

func TestPayloadBelowMinimumSize7Bytes(t *testing.T) {
	data := make([]byte, 7)
	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "minimum")
}

func TestPayloadHeaderSizeMismatchACK24bit(t *testing.T) {
	// Flags indicate ACK present + 24-bit (needs 17 bytes total)
	// But only provide 16 bytes
	data := make([]byte, 16)
	data[0] = 0x04 // flags: ACK present, 24-bit mode

	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "minimum")
}

func TestPayloadHeaderSizeMismatchACK48bit(t *testing.T) {
	// Flags indicate ACK present + 48-bit (needs 23 bytes total)
	// But only provide 22 bytes
	data := make([]byte, 22)
	data[0] = 0x06 // flags: ACK present, 48-bit mode

	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "minimum")
}

func TestPayloadHeaderSizeMismatch48bitNoACK(t *testing.T) {
	// Flags indicate 48-bit mode, no ACK (needs 11 bytes total)
	// But only provide 10 bytes
	data := make([]byte, 10)
	data[0] = 0x02 // flags: no ACK, 48-bit mode

	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "minimum")
}

func TestPayloadBufferOverrunProtection(t *testing.T) {
	// Test that decoder doesn't read past buffer when flags indicate more data
	data := []byte{0x06} // Flags indicate ACK + 48-bit, but buffer is too short

	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	// Should not panic or read past buffer
}
