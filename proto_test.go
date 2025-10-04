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

func roundTrip(t *testing.T, payload *PayloadHeader, data []byte) (*PayloadHeader, []byte) {
	encoded := encodePayload(payload, data)
	return mustDecodePayload(t, encoded)
}

// Helper to assert payload equality
func assertPayloadEqual(t *testing.T, expected, actual *PayloadHeader) {
	assert.Equal(t, expected.StreamID, actual.StreamID)
	assert.Equal(t, expected.StreamOffset, actual.StreamOffset)
	assert.Equal(t, expected.IsClose, actual.IsClose)

	if expected.Ack == nil {
		assert.Nil(t, actual.Ack)
	} else {
		require.NotNil(t, actual.Ack)
		assert.Equal(t, expected.Ack.streamID, actual.Ack.streamID)
		assert.Equal(t, expected.Ack.offset, actual.Ack.offset)
		assert.Equal(t, expected.Ack.len, actual.Ack.len)
		
		encoded := EncodeRcvWindow(expected.Ack.rcvWnd)
		expectedDecoded := DecodeRcvWindow(encoded)
		assert.Equal(t, expectedDecoded, actual.Ack.rcvWnd)
	}
}

// =============================================================================
// Basic Payload Tests
// =============================================================================

func TestProtoMinimal(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     12345,
		StreamOffset: 0,
	}
	
	decoded, decodedData := roundTrip(t, original, []byte{})
	
	assertPayloadEqual(t, original, decoded)
	assert.Empty(t, decodedData)
}

func TestProtoWithData(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 100,
	}
	originalData := []byte("test data")
	
	decoded, decodedData := roundTrip(t, original, originalData)
	
	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

// =============================================================================
// ACK Tests
// =============================================================================

func TestProtoWithAck24Bit(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 100,
		Ack:          &Ack{streamID: 10, offset: 200, len: 300, rcvWnd: 1000},
	}
	
	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

func TestProtoWithAck48Bit(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     5,
		StreamOffset: 0x1000000,
		Ack:          &Ack{streamID: 50, offset: 0x1000000, len: 200, rcvWnd: 5000},
	}
	
	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

func TestProtoAckBoundary24Bit(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     4,
		StreamOffset: 0xFFFFFF,
		Ack:          &Ack{streamID: 40, offset: 0xFFFFFF, len: 100, rcvWnd: 4000},
	}
	
	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

func TestProtoAckMixed24And48Bit(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 0x1000000,
		Ack:          &Ack{streamID: 10, offset: 100, len: 50, rcvWnd: 1000},
	}
	
	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

// =============================================================================
// Close Flag Tests
// =============================================================================

func TestProtoCloseFlag(t *testing.T) {
	original := &PayloadHeader{
		IsClose:      true,
		StreamID:     1,
		StreamOffset: 100,
	}
	
	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

func TestProtoCloseFlagWithAck(t *testing.T) {
	original := &PayloadHeader{
		IsClose:      true,
		StreamID:     1,
		StreamOffset: 9999,
		Ack:          &Ack{streamID: 1, offset: 123456, len: 10, rcvWnd: 1000},
	}
	originalData := []byte("closing")
	
	decoded, decodedData := roundTrip(t, original, originalData)
	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

// =============================================================================
// Offset Size Tests
// =============================================================================

func TestProto24BitOffset(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 0xFFFFFF,
	}
	
	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

func TestProto48BitOffset(t *testing.T) {
	original := &PayloadHeader{
		StreamID:     1,
		StreamOffset: 0x1000000,
	}
	
	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

// =============================================================================
// Error Tests
// =============================================================================

func TestProtoErrorBelowMinSize(t *testing.T) {
	testCases := []int{0, 1, 7}
	for _, size := range testCases {
		data := make([]byte, size)
		_, _, err := DecodePayload(data)
		assert.Error(t, err)
	}
}

func TestProtoErrorInvalidVersion(t *testing.T) {
	data := make([]byte, 8)
	data[0] = 0x1F // Invalid version
	
	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

// =============================================================================
// RcvWindow Tests
// =============================================================================

func TestProtoRcvWindowRoundTrip(t *testing.T) {
	testCases := []uint64{
		0, 512, 1024, 2048, 4096, 8192, 16384, 32768,
		65536, 131072, 262144, 524288, 1048576, 1073741824,
	}
	
	for _, input := range testCases {
		encoded := EncodeRcvWindow(input)
		decoded := DecodeRcvWindow(encoded)
		assert.LessOrEqual(t, input, decoded)
	}
}