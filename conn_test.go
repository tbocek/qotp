package qotp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// mockAddr implements net.Addr for testing
type mockAddr struct{}

func (m mockAddr) Network() string { return "mock" }
func (m mockAddr) String() string  { return "mock-address" }

func TestConnection_GetOrNewStreamRcv(t *testing.T) {
	tests := []struct {
		name     string
		streamID uint32
		setup    bool
	}{
		{
			name:     "new stream",
			streamID: 1,
			setup:    true,
		},
		{
			name:     "existing stream",
			streamID: 1,
			setup:    false,
		},
	}
	conn := &Conn{
		streams: NewLinkedMap[uint32, *Stream](),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := conn.Stream(tt.streamID)
			assert.NotNil(t, stream)
			assert.Equal(t, tt.streamID, stream.streamID)
		})
	}
}
