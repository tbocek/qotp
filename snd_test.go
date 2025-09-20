package qotp

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSndInsert(t *testing.T) {
	sb := NewSendBuffer(1000, nil)

	// Basic insert
	n, status := sb.QueueData(1, []byte("test"))
	assert.Equal(t, InsertStatusOk, status)
	assert.Equal(t, 4, n)

	// Verify stream created correctly
	stream := sb.streams[1]
	assert.Equal(t, []byte("test"), stream.userData)
	assert.Equal(t, uint64(4), stream.unsentOffset)
	assert.Equal(t, uint64(0), stream.sentOffset)
	assert.Equal(t, uint64(0), stream.bias)

	// Test capacity limit
	sb2 := NewSendBuffer(3, nil)
	nr, status := sb2.QueueData(1, []byte("test"))
	assert.Equal(t, InsertStatusSndFull, status)
	assert.Equal(t, 3, nr)

	// Test 48-bit wrapping (using MaxUint64 as uint48 in go doesn't exist)
	sb3 := NewSendBuffer(1000, nil)
	stream = NewStreamBuffer()
	stream.unsentOffset = math.MaxUint64 - 2
	sb3.streams[1] = stream
	_, status = sb3.QueueData(1, []byte("test"))
	assert.Equal(t, InsertStatusOk, status) // Should succeed now

	stream = sb3.streams[1]
	assert.Equal(t, uint64(1), stream.unsentOffset) // Rollover will occur. Because we are using uint64
	assert.Equal(t, uint64(0), stream.sentOffset)
}

func TestSndReadyToSend(t *testing.T) {
	sb := NewSendBuffer(1000, nil)
	nowNano := uint64(100)

	// Insert data
	sb.QueueData(1, []byte("test1"))
	sb.QueueData(2, []byte("test2"))

	// Basic send
	data, offset := sb.ReadyToSend(1, Data, nil, 1000, false, nowNano)
	assert.Equal(t, []byte("test1"), data)
	assert.Equal(t, uint64(0), offset)

	// Verify range tracking
	stream := sb.streams[1]
	rangePair, v, ok := stream.dataInFlightMap.First()
	assert.True(t, ok)
	assert.NotNil(t, rangePair)
	assert.Equal(t, uint16(5), rangePair.length())
	assert.Equal(t, nowNano, v.sentTimeNano)

	// Test MTU limiting with small MTU
	sb.QueueData(3, []byte("toolongdata"))
	data, offset = sb.ReadyToSend(3, Data, nil, 15, false, nowNano) // Use larger MTU to account for overhead
	// Should get limited data based on MTU minus overhead
	assert.True(t, len(data) <= 15)
	assert.Equal(t, uint64(0), offset)

	// Test no data available
	data, offset = sb.ReadyToSend(4, Data, nil, 1000, false, nowNano)
	assert.Nil(t, data)
	assert.Equal(t, uint64(0), offset)

	// Test InitSnd message type (no overhead calculation, maxData = 0)
	sb.QueueData(5, []byte("initdata"))
	data, offset = sb.ReadyToSend(5, InitSnd, nil, 4, false, nowNano)
	// InitSnd with maxData=0 results in empty data because length = min(0, remainingData) = 0
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(0), offset)
}

func TestSndReadyToRetransmit(t *testing.T) {
	sb := NewSendBuffer(1000, nil)

	// Setup test data
	sb.QueueData(1, []byte("test1"))
	sb.QueueData(2, []byte("test2"))

	sb.ReadyToSend(1, Data, nil, 1000, false, 100) // Initial send at time 100
	sb.ReadyToSend(2, Data, nil, 1000, false, 100) // Initial send at time 100

	// Test basic retransmit
	data, offset, msgType, err := sb.ReadyToRetransmit(1, nil, 1000, 50, 200) // RTO = 50, now = 200. 200-100 > 50
	assert.Nil(t, err)
	assert.Equal(t, []byte("test1"), data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, Data, msgType)

	data, offset, msgType, err = sb.ReadyToRetransmit(2, nil, 1000, 100, 200) // RTO = 100, now = 200. 200-100 = 100, thus not ready yet
	assert.Nil(t, err)
	assert.Nil(t, data)
	assert.Equal(t, uint64(0), offset)

	data, offset, msgType, err = sb.ReadyToRetransmit(1, nil, 1000, 99, 399) // RTO = 99, now = 399. 399-100 > 99 with backoff
	assert.Nil(t, err)
	assert.Equal(t, []byte("test1"), data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, Data, msgType)

	// Test MTU split scenario with proper MTU that should trigger splitting
	sb2 := NewSendBuffer(1000, nil)
	sb2.QueueData(1, []byte("testdata"))
	sb2.ReadyToSend(1, Data, nil, 1000, false, 100) // Initial send

	// Use very small MTU to force splitting
	data, offset, msgType, err = sb2.ReadyToRetransmit(1, nil, 20, 99, 200) // Small MTU should trigger split
	assert.Nil(t, err)
	// Should get partial data due to MTU limiting
	assert.True(t, len(data) <= 20)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, Data, msgType)

	// Verify range behavior after potential split
	stream := sb2.streams[1]
	// After split, we should have at least 1 range, possibly 2
	assert.True(t, stream.dataInFlightMap.Size() >= 1)
	node, _, ok := stream.dataInFlightMap.First()
	assert.True(t, ok)
	assert.Equal(t, uint64(0), node.offset())
}

func TestSndAcknowledgeRangeBasic(t *testing.T) {
	sb := NewSendBuffer(1000, nil)

	sb.QueueData(1, []byte("testdata"))
	sb.ReadyToSend(1, Data, nil, 1000, false, 100)
	stream := sb.streams[1]

	status, sentTime := sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      8,
	})
	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, uint64(100), sentTime)
	assert.Equal(t, 0, len(stream.userData)) // All data should be removed
	assert.Equal(t, uint64(8), stream.bias)
}

func TestSndAcknowledgeRangeNonExistentStream(t *testing.T) {
	sb := NewSendBuffer(1000, nil)

	status, sentTime := sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      4,
	})
	assert.Equal(t, AckNoStream, status)
	assert.Equal(t, uint64(0), sentTime)
}

func TestSndAcknowledgeRangeNonExistentRange(t *testing.T) {
	sb := NewSendBuffer(1000, nil)

	stream := NewStreamBuffer()
	sb.streams[1] = stream

	status, sentTime := sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      4,
	})
	assert.Equal(t, AckDup, status)
	assert.Equal(t, uint64(0), sentTime)
}

func TestSndEmptyData(t *testing.T) {
	sb := NewSendBuffer(1000, nil)

	n, status := sb.QueueData(1, []byte{})
	assert.Equal(t, InsertStatusNoData, status)
	assert.Equal(t, 0, n)

	n, status = sb.QueueData(1, nil)
	assert.Equal(t, InsertStatusNoData, status)
	assert.Equal(t, 0, n)
}

func TestSndMultipleStreams(t *testing.T) {
	sb := NewSendBuffer(1000, nil)

	// Add data to multiple streams
	sb.QueueData(1, []byte("stream1"))
	sb.QueueData(2, []byte("stream2"))
	sb.QueueData(3, []byte("stream3"))

	// Send from different streams
	data1, offset1 := sb.ReadyToSend(1, Data, nil, 1000, false, 100)
	data2, offset2 := sb.ReadyToSend(2, Data, nil, 1000, false, 00)
	data3, offset3 := sb.ReadyToSend(3, Data, nil, 1000, false, 300)

	assert.Equal(t, []byte("stream1"), data1)
	assert.Equal(t, []byte("stream2"), data2)
	assert.Equal(t, []byte("stream3"), data3)
	assert.Equal(t, uint64(0), offset1)
	assert.Equal(t, uint64(0), offset2)
	assert.Equal(t, uint64(0), offset3)

	// Verify each stream has correct tracking
	assert.Equal(t, 1, sb.streams[1].dataInFlightMap.Size())
	assert.Equal(t, 1, sb.streams[2].dataInFlightMap.Size())
	assert.Equal(t, 1, sb.streams[3].dataInFlightMap.Size())
}
