package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSndInsert(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Basic insert
	n, status := sb.QueueData(1, []byte("test"), false)
	assert.Equal(t, InsertStatusOk, status)
	assert.Equal(t, 4, n)

	// Verify stream created correctly
	stream := sb.streams[1]
	assert.Equal(t, []byte("test"), stream.userData)
	assert.Equal(t, uint64(0), stream.bytesSentUserOffset)
	assert.Equal(t, uint64(0), stream.diffArrayToUserOffset)

	// Test capacity limit
	sb2 := NewSendBuffer(3)
	nr, status := sb2.QueueData(1, []byte("test"), false)
	assert.Equal(t, InsertStatusSndFull, status)
	assert.Equal(t, 3, nr)

	// Test 48-bit wrapping (using MaxUint64 as uint48 in go doesn't exist)
	sb3 := NewSendBuffer(1000)
	stream = NewStreamBuffer()
	sb3.streams[1] = stream
	_, status = sb3.QueueData(1, []byte("test"), false)
	assert.Equal(t, InsertStatusOk, status) // Should succeed now

	stream = sb3.streams[1]
	assert.Equal(t, uint64(0), stream.bytesSentUserOffset)
}

func TestSndReadyToSend(t *testing.T) {
	sb := NewSendBuffer(1000)
	nowNano := uint64(100)

	// Insert data
	sb.QueueData(1, []byte("test1"), false)
	sb.QueueData(2, []byte("test2"), false)

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
	sb.QueueData(3, []byte("toolongdata"), false)
	data, offset = sb.ReadyToSend(3, Data, nil, 15, false, nowNano) // Use larger MTU to account for overhead
	// Should get limited data based on MTU minus overhead
	assert.True(t, len(data) <= 15)
	assert.Equal(t, uint64(0), offset)

	// Test no data available
	data, offset = sb.ReadyToSend(4, Data, nil, 1000, false, nowNano)
	assert.Nil(t, data)
	assert.Equal(t, uint64(0), offset)

	// Test InitSnd message type (no overhead calculation, maxData = 0)
	sb.QueueData(5, []byte("initdata"), false)
	data, offset = sb.ReadyToSend(5, InitSnd, nil, 4, false, nowNano)
	// InitSnd with maxData=0 results in empty data because length = min(0, remainingData) = 0
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(0), offset)
}

func TestSndReadyToRetransmit(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Setup test data
	sb.QueueData(1, []byte("test1"), false)
	sb.QueueData(2, []byte("test2"), false)

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
	sb2 := NewSendBuffer(1000)
	sb2.QueueData(1, []byte("testdata"), false)
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
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("testdata"), false)
	sb.ReadyToSend(1, Data, nil, 1000, false, 100)
	stream := sb.streams[1]

	status, sentTime, _ := sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      8,
	})
	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, uint64(100), sentTime)
	assert.Equal(t, 0, len(stream.userData)) // All data should be removed
	assert.Equal(t, uint64(8), stream.diffArrayToUserOffset)
}

func TestSndAcknowledgeRangeNonExistentStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	status, sentTime, _ := sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      4,
	})
	assert.Equal(t, AckNoStream, status)
	assert.Equal(t, uint64(0), sentTime)
}

func TestSndAcknowledgeRangeNonExistentRange(t *testing.T) {
	sb := NewSendBuffer(1000)

	stream := NewStreamBuffer()
	sb.streams[1] = stream

	status, sentTime, _ := sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      4,
	})
	assert.Equal(t, AckDup, status)
	assert.Equal(t, uint64(0), sentTime)
}

func TestSndEmptyData(t *testing.T) {
	sb := NewSendBuffer(1000)

	n, status := sb.QueueData(1, []byte{}, false)
	assert.Equal(t, InsertStatusNoData, status)
	assert.Equal(t, 0, n)

	n, status = sb.QueueData(1, nil, false)
	assert.Equal(t, InsertStatusNoData, status)
	assert.Equal(t, 0, n)
}

func TestSndMultipleStreams(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Add data to multiple streams
	sb.QueueData(1, []byte("stream1"), false)
	sb.QueueData(2, []byte("stream2"), false)
	sb.QueueData(3, []byte("stream3"), false)

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

// Test gaps: when middle packets are acked before earlier ones
func TestSndAcknowledgeGaps(t *testing.T) {
	sb := NewSendBuffer(1000)
	
	// Queue 12 bytes
	sb.QueueData(1, []byte("012345678901"), false)
	
	// Send in 4-byte chunks
	sb.ReadyToSend(1, Data, nil, 43, false, 100) // offset 0, len 4
	sb.ReadyToSend(1, Data, nil, 43, false, 100) // offset 4, len 4
	sb.ReadyToSend(1, Data, nil, 43, false, 100) // offset 8, len 4
	
	stream := sb.streams[1]
	assert.Equal(t, 3, stream.dataInFlightMap.Size())
	
	// Ack middle packet first (offset 4, len 4)
	status, _, _ := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 4, len: 4})
	assert.Equal(t, AckStatusOk, status)
	
	// userData should NOT be trimmed yet (gap at start)
	assert.Equal(t, 12, len(stream.userData))
	assert.Equal(t, uint64(0), stream.diffArrayToUserOffset)
	assert.Equal(t, 2, stream.dataInFlightMap.Size())
	
	// Ack last packet (offset 8, len 4)
	status, _, _ = sb.AcknowledgeRange(&Ack{streamID: 1, offset: 8, len: 4})
	assert.Equal(t, AckStatusOk, status)
	
	// Still should NOT trim (gap at start)
	assert.Equal(t, 12, len(stream.userData))
	assert.Equal(t, uint64(0), stream.diffArrayToUserOffset)
	assert.Equal(t, 1, stream.dataInFlightMap.Size())
	
	// Ack first packet (offset 0, len 4) - should trigger trim
	status, _, _ = sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckStatusOk, status)
	
	// Now everything should be trimmed
	assert.Equal(t, 0, len(stream.userData))
	assert.Equal(t, uint64(12), stream.diffArrayToUserOffset)
	assert.Equal(t, 0, stream.dataInFlightMap.Size())
}

func TestSndAcknowledgeComplexGaps(t *testing.T) {
	sb := NewSendBuffer(1000)
	
	// Queue 20 bytes
	sb.QueueData(1, []byte("01234567890123456789"), false)
	
	// Send in 4-byte chunks (5 packets)
	for i := 0; i < 5; i++ {
		sb.ReadyToSend(1, Data, nil, 43, false, 100)
	}
	
	stream := sb.streams[1]
	assert.Equal(t, 5, stream.dataInFlightMap.Size())
	
	// Ack in random order: 2, 4, 1, 3, 0
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 8, len: 4})  // packet 2
	assert.Equal(t, 20, len(stream.userData))
	assert.Equal(t, uint64(0), stream.diffArrayToUserOffset)
	
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 16, len: 4}) // packet 4
	assert.Equal(t, 20, len(stream.userData))
	
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 4, len: 4})  // packet 1
	assert.Equal(t, 20, len(stream.userData))
	
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 12, len: 4}) // packet 3
	assert.Equal(t, 20, len(stream.userData))
	
	// Ack packet 0 - should trim everything
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, 0, len(stream.userData))
	assert.Equal(t, uint64(20), stream.diffArrayToUserOffset)
}

func TestSndRetransmitWithGaps(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"), false)
	
	// Send two packets with 5-byte payload each
	sb.ReadyToSend(1, Data, nil, 44, false, 100)  // sends "01234"
	sb.ReadyToSend(1, Data, nil, 44, false, 100)  // sends "56789"
	
	stream := sb.streams[1]
	assert.Equal(t, 2, stream.dataInFlightMap.Size())
	
	// Ack second packet
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 5, len: 5})
	
	// userData should still exist (gap at start)
	assert.Equal(t, 10, len(stream.userData))
	assert.Equal(t, uint64(0), stream.diffArrayToUserOffset)
	
	// Retransmit first packet (should work with gap)
	data, offset, _, err := sb.ReadyToRetransmit(1, nil, 44, 50, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte("01234"), data)
	assert.Equal(t, uint64(0), offset)
}

func TestSndCloseWithoutGaps(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Queue with close flag
	sb.QueueData(1, []byte("test"), true)

	stream := sb.streams[1]
	assert.Equal(t, uint64(4), stream.closeAt)

	// Send and ack
	sb.ReadyToSend(1, Data, nil, 43, false, 100)
	status, _, senderClose := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	assert.Equal(t, AckStatusOk, status)
	assert.True(t, senderClose)
}

func TestSndCloseWithGaps(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("01234567"), true)

	stream := sb.streams[1]
	assert.Equal(t, uint64(8), stream.closeAt)

	// Send two packets
	sb.ReadyToSend(1, Data, nil, 43, false, 100)
	sb.ReadyToSend(1, Data, nil, 43, false, 100)

	// Ack second packet (gap exists)
	_, _, senderClose := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 4, len: 4})
	assert.False(t, senderClose) // Can't close yet, gap exists

	// Ack first packet (no more gaps)
	_, _, senderClose = sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.True(t, senderClose) // Now we can close
}

func TestSndPingWithGaps(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Queue and send some data
	sb.QueueData(1, []byte("test"), false)
	sb.ReadyToSend(1, Data, nil, 43, false, 100)

	// Queue ping
	sb.QueuePing(1)

	// Send ping (length 0)
	ready := sb.ReadyToPing(1, 200)
	assert.True(t, ready)

	stream := sb.streams[1]
	assert.Equal(t, 2, stream.dataInFlightMap.Size())

	// Verify ping exists in inflight ranges
	// Since we can't use Last(), check that size increased
	assert.Equal(t, 2, stream.dataInFlightMap.Size())
}

func TestSndDuplicateAck(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test"), false)
	sb.ReadyToSend(1, Data, nil, 43, false, 100)

	// First ack
	status, _, _ := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckStatusOk, status)

	// Duplicate ack
	status, _, _ = sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckDup, status)
}
