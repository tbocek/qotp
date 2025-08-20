package qotp

import (
	"log/slog"
	"sync"
)

type RcvInsertStatus int

const (
	RcvInsertOk RcvInsertStatus = iota
	RcvInsertDuplicate
	RcvInsertBufferFull
)

type RcvBuffer struct {
	segments                   *SortedMap[packetKey, []byte]
	nextInOrderOffsetToWaitFor uint64 // Next expected offset
	closeAtOffset              *uint64
}

type RcvBufferAck struct {
	segments                   *SortedMap[packetKey, *Ack]
	nextInOrderOffsetToWaitFor uint64 // Next expected offset
}

type ReceiveBuffer struct {
	streams    map[uint32]*RcvBuffer
	lastStream uint32
	capacity   int // Max buffer size
	size       int // Current size
	ackList    []*Ack
	mu         *sync.Mutex
}

type packetKey [10]byte

func (p packetKey) offset() uint64 {
	return Uint64(p[:8])
}

func (p packetKey) length() uint16 {
	return Uint16(p[8:])
}

func (p packetKey) less(other packetKey) bool {
	for i := range len(p) {
		if p[i] < other[i] {
			return true
		}
		if p[i] > other[i] {
			return false
		}
	}
	return false
}

func createPacketKey(offset uint64, length uint16) packetKey {
	p := packetKey{}
	PutUint64(p[:8], offset)
	PutUint16(p[8:], length)
	return p
}


func NewRcvBuffer() *RcvBuffer {
	return &RcvBuffer{
		segments: NewSortedMap[packetKey, []byte](func(a, b packetKey) bool {
			if a.less(b) {
				return true
			}
			return false
		}),
		nextInOrderOffsetToWaitFor: 0,
		closeAtOffset: nil,
	}
}

func NewReceiveBuffer(capacity int) *ReceiveBuffer {
	return &ReceiveBuffer{
		streams:  make(map[uint32]*RcvBuffer),
		capacity: capacity,
		ackList:  []*Ack{},
		mu:       &sync.Mutex{},
	}
}

func (rb *ReceiveBuffer) Insert(streamId uint32, offset uint64, decodedData []byte) RcvInsertStatus {
	dataLen := len(decodedData)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Get or create stream buffer
	stream := rb.streams[streamId]
	if stream == nil {
		stream = NewRcvBuffer()
		rb.streams[streamId] = stream
	}

	if rb.size+dataLen > rb.capacity {
		return RcvInsertBufferFull
	}

	key := createPacketKey(offset, uint16(dataLen))

	//now we need to add the ack to the list even if it's a duplicate,
	//as the ack may have been lost, we need to send it again
	rb.ackList = append(rb.ackList, &Ack{streamId: streamId, offset: offset, len: uint16(dataLen)})
	
	if offset+uint64(dataLen) <= stream.nextInOrderOffsetToWaitFor {
		slog.Debug("Rcv/Duplicate/WithUser", slog.Uint64("offset", offset), slog.Int("len(data)", dataLen))
		return RcvInsertDuplicate
	}

	if stream.segments.Contains(key) {
		slog.Debug("Rcv/Duplicate/InMap", slog.Uint64("offset", offset), slog.Int("len(data)", dataLen))
		return RcvInsertDuplicate
	}

	stream.segments.Put(key, decodedData)
	rb.size += dataLen

	return RcvInsertOk
}

func (rb *ReceiveBuffer) CloseAt(streamId uint32, offset uint64)  {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Get or create stream buffer
	stream := rb.streams[streamId]
	if stream == nil {
		stream = NewRcvBuffer()
		rb.streams[streamId] = stream
	}
	stream.closeAtOffset = &offset
}

func (rb *ReceiveBuffer) GetOffsetClosedAt(streamId uint32) (offset *uint64)  {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.streams[streamId]
	if stream == nil {
		return nil
	}
	
	return stream.closeAtOffset
}

func (rb *ReceiveBuffer) RemoveOldestInOrder(streamId uint32) (offset uint64, data []byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if len(rb.streams) == 0 {
		return 0, nil
	}

	stream := rb.streams[streamId]
	if stream == nil {
		return 0, nil
	}

	// Check if there is any dataToSend at all
	oldestKey, oldestValue, ok := stream.segments.Min()
	if !ok {
		return 0, nil
	}

	if oldestKey.offset() == stream.nextInOrderOffsetToWaitFor {
		stream.segments.Remove(oldestKey)
		rb.size -= int(oldestKey.length())

		off := oldestKey.offset()
		if off < stream.nextInOrderOffsetToWaitFor {
			diff := stream.nextInOrderOffsetToWaitFor - oldestKey.offset()
			oldestValue = oldestValue[diff:]
			off = stream.nextInOrderOffsetToWaitFor
		}

		stream.nextInOrderOffsetToWaitFor = off + uint64(len(oldestValue))
		return oldestKey.offset(), oldestValue
	} else if oldestKey.offset() > stream.nextInOrderOffsetToWaitFor {
		// Out of order; wait until segment offset available, signal that
		return 0, nil
	} else {
		//Dupe, overlap, do nothing. Here we could think about adding the non-overlapping part. But if
		//it's correctly implemented, this should not happen.
		return 0, nil
	}
}

func (rb *ReceiveBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
}

func (rb *ReceiveBuffer) Available() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.capacity - rb.size
}

func (rb *ReceiveBuffer) GetSndAck() *Ack {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if len(rb.ackList) == 0 {
		return nil
	}

	ack := rb.ackList[0]
	rb.ackList = rb.ackList[1:]
	return ack
}
