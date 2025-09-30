package qotp

import (
	"log/slog"
	"sync"
)

type InsertStatus int

const (
	InsertStatusOk InsertStatus = iota
	InsertStatusSndFull
	InsertStatusNoData
)

type AckStatus int

const (
	AckStatusOk AckStatus = iota
	AckNoStream
	AckDup
)

type SendInfo struct {
	sentTimeNano           uint64
	sentNr                 int
	msgType                MsgType //we may know this only after running encryption
	expectedRtoBackoffNano uint64
	actualRtoNano          uint64
	noRetry                bool
}

func (s *SendInfo) debug() slog.Attr {
	if s == nil {
		return slog.String("meta", "n/a")
	}
	return slog.Group("meta",
		slog.Uint64("expRto:ms", s.expectedRtoBackoffNano/msNano),
		slog.Uint64("actRto:ms", s.actualRtoNano/msNano))
}

// StreamBuffer represents a single stream's userData and metadata
type StreamBuffer struct {
	// here we append the userData, after appending, we sent currentOffset.
	// This is necessary, as when userData gets acked, we Remove the acked userData,
	// which will be in front of the array. Thus, len(userData) would not work.
	userData []byte
	// this is the offset of the dataToSend we did send, this is ever increasing
	// rolls over after 48bit
	bytesSentUserOffset uint64
	// when dataToSend is acked, we Remove the dataToSend, however we don't want to update all the offsets, 
	// hence this diffArrayToUserOffset
	// TODO: check what happens on an 48bit rollover
	diffArrayToUserOffset uint64
	// inflight dataToSend - key is offset, which is uint48, len in 16bit is added to a 64bit key. value is sentTime
	// If MTU changes for inflight packets and need to be resent. The range is split. Example:
	// offset: 500, len/mtu: 50 -> 1 range: 500/50,time
	// retransmit with mtu:20 -> 3 dataInFlightMap: 500/20,time; 520/20,time; 540/10,time
	dataInFlightMap *LinkedMap[packetKey, *SendInfo]
	pingRequest     bool
	closeAt         uint64
}

type SendBuffer struct {
	streams  map[uint32]*StreamBuffer // Changed to LinkedHashMap
	capacity int                      //len(dataToSend) of all streams cannot become larger than capacity
	size     int                      //len(dataToSend) of all streams
	mu       *sync.Mutex
}

func NewStreamBuffer() *StreamBuffer {
	return &StreamBuffer{
		userData:        []byte{},
		dataInFlightMap: NewLinkedMap[packetKey, *SendInfo](),
	}
}

func NewSendBuffer(capacity int, callback func()) *SendBuffer {
	return &SendBuffer{
		streams:  make(map[uint32]*StreamBuffer),
		capacity: capacity,
		mu:       &sync.Mutex{},
	}
}

// QueueData stores the userData in the dataMap, does not send yet
func (sb *SendBuffer) QueueData(streamId uint32, userData []byte, close bool) (n int, status InsertStatus) {
	if len(userData) <= 0 {
		return 0, InsertStatusNoData
	}

	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Calculate how much userData we can insert
	remainingCapacitySnd := sb.capacity - sb.size
	if remainingCapacitySnd == 0 {
		return 0, InsertStatusSndFull
	}

	// We fill up the chunk up to the capacity of snd
	// chunk is then what we will queue, and we report
	// how much bytes we queued
	chunk := userData
	if len(userData) > remainingCapacitySnd {
		chunk = userData[:remainingCapacitySnd]
		status = InsertStatusSndFull
	} else {
		status = InsertStatusOk
	}
	n = len(chunk)

	// Get or create stream buffer
	stream := sb.streams[streamId]
	if stream == nil {
		stream = NewStreamBuffer()
		sb.streams[streamId] = stream
	}

	// Store chunk
	stream.userData = append(stream.userData, chunk...)
	// We need to keep track of where the next fresh offset is
	// As we may remove userData, if it has bee acked.
	if close {
		stream.closeAt = uint64(len(stream.userData))
	}
	sb.size += n

	return n, status
}

func (sb *SendBuffer) QueuePing(streamId uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Get or create stream buffer
	stream := sb.streams[streamId]
	if stream == nil {
		stream = NewStreamBuffer()
		sb.streams[streamId] = stream
	}

	stream.pingRequest = true
}

func (sb *SendBuffer) ReadyToPing(streamID uint32, nowNano uint64) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return false
	}

	stream := sb.streams[streamID]
	if stream == nil {
		return false
	}

	if !stream.pingRequest {
		return false
	}
	stream.pingRequest = false

	// Pack offset and length into key, offset does not matter as data is 0
	key := createPacketKey(stream.bytesSentUserOffset, 0)

	// Track range, important when acked, so we can update stats, but no retransmission of this.
	m := &SendInfo{sentNr: 1, msgType: -1, sentTimeNano: nowNano, noRetry: true}
	stream.dataInFlightMap.Put(key, m)

	return true
}

// ReadyToSend gets data from dataToSend and creates an entry in dataInFlightMap
func (sb *SendBuffer) ReadyToSend(streamID uint32, msgType MsgType, ack *Ack, mtu int, noRetry bool, nowNano uint64) (
	packetData []byte, offset uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return nil, 0
	}

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0
	}

	//We have send all queued data for the first time
	currentUserOffset := uint64(len(stream.userData)) + stream.diffArrayToUserOffset
	if currentUserOffset == stream.bytesSentUserOffset {
		return nil, 0
	}

	maxData := 0
	if msgType != InitSnd {
		overhead := calcCryptoOverhead(msgType, ack, stream.bytesSentUserOffset)
		maxData = mtu - overhead
	}

	//the max length we can send
	dataToSend := currentUserOffset - stream.bytesSentUserOffset
	length := min(uint64(maxData), dataToSend)

	// Get userData slice accounting for bias
	realOffset := stream.bytesSentUserOffset - stream.diffArrayToUserOffset
	packetData = stream.userData[realOffset : realOffset+length]

	// Pack offset and length into key
	key := createPacketKey(stream.bytesSentUserOffset, uint16(length))
	// Track range
	m := &SendInfo{sentNr: 1, msgType: msgType, sentTimeNano: nowNano, noRetry: noRetry}
	stream.dataInFlightMap.Put(key, m)

	// Update sent bytes
	stream.bytesSentUserOffset = stream.bytesSentUserOffset + length

	return packetData, key.offset()
}

// ReadyToRetransmit finds expired dataInFlightMap that need to be resent
func (sb *SendBuffer) ReadyToRetransmit(streamID uint32, ack *Ack, mtu int, expectedRtoNano uint64, nowNano uint64) (
	data []byte, offset uint64, msgType MsgType, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return nil, 0, 0, nil
	}

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, 0, nil
	}

	// Check oldest range first
	packetKey, rtoData, ok := stream.dataInFlightMap.First()
	if !ok {
		return nil, 0, 0, nil // or continue to next logic
	}

	expectedRtoBackoffNano, err := backoff(expectedRtoNano, rtoData.sentNr)
	if err != nil {
		return nil, 0, 0, err
	}

	actualRtoNano := nowNano - rtoData.sentTimeNano
	if actualRtoNano <= expectedRtoBackoffNano {
		return nil, 0, 0, nil // or continue to next logic
	}

	//Timeout
	if rtoData.noRetry {
		//just remove as we do not retransmit
		sb.trimAckedData(stream, packetKey)
		return nil, 0, 0, nil
	}

	// Calculate data slice once
	realOffset := packetKey.offset() - stream.diffArrayToUserOffset
	length := packetKey.length()

	if length == 0 {
		return nil, 0, 0, nil
	}

	data = stream.userData[realOffset : realOffset+uint64(length)]

	// Calculate available space once
	maxData := 0
	if rtoData.msgType != InitSnd {
		overhead := calcCryptoOverhead(rtoData.msgType, ack, packetKey.offset())
		maxData = mtu - overhead
	}

	baseSendInfo := &SendInfo{
		sentTimeNano:           nowNano,
		sentNr:                 rtoData.sentNr + 1,
		msgType:                rtoData.msgType,
		expectedRtoBackoffNano: expectedRtoBackoffNano,
		actualRtoNano:          actualRtoNano,
	}

	if length <= uint16(maxData) {
		// Resend entire range
		slog.Debug("Resend", slog.Uint64("free-space", uint64(uint16(maxData)-length)))
		stream.dataInFlightMap.Replace(packetKey, packetKey, baseSendInfo)
		return data, packetKey.offset(), rtoData.msgType, nil
	} else {
		// Split range
		leftKey := createPacketKey(packetKey.offset(), uint16(maxData))
		remainingOffset := packetKey.offset() + uint64(maxData)
		stream.dataInFlightMap.Put(leftKey, baseSendInfo)

		// only change the remainingOffset here, the length changes in the key
		// rest stays the same
		rightKey := createPacketKey(remainingOffset, length-uint16(maxData))
		stream.dataInFlightMap.Replace(packetKey, rightKey, rtoData)

		slog.Debug("Resend/Split", slog.Uint64("send", uint64(maxData)),
			slog.Uint64("remain", uint64(length-uint16(maxData))))
		return data[:maxData], packetKey.offset(), rtoData.msgType, nil
	}
}

// AcknowledgeRange handles acknowledgment of dataToSend
func (sb *SendBuffer) AcknowledgeRange(ack *Ack) (status AckStatus, sentTimeNano uint64, senderClose bool) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[ack.streamID]
	if stream == nil {
		return AckNoStream, 0, false
	}

	// Remove range key
	key := createPacketKey(ack.offset, ack.len)

	ok, sentTimeNano, senderClose := sb.trimAckedData(stream, key)
	if !ok {
		return AckDup, 0, false
	}

	return AckStatusOk, sentTimeNano, senderClose
}

func (sb *SendBuffer) trimAckedData(stream *StreamBuffer, p packetKey) (success bool, sentTimeNano uint64, senderClose bool) {
	_, _, okPrev := stream.dataInFlightMap.Previous(p)
	
	rangePair, okThis := stream.dataInFlightMap.Remove(p)
	if !okThis {
		return false, 0, false
	}
	
	if !okPrev {
		// //we have no prev, so drop everything, including this packet
		realOffset := p.offset() - stream.diffArrayToUserOffset
		bytesToTrim := realOffset + uint64(p.length())
		
		stream.userData = stream.userData[bytesToTrim:]
		stream.diffArrayToUserOffset += bytesToTrim
		
		pNext, _, okNext := stream.dataInFlightMap.Next(p)
		if okNext {
			//we have no prev, but next, so drop everything until next
			realOffset := pNext.offset() - stream.diffArrayToUserOffset
			stream.userData = stream.userData[realOffset:]
			stream.diffArrayToUserOffset += realOffset
		} else {
			//no prev, no next, delete everything
			bytesToTrim = stream.bytesSentUserOffset - stream.diffArrayToUserOffset
			stream.userData = stream.userData[bytesToTrim:]
			stream.diffArrayToUserOffset += bytesToTrim
		}	
		
		//check if we can close this
		if stream.closeAt > 0 && stream.diffArrayToUserOffset >= stream.closeAt {
			senderClose = true
		}
	}
	
	return true, rangePair.sentTimeNano, senderClose
}

type packetKey uint64

func (p packetKey) offset() uint64 {
	return uint64(p) >> 16
}

func (p packetKey) length() uint16 {
	return uint16(p & 0xFFFF)
}

func createPacketKey(offset uint64, length uint16) packetKey {
	return packetKey((offset << 16) | uint64(length))
}
