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
	sentTimeNano uint64
	sentNr       int
	pingRequest  bool
}

func (s *SendInfo) debug() slog.Attr {
	if s == nil {
		return slog.String("meta", "n/a")
	}
	return slog.Group("meta",
		slog.Uint64("sentTimeNano:ms", s.sentTimeNano/msNano),
		slog.Int("sentNr", s.sentNr))
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
	closeAtOffset   *uint64
}

type SendBuffer struct {
	streams  map[uint32]*StreamBuffer // Changed to LinkedHashMap
	capacity int                      // len(dataToSend) of all streams cannot become larger than capacity
	size     int                      // len(dataToSend) of all streams
	mu       *sync.Mutex
}

func NewStreamBuffer() *StreamBuffer {
	return &StreamBuffer{
		userData:        []byte{},
		dataInFlightMap: NewLinkedMap[packetKey, *SendInfo](),
	}
}

func NewSendBuffer(capacity int) *SendBuffer {
	return &SendBuffer{
		streams:  make(map[uint32]*StreamBuffer),
		capacity: capacity,
		mu:       &sync.Mutex{},
	}
}

// QueueData stores the userData in the dataMap, does not send yet
func (sb *SendBuffer) QueueData(streamId uint32, userData []byte) (n int, status InsertStatus) {
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

// ReadyToSend gets data from dataToSend and creates an entry in dataInFlightMap
func (sb *SendBuffer) ReadyToSend(streamID uint32, msgType CryptoMsgType, ack *Ack, mtu int, nowNano uint64) (
	packetData []byte, offset uint64, messageType StreamMsgType,
) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return nil, 0, MsgTypeInvalid
	}

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, MsgTypeInvalid
	}

	if stream.pingRequest {
		stream.pingRequest = false
		// Pack offset and length into key, offset does not matter as data is 0
		key := createPacketKey(stream.bytesSentUserOffset, 0)

		// Track range, important when acked, so we can update stats, but no retransmission of this.
		m := &SendInfo{sentNr: 1, sentTimeNano: nowNano, pingRequest: true}
		stream.dataInFlightMap.Put(key, m)

		return []byte{}, 0, MsgTypePing // not nil, but empty data actually
	}

	// We have send all queued data for the first time
	currentUserOffset := uint64(len(stream.userData)) + stream.diffArrayToUserOffset
	if currentUserOffset == stream.bytesSentUserOffset {
		if stream.closeAtOffset == nil || stream.bytesSentUserOffset < *stream.closeAtOffset {
			return nil, 0, MsgTypeInvalid
		}
		key := createPacketKey(stream.bytesSentUserOffset, 0)
		m := &SendInfo{sentNr: 1, sentTimeNano: nowNano, pingRequest: false}
		stream.dataInFlightMap.Put(key, m)
		return []byte{}, key.offset(), MsgTypeClose // not nil, but empty data actually
	}

	maxData := 0
	if msgType != InitSnd {
		overhead := calcCryptoOverhead(msgType, ack, stream.bytesSentUserOffset)
		maxData = mtu - overhead
	}

	// the max length we can send
	dataToSend := currentUserOffset - stream.bytesSentUserOffset
	length := min(uint64(maxData), dataToSend)

	// Get userData slice accounting for bias
	realOffset := stream.bytesSentUserOffset - stream.diffArrayToUserOffset
	packetData = stream.userData[realOffset : realOffset+length]

	// Pack offset and length into key
	key := createPacketKey(stream.bytesSentUserOffset, uint16(length))
	// Track range

	m := &SendInfo{sentNr: 1, sentTimeNano: nowNano, pingRequest: false}
	stream.dataInFlightMap.Put(key, m)

	// Update sent bytes
	stream.bytesSentUserOffset = stream.bytesSentUserOffset + length

	if stream.closeAtOffset != nil && stream.bytesSentUserOffset >= *stream.closeAtOffset {
		messageType = MsgTypeClose
	}
	return packetData, key.offset(), messageType
}

// ReadyToRetransmit finds expired dataInFlightMap that need to be resent
func (sb *SendBuffer) ReadyToRetransmit(streamID uint32, ack *Ack, mtu int, expectedRtoNano uint64, msgType CryptoMsgType, nowNano uint64) (
	data []byte, offset uint64, messageType StreamMsgType, err error,
) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return nil, 0, MsgTypeInvalid, nil
	}

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, MsgTypeInvalid, nil
	}

	// Check oldest range first
	packetKey, rtoData, ok := stream.dataInFlightMap.First()
	if !ok {
		return nil, 0, MsgTypeInvalid, nil // or continue to next logic
	}

	expectedRtoBackoffNano, err := backoff(expectedRtoNano, rtoData.sentNr)
	if err != nil {
		return nil, 0, MsgTypeInvalid, err
	}

	actualRtoNano := nowNano - rtoData.sentTimeNano
	if actualRtoNano <= expectedRtoBackoffNano {
		return nil, 0, MsgTypeInvalid, nil // or continue to next logic
	}

	// Timeout
	if rtoData.pingRequest {
		// just remove as we do not retransmit
		sb.trimAckedData(stream, packetKey)
		return nil, 0, MsgTypeInvalid, nil
	}

	// Calculate data slice once
	realOffset := packetKey.offset() - stream.diffArrayToUserOffset
	length := packetKey.length()

	data = stream.userData[realOffset : realOffset+uint64(length)]

	// Calculate available space once
	maxData := 0
	if msgType != InitSnd {
		overhead := calcCryptoOverhead(msgType, ack, packetKey.offset())
		maxData = mtu - overhead
	}

	baseSendInfo := &SendInfo{
		sentTimeNano: nowNano,
		sentNr:       rtoData.sentNr + 1,
	}

	if length <= uint16(maxData) {
		// Resend entire range
		slog.Debug("Resend", slog.Uint64("free-space", uint64(uint16(maxData)-length)))
		stream.dataInFlightMap.Replace(packetKey, packetKey, baseSendInfo)
		packetEnd := packetKey.offset() + uint64(length)
		if stream.closeAtOffset != nil && packetEnd >= *stream.closeAtOffset {
			messageType = MsgTypeClose
		}
		return data, packetKey.offset(), messageType, nil
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
		return data[:maxData], packetKey.offset(), MsgTypeData, nil
	}
}

// AcknowledgeRange handles acknowledgment of dataToSend
func (sb *SendBuffer) AcknowledgeRange(ack *Ack) (status AckStatus, sentTimeNano uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[ack.streamID]
	if stream == nil {
		return AckNoStream, 0
	}

	// Remove range key
	key := createPacketKey(ack.offset, ack.len)

	ok, sentTimeNano := sb.trimAckedData(stream, key)
	if !ok {
		return AckDup, 0
	}

	return AckStatusOk, sentTimeNano
}

func (sb *SendBuffer) GetOffsetAcked(streamID uint32) (offset uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return 0
	}

	// If there's inflight data, the acked offset is where inflight begins
	firstKey, _, ok := stream.dataInFlightMap.First()
	if ok {
		ackedOffset := firstKey.offset()
		return ackedOffset
	}

	// No inflight data means everything sent has been acked
	return stream.bytesSentUserOffset
}

func (sb *SendBuffer) GetOffsetClosedAt(streamID uint32) (offset *uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return nil
	}

	return stream.closeAtOffset
}

func (sb *SendBuffer) Close(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Get or create stream buffer
	stream := sb.streams[streamID]
	if stream == nil {
		stream = NewStreamBuffer()
		sb.streams[streamID] = stream
	}
	if stream.closeAtOffset == nil {
		offset := uint64(len(stream.userData)) + stream.diffArrayToUserOffset
		stream.closeAtOffset = &offset
	}
}

// remove packets from dataInFlightMap whose data has been trimmed
// packets are ordered by offset, stale packets will be at the beginning
func (sb *SendBuffer) removeStalePackets(stream *StreamBuffer) {
	for {
		key, _, ok := stream.dataInFlightMap.First()
		if !ok {
			break // No more packets
		}
		if key.offset() >= stream.diffArrayToUserOffset {
			break // Found first valid packet, done
		}
		stream.dataInFlightMap.Remove(key)
	}
}

func (sb *SendBuffer) trimAckedData(stream *StreamBuffer, p packetKey) (success bool, sentTimeNano uint64) {
	_, _, okPrev := stream.dataInFlightMap.Previous(p)
	pNext, _, okNext := stream.dataInFlightMap.Next(p)

	rangePair, okThis := stream.dataInFlightMap.Remove(p)
	if !okThis {
		return false, 0
	}

	if !okPrev {
		// we have no prev, so drop everything, including this packet
		realOffset := p.offset() - stream.diffArrayToUserOffset
		bytesToTrim := realOffset + uint64(p.length())

		stream.userData = stream.userData[bytesToTrim:]
		stream.diffArrayToUserOffset += bytesToTrim
		if okNext {
			// we have no prev, but next, so drop everything until next
			realOffset := pNext.offset() - stream.diffArrayToUserOffset
			stream.userData = stream.userData[realOffset:]
			stream.diffArrayToUserOffset += realOffset
			sb.removeStalePackets(stream)
		} else {
			// no prev, no next, delete everything
			bytesToTrim = stream.bytesSentUserOffset - stream.diffArrayToUserOffset
			stream.userData = stream.userData[bytesToTrim:]
			stream.diffArrayToUserOffset += bytesToTrim
			sb.removeStalePackets(stream)
		}
	}

	return true, rangePair.sentTimeNano
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
