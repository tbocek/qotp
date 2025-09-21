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
	offset                 uint64
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
	// this is the offset of the userData we did not send yet
	unsentOffset uint64
	// this is the offset of the dataToSend we did send
	sentOffset uint64
	// when dataToSend is acked, we Remove the dataToSend, however we don't want to update all the offsets, hence this bias
	// TODO: check what happens on an 48bit rollover
	bias uint64
	// inflight dataToSend - key is offset, which is uint48, len in 16bit is added to a 64bit key. value is sentTime
	// If MTU changes for inflight packets and need to be resent. The range is split. Example:
	// offset: 500, len/mtu: 50 -> 1 range: 500/50,time
	// retransmit with mtu:20 -> 3 dataInFlightMap: 500/20,time; 520/20,time; 540/10,time
	dataInFlightMap *LinkedMap[packetKey, *SendInfo]
	pingRequest     bool
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
func (sb *SendBuffer) QueueData(streamId uint32, userData []byte) (n int, status InsertStatus) {
	remainingData := userData

	if len(remainingData) <= 0 {
		return 0, InsertStatusNoData
	}

	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Calculate how much userData we can insert
	remainingCapacitySnd := sb.capacity - sb.size
	if remainingCapacitySnd <= 0 {
		return 0, InsertStatusSndFull
	}

	// Calculate chunk size
	chunk := remainingData
	if len(remainingData) > remainingCapacitySnd {
		chunk = remainingData[:remainingCapacitySnd]
		status = InsertStatusSndFull
		n = remainingCapacitySnd
	} else {
		status = InsertStatusOk
		n = len(remainingData)
	}

	// Get or create stream buffer
	stream := sb.streams[streamId]
	if stream == nil {
		stream = NewStreamBuffer()
		sb.streams[streamId] = stream
	}

	// Store chunk
	stream.userData = append(stream.userData, chunk...)
	stream.unsentOffset = stream.unsentOffset + uint64(n)
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

	// Pack offset and length into key
	key := createPacketKey(stream.sentOffset, 0)
	
	// Track range
	m := &SendInfo{sentNr: 1, msgType: -1, offset: stream.sentOffset, sentTimeNano: nowNano, noRetry: true}
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

	// Check if there's unsent dataToSend, if true, we have unsent dataToSend
	if stream.unsentOffset > stream.sentOffset {
		remainingData := stream.unsentOffset - stream.sentOffset

		maxData := 0
		if msgType != InitSnd {
			overhead := calcCryptoOverhead(msgType, ack, stream.sentOffset)
			maxData = mtu - overhead
		}

		//the max length we can send
		length := uint16(min(uint64(maxData), remainingData))

		// Get userData slice accounting for bias
		offset := stream.sentOffset - stream.bias
		packetData = stream.userData[offset : offset+uint64(length)]

		// Pack offset and length into key
		key := createPacketKey(stream.sentOffset, length)
		// Track range
		m := &SendInfo{sentNr: 1, msgType: msgType, offset: stream.sentOffset, sentTimeNano: nowNano, noRetry: noRetry}
		stream.dataInFlightMap.Put(key, m)

		// Update tracking
		currentOffset := stream.sentOffset
		stream.sentOffset = stream.sentOffset + uint64(length)

		if noRetry {
			//TODO: remove data now instead of in the ack or retransmit
			slog.Debug("we should remove data now, currently we do it later.")
		}

		return packetData, currentOffset
	}

	return nil, 0
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
		//just remove as we do not expect a retransmission
		stream.dataInFlightMap.Remove(packetKey)
		slog.Debug("removed a packet, which was not acked, we could have done this earlier")
		return nil, 0, 0, nil
	}

	// Calculate data slice once
	rangeOffset := packetKey.offset()
	rangeLen := packetKey.length()
	dataOffset := rangeOffset - stream.bias
	data = stream.userData[dataOffset : dataOffset+uint64(rangeLen)]

	// Calculate available space once
	maxData := 0
	if rtoData.msgType != InitSnd {
		overhead := calcCryptoOverhead(rtoData.msgType, ack, dataOffset)
		maxData = mtu - overhead
	}

	baseSendInfo := &SendInfo{
		sentTimeNano:           nowNano,
		sentNr:                 rtoData.sentNr + 1,
		msgType:                rtoData.msgType,
		offset:                 rangeOffset,
		expectedRtoBackoffNano: expectedRtoBackoffNano,
		actualRtoNano:          actualRtoNano,
	}

	if rangeLen <= uint16(maxData) {
		// Resend entire range
		slog.Debug("Resend", slog.Uint64("free-space", uint64(uint16(maxData)-rangeLen)))
		stream.dataInFlightMap.Replace(packetKey, packetKey, baseSendInfo)
		return data, rangeOffset, rtoData.msgType, nil
	} else {
		// Split range
		leftKey := createPacketKey(rangeOffset, uint16(maxData))
		remainingOffset := rangeOffset + uint64(maxData)
		rightKey := createPacketKey(remainingOffset, rangeLen-uint16(maxData))

		stream.dataInFlightMap.Put(leftKey, baseSendInfo)

		rightSendInfo := &SendInfo{
			sentTimeNano:           rtoData.sentTimeNano,
			sentNr:                 rtoData.sentNr,
			msgType:                rtoData.msgType,
			offset:                 remainingOffset,
			expectedRtoBackoffNano: rtoData.expectedRtoBackoffNano,
			actualRtoNano:          rtoData.actualRtoNano,
		}
		stream.dataInFlightMap.Replace(packetKey, rightKey, rightSendInfo)

		slog.Debug("Resend/Split", slog.Uint64("send", uint64(maxData)),
			slog.Uint64("remain", uint64(rangeLen-uint16(maxData))))
		return data[:maxData], rangeOffset, rtoData.msgType, nil
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
	rangePair, ok := stream.dataInFlightMap.Remove(key)
	if !ok {
		return AckDup, 0
	}

	sentTimeNano = rangePair.sentTimeNano

	// Try to advance the bias and remove acknowledged data
	if ack.len > 0 {
		// Find the lowest offset still in flight (excluding ping packets with len=0)
		minInFlightOffset := stream.sentOffset // Default if no real data in flight
		hasRealDataInFlight := false
		
		for inFlightKey, _ := range stream.dataInFlightMap.Iterator(nil) {
			offset := inFlightKey.offset()
			length := inFlightKey.length()
			
			// Skip ping packets (length = 0)
			if length == 0 {
				continue
			}
			
			if offset < minInFlightOffset {
				minInFlightOffset = offset
				hasRealDataInFlight = true
			}
		}
		
		// If no real data is in flight, we can remove up to sentOffset
		// Otherwise, we can only remove up to the earliest in-flight data
		targetBias := minInFlightOffset
		if !hasRealDataInFlight {
			targetBias = stream.sentOffset
		}
		
		// Only advance if we're moving forward
		if targetBias > stream.bias {
			bytesToRemove := targetBias - stream.bias
			
			// Safety check
			if int(bytesToRemove) > len(stream.userData) {
				slog.Error("Attempted to remove more data than available",
					slog.Uint64("bytesToRemove", bytesToRemove),
					slog.Int("dataLen", len(stream.userData)),
					slog.Uint64("bias", stream.bias),
					slog.Uint64("targetBias", targetBias))
				// Remove what we can
				bytesToRemove = uint64(len(stream.userData))
			}
			
			stream.userData = stream.userData[bytesToRemove:]
			sb.size -= int(bytesToRemove)
			stream.bias = targetBias
			
			if rangePair.noRetry {
				slog.Debug("removed a packet which was acked, we could have done this earlier")
			}
		}
	}

	return AckStatusOk, sentTimeNano
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
