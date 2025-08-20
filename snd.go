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
}

type SendBuffer struct {
	streams                    map[uint32]*StreamBuffer // Changed to LinkedHashMap
	lastReadToSendStream       uint32                   //for round-robin, we continue where we left
	lastReadToRetransmitStream uint32
	capacity                   int //len(dataToSend) of all streams cannot become larger than capacity
	size                       int //len(dataToSend) of all streams
	mu                         *sync.Mutex
}

func NewStreamBuffer() *StreamBuffer {
	return &StreamBuffer{
		userData:      []byte{},
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
func (sb *SendBuffer) QueueData(streamID uint32, userData []byte) (inserted int, status InsertStatus) {
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
	inserted = min(len(remainingData), remainingCapacitySnd)
	chunk := remainingData[:inserted]

	// Get or create stream buffer
	stream := sb.streams[streamID]
	if stream == nil {
		stream = NewStreamBuffer()
		sb.streams[streamID] = stream
	}

	// Store chunk
	stream.userData = append(stream.userData, chunk...)
	stream.unsentOffset = stream.unsentOffset + uint64(inserted)
	sb.size += inserted

	// Update remaining dataToSend
	remainingData = remainingData[inserted:]
	return inserted, InsertStatusOk
}

// ReadyToSend gets data from dataToSend and creates an entry in dataInFlightMap
func (sb *SendBuffer) ReadyToSend(streamID uint32, overhead *Overhead, nowNano uint64) (packetData []byte, m *SendInfo) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return nil, nil
	}

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, nil
	}

	// Check if there's unsent dataToSend, if true, we have unsent dataToSend
	if stream.unsentOffset > stream.sentOffset {
		remainingData := stream.unsentOffset - stream.sentOffset

		overhead.dataOffset = stream.sentOffset
		maxData := overhead.CalcMaxData()

		//the max length we can send
		length := uint16(min(uint64(maxData), remainingData))

		// Pack offset and length into key
		key := createPacketKey(stream.sentOffset, length)

		// Get userData slice accounting for bias
		offset := stream.sentOffset - stream.bias
		packetData = stream.userData[offset : offset+uint64(length)]

		// Track range
		m = &SendInfo{sentNr: 1, msgType: -1, offset: stream.sentOffset, sentTimeNano: nowNano} //we do not know the msg type yet
		stream.dataInFlightMap.Put(key, m)

		// Update tracking
		stream.sentOffset = stream.sentOffset + uint64(length)
		sb.lastReadToSendStream = streamID

		return packetData, m
	}

	return nil, nil
}

// ReadyToRetransmit finds expired dataInFlightMap that need to be resent
func (sb *SendBuffer) ReadyToRetransmit(streamID uint32, overhead *Overhead, expectedRtoNano uint64, nowNano uint64) (data []byte, m *SendInfo, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return nil, nil, nil
	}

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, nil, nil
	}

	// Check Oldest range first
	packetKey, rtoData, ok := stream.dataInFlightMap.First()
	if ok {
		expectedRtoBackoffNano, err := backoff(expectedRtoNano, rtoData.sentNr)
		if err != nil {
			return nil, nil, err
		}
		actualRtoNano := nowNano - rtoData.sentTimeNano

		if actualRtoNano > expectedRtoBackoffNano {
			// Extract offset and length from key
			rangeOffset := packetKey.offset()
			rangeLen := packetKey.length()

			// Get userData using bias
			dataOffset := rangeOffset - stream.bias
			data = stream.userData[dataOffset : dataOffset+uint64(rangeLen)]

			overhead.dataOffset = dataOffset
			maxData := overhead.CalcMaxData()

			sb.lastReadToRetransmitStream = streamID
			if rangeLen <= maxData {
				if rangeLen < maxData {
					slog.Debug("Resend/Partial", slog.Uint64("free-space", uint64(maxData-rangeLen)))
				} else {
					slog.Debug("Resend/Full")
				}
				// Remove old range
				stream.dataInFlightMap.Remove(packetKey)
				// Same MTU - resend entire range
				m := &SendInfo{
					sentTimeNano:           nowNano,
					sentNr:                 rtoData.sentNr + 1,
					msgType:                rtoData.msgType,
					offset:                 rangeOffset,
					expectedRtoBackoffNano: expectedRtoBackoffNano,
					actualRtoNano:          actualRtoNano}
				stream.dataInFlightMap.Put(createPacketKey(packetKey.offset(), packetKey.length()), m)
				return data, m, nil
			} else {
				// Split range due to smaller MTU
				leftKey := createPacketKey(rangeOffset, maxData)
				// Queue remaining dataToSend with nxt offset
				remainingOffset := rangeOffset + uint64(maxData)
				remainingLen := rangeLen - maxData
				rightKey := createPacketKey(remainingOffset, remainingLen)

				mLeft := &SendInfo{sentTimeNano: nowNano,
					sentNr:  rtoData.sentNr + 1,
					msgType: rtoData.msgType,
					offset:  rangeOffset, expectedRtoBackoffNano: expectedRtoBackoffNano, actualRtoNano: actualRtoNano}
				stream.dataInFlightMap.Put(leftKey, mLeft)
				
				mRight := &SendInfo{sentTimeNano: rtoData.sentTimeNano,
					sentNr:                 rtoData.sentNr,
					msgType:                rtoData.msgType,
					offset:                 remainingOffset,
					expectedRtoBackoffNano: rtoData.expectedRtoBackoffNano,
					actualRtoNano:          rtoData.actualRtoNano}
				stream.dataInFlightMap.Replace(packetKey, rightKey, mRight)

				slog.Debug("Resend/Split", slog.Uint64("send", uint64(maxData)), slog.Uint64("remain", uint64(remainingLen)))
				return data[:maxData], mLeft, nil
			}
		}
	}

	return nil, nil, nil
}

// AcknowledgeRange handles acknowledgment of dataToSend
func (sb *SendBuffer) AcknowledgeRange(ack *Ack) (status AckStatus, sentTimeNano uint64) {
	sb.mu.Lock()

	stream := sb.streams[ack.streamID]
	if stream == nil {
		sb.mu.Unlock()
		return AckNoStream, 0
	}

	// Remove range key
	key := createPacketKey(ack.offset, ack.len)

	rangePair, ok := stream.dataInFlightMap.Remove(key)
	if !ok {
		sb.mu.Unlock()
		return AckDup, 0
	}

	sentTimeNano = rangePair.sentTimeNano

	// If this range starts at our bias point, we can Remove dataToSend
	if ack.offset == stream.bias {
		// Check if we have a gap between this ack and nxt range
		nextRange, _, ok := stream.dataInFlightMap.First()
		if !ok {
			// No gap, safe to Remove all userData
			stream.userData = stream.userData[stream.sentOffset-stream.bias:]
			sb.size -= int(stream.sentOffset - stream.bias)
			stream.bias += stream.sentOffset - stream.bias
		} else {
			nextOffset := nextRange.offset()
			stream.userData = stream.userData[nextOffset-stream.bias:]
			stream.bias += nextOffset
			sb.size -= int(nextOffset)
		}
	}
	sb.mu.Unlock()
	return AckStatusOk, sentTimeNano
}
