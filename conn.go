package tomtp

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
)

type ConnectionKeys struct {
	pubKeyIdRcv     *ecdh.PublicKey
	prvKeyEpSnd     *ecdh.PrivateKey
	prvKeyEpSndRoll *ecdh.PrivateKey
	pubKeyEpRcv     *ecdh.PublicKey
	pubKeyEpRcvRoll *ecdh.PublicKey
}

type ConnectionState struct {
	isSender              bool
	isRoll                bool
	isHandshakeComplete   bool
	isFirstPacketProduced bool
	withCrypto            bool
}

type Connection struct {
	// Connection identification
	connId     uint64
	connIdRoll uint64
	remoteAddr netip.AddrPort

	// Core components
	listener *Listener
	streams  *skipList[uint32, *Stream]

	// Cryptographic keys
	keys ConnectionKeys

	// Shared secrets
	sharedSecret     []byte
	sharedSecretRoll []byte

	// Buffers and flow control
	rbSnd        *SendBuffer
	rbRcv        *ReceiveBuffer
	dataInFlight int
	rcvWndSize   uint64
	mtu          uint64

	// Connection state
	state         ConnectionState
	stateStream   *shmPair[uint32, *Stream]
	nextWriteTime uint64

	// Crypto and performance
	snCrypto    uint64 //this is 48bit
	tmpRollover *tmpRollover
	BBR
	RTT

	mu sync.Mutex
}

// tmpRollover is used during rollover to temporarily store new rollover material. In case of perfect rollover,
// this is not needed. If you still have packets to send before the rollover and after, we need to temporarily store
// the new values, until all packets from the before rollover are sent.
type tmpRollover struct {
	connIdRollover       uint64
	prvKeyEpSndRollover  *ecdh.PrivateKey
	sharedSecretRollover []byte
}

func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for node := c.streams.Min(); node != nil; node = node.Next() {
		if node.value != nil {
			node.value.Close()
		}
	}
}

func (c *Connection) Stream(streamId uint32) (s *Stream) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if node := c.streams.Get(streamId); node != nil && node.value != nil {
		return node.value
	}

	s = &Stream{
		streamId: streamId,
		conn:     c,
		mu:       sync.Mutex{},
		state:    StreamStateOpen,
	}
	c.streams.Put(streamId, s)
	return s
}

func (c *Connection) decode(decryptedData []byte, rawLen int, nowMicros uint64) (s *Stream, err error) {
	p, _, payloadData, err := DecodePayload(decryptedData)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return nil, err
	}

	c.rcvWndSize = p.RcvWndSize
	s = c.Stream(p.StreamId)

	if p.Ack != nil {
		ackStatus, sentTimeMicros := c.rbSnd.AcknowledgeRange(p.Ack) //remove data from rbSnd if we got the ack
		if ackStatus == AckStatusOk {
			c.dataInFlight -= rawLen
		} else if ackStatus == AckDup {
			c.OnDuplicateAck()
		}
		if nowMicros > sentTimeMicros {
			rttMicros := nowMicros - sentTimeMicros
			c.UpdateRTT(rttMicros)
			if ackStatus == AckStatusOk {
				c.UpdateBBR(rttMicros, uint64(p.Ack.len), nowMicros)
			} else {
				return nil, errors.New("stream does not exist")
			}
		}
	}

	if len(payloadData) > 0 || p.IsClose {
		c.rbRcv.Insert(s.streamId, p.StreamOffset, payloadData, p.IsClose)
	}

	return s, nil
}

func (c *Connection) updateState(s *Stream, isClose bool) {
	//update state
	if s.state == StreamStateOpen && isClose {
		s.state = StreamStateCloseReceived
	}
	if s.state == StreamStateCloseRequest && isClose {
		s.state = StreamStateClosed
		c.cleanup(s.streamId)
	}
}

// We need to check if we remove the current state, if yes, then move the state to the next stream
func (c *Connection) cleanup(streamId uint32) {
	if c.stateStream != nil && streamId == c.stateStream.key {
		c.stateStream = c.stateStream.Next()
	}
	s := c.streams.Remove(streamId)

	if s != nil && c.streams.Size() == 0 {
		c.cleanup2(s.value.conn.connId)
	}
}

func (c *Connection) cleanup2(connId uint64) {
	if connId == c.listener.stateConn.key {
		c.listener.stateConn = c.listener.stateConn.Next()
	}
	c.listener.connMap.Remove(c.connId)
}

func (c *Connection) Flush(stream *Stream, nowMicros uint64) (raw int, data int, pacingMicros uint64, err error) {
	//update state for receiver
	if stream.state == StreamStateCloseReceived {
		stream.state = StreamStateClosed
	}

	ack := c.rbRcv.GetSndAck()

	// Respect pacing
	if c.nextWriteTime > nowMicros {
		if ack != nil {
			return c.writeAck(stream, ack)
		}
	}

	overhead := &Overhead{
		msgType:    stream.msgType(),
		ack:        ack,
		dataOffset: 0,
		currentMtu: startMtu,
	}

	// Retransmission case
	splitData, m, err := c.rbSnd.ReadyToRetransmit(stream.streamId, overhead, c.rtoMicros(), nowMicros)
	if err != nil {
		return 0, 0, 0, err
	}

	switch {
	case m != nil && splitData != nil:
		c.OnPacketLoss()
		encData, msgType, err := stream.encode(splitData, m.offset, ack, m.msgType)
		if msgType != m.msgType {
			panic("cryptoType changed")
		}
		if err != nil {
			return 0, 0, 0, err
		}
		slog.Debug("UpdateSnd/ReadyToRetransmit", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
		raw, err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
		if err != nil {
			return 0, 0, 0, err
		}
		if raw != len(encData) {
			return 0, 0, 0, fmt.Errorf("could not send all data. This should not happen")
		}

		packetLen := len(splitData)
		pacingMicros = c.GetPacingInterval(uint64(packetLen))
		c.nextWriteTime = nowMicros + pacingMicros
		return raw, packetLen, pacingMicros, nil

	case !c.state.isHandshakeComplete && c.state.isFirstPacketProduced:
		// Handshake mode - already sent first packet, can only retransmit or ack
		switch {
		case ack != nil:
			return c.writeAck(stream, ack)
		default:
			return 0, 0, 100 * 1000, nil // need to wait, go to next connection
		}

	}

	// Normal operation - try to send new data
	splitData, m = c.rbSnd.ReadyToSend(stream.streamId, overhead, nowMicros)
	switch {
	case m != nil && splitData != nil:
		encData, msgType, err := stream.encode(splitData, m.offset, ack, -1)
		if err != nil {
			return 0, 0, 0, err
		}
		m.msgType = msgType
		c.state.isFirstPacketProduced = true
		slog.Debug("UpdateSnd/ReadyToSend/splitData", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
		raw, err := c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
		if err != nil {
			return 0, 0, 0, err
		}
		if raw != len(encData) {
			return 0, 0, 0, fmt.Errorf("could not send all data. This should not happen.")
		}

		packetLen := len(splitData)
		c.dataInFlight += packetLen
		pacingMicros = c.GetPacingInterval(uint64(packetLen))
		c.nextWriteTime = nowMicros + pacingMicros
		return raw, packetLen, pacingMicros, nil
	case ack != nil:
		// Only have acks to send
		return c.writeAck(stream, ack)

	default:
		return 0, 0, 100 * 1000, nil // need to wait, go to next stream
	}
}

func (c *Connection) writeAck(stream *Stream, ack *Ack) (raw int, data int, pacingMicros uint64, err error) {
	encData, _, err := stream.encode([]byte{}, stream.currentOffset(), ack, -1)
	if err != nil {
		return 0, 0, 0, err
	}
	slog.Debug("UpdateSnd/Acks", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
	raw, err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
	if err != nil {
		return 0, 0, 0, err
	}
	if raw != len(encData) {
		return 0, 0, 0, fmt.Errorf("could not send all data. This should not happen.")
	}
	return raw, 0, 100 * 1000, nil
}
